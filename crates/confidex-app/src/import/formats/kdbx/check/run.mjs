import assert from 'node:assert/strict';
import {readFile, writeFile, mkdir, mkdtemp, copyFile} from 'node:fs/promises';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn, execFileSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import {createHash} from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../../../../../..');
const {runBrowser} = await import(join(root, 'tools/browser-run.mjs'));
const work = await mkdtemp(join(dirname(root), 'confidex-kdbx-plan-probe-'));
const target = process.env.CARGO_TARGET_DIR ?? join(work, 'target');
const env = {...process.env, CARGO_TARGET_DIR: target, CONFIDEX_ROOT: root};
const cargo = process.env.CARGO ?? 'cargo';
async function run(command, args, options = {}) {
  await new Promise((accept, reject) => {
    const child = spawn(command, args, {env, stdio: 'inherit', ...options});
    child.on('error', reject);
    child.on('exit', code => code === 0 ? accept() : reject(new Error(`${command}: exit ${code}`)));
  });
}
await mkdir(join(work, 'app'));
await mkdir(join(work, 'pkg'));
const app = join(root, 'crates/confidex-app');
let manifest = await readFile(join(app, 'Cargo.toml'), 'utf8');
assert(!manifest.includes('[lib]'), 'review the temporary app manifest adapter');
manifest = manifest.replace(/\bpath\s*=\s*"([^"]+)"/g, (_, path) => `path=${JSON.stringify(resolve(app, path))}`);
if (!/^keepass\s*=/m.test(manifest)) {
  manifest = manifest.replace('[dependencies]', `[dependencies]\nkeepass={path=${JSON.stringify(join(root, 'vendor/keepass'))},default-features=false}`);
}
manifest += `\n[lib]\npath=${JSON.stringify(join(app, 'src/lib.rs'))}\n`;
await writeFile(join(work, 'app/Cargo.toml'), manifest);
await writeFile(join(work, 'Cargo.toml'), `[package]
name="confidex-kdbx-import-probe"
version="0.0.0"
edition="2024"
[workspace]
[lib]
crate-type=["rlib","cdylib"]
path=${JSON.stringify(join(here, 'probe.rs'))}
[[bin]]
name="confidex-kdbx-import-probe"
path=${JSON.stringify(join(here, 'native.rs'))}
[[bin]]
name="generate"
path=${JSON.stringify(join(here, 'generate.rs'))}
required-features=["producer"]
[features]
producer=["keepass/save_kdbx4"]
[dependencies]
confidex-app={path="app"}
confidex-vault={path=${JSON.stringify(join(root, 'crates/confidex-vault'))},features=["browser"]}
keepass={path=${JSON.stringify(join(root, 'vendor/keepass'))},default-features=false}
serde={version="1",features=["derive"]}
serde_json="1"
sha2="0.11"
zeroize="1"
wasm-bindgen="=0.2.130"
js-sys="=0.3.107"
[profile.release]
lto=true
codegen-units=1
`);
if (process.argv.includes('--lock')) {
  await run(cargo, ['generate-lockfile', '--manifest-path', join(work, 'Cargo.toml')]);
  await copyFile(join(work, 'Cargo.lock'), join(here, 'probe.lock'));
  console.log(`Pinned probe.lock; work=${work}`);
  process.exit(0);
}
await copyFile(join(here, 'probe.lock'), join(work, 'Cargo.lock'));
const build = ['--locked', '--release', '--manifest-path', join(work, 'Cargo.toml')];
await run(cargo, ['build', ...build, '--bin', 'confidex-kdbx-import-probe']);
const bench = join(work, 'public-10k.kdbx');
await run(cargo, ['run', ...build, '--features', 'producer', '--bin', 'generate', '--', bench]);
await run(cargo, ['build', ...build, '--lib', '--target', 'wasm32-unknown-unknown'], {
  env: {...env, RUSTFLAGS: `${process.env.RUSTFLAGS ?? ''} -C link-arg=--max-memory=268435456`},
});
await run(process.env.WASM_BINDGEN ?? 'wasm-bindgen', [
  join(target, 'wasm32-unknown-unknown/release/confidex_kdbx_import_probe.wasm'),
  '--target', 'web', '--out-name', 'probe', '--out-dir', join(work, 'pkg'),
]);
const fixture = name => join(root, 'crates/confidex-app/tests/import_fixtures/kdbx', name);
const variant = name => join(root, 'vendor/keepass/tests/resources/bounded', name);
const files = [fixture('password.kdbx'), fixture('keyfile.kdbx'), fixture('both.kdbx'),
  variant('argon2d-aes.kdbx'), variant('argon2d-aes-v10.kdbx'), variant('argon2id-chacha.kdbx'),
  variant('aes-twofish.kdbx'), variant('argon2id-aes-hex.kdbx'),
  join(root, 'vendor/keepass/tests/resources/test_db_with_password.kdbx'),
  fixture('legacy-attachments.kdbx'), bench, bench, bench, bench];
const hostile = Buffer.from(await readFile(files[3]));
const marker = Buffer.from([5, 1, 0, 0, 0, 77, 8, 0, 0, 0]);
const offset = hostile.indexOf(marker) + marker.length;
assert(offset >= marker.length);
hostile.writeBigUInt64LE(65n << 20n, offset);
let end = 12;
for (;;) { const kind = hostile[end]; const size = hostile.readUInt32LE(end + 1); end += 5 + size; if (kind === 0) break; }
createHash('sha256').update(hostile.subarray(0, end)).digest().copy(hostile, end);
const hostilePath = join(work, 'public-hostile-kdf.kdbx');
await writeFile(hostilePath, hostile); files.push(hostilePath);
files.push(fixture('empty-password.kdbx'), fixture('empty-password-keyfile.kdbx'),
  fixture('empty-password-keyfile.kdbx'), fixture('keyfile.kdbx'),
  fixture('password.kdbx'), fixture('password.kdbx'));

const expected = [];
for (let profile = 0; profile < files.length; profile++) {
  const child = spawn(process.platform === 'darwin' ? '/usr/bin/time' : join(target, 'release/confidex-kdbx-import-probe'),
    process.platform === 'darwin' ? ['-l', join(target, 'release/confidex-kdbx-import-probe'), String(profile), files[profile]] : [String(profile), files[profile]],
    {env, stdio: ['ignore', 'pipe', 'pipe']});
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => stdout += chunk); child.stderr.on('data', chunk => stderr += chunk);
  await new Promise((accept, reject) => { child.on('error', reject); child.on('exit', code => code === 0 ? accept() : reject(new Error(`native ${profile}: ${code}: ${stderr}`))); });
  const report = JSON.parse(stdout);
  const rss = stderr.match(/(\d+)\s+maximum resident set size/);
  expected.push({...report, maxRss: rss ? Number(rss[1]) : null});
  await writeFile(join(work, `native-${profile}.log`), stdout + stderr);
  console.log(`Native profile ${profile}: records=${report.records}, error=${report.error}, heap=${report.realloc_upper_bound}`);
}
await writeFile(join(work, 'native.json'), JSON.stringify(expected, null, 2));
assert.equal(expected[10].records, 10000);
assert.deepEqual(expected.slice(0,11).map(r=>r.records), [3,3,3,1,1,1,1,1,6,6,10000]);
assert.deepEqual(expected.slice(15,17).map(r=>r.records), [3,3]);
assert(expected.every(r=>r.rust_after_drop===0));
assert(expected.every(r=>r.budget_released));
assert.deepEqual(expected.map(r => r.error), [...Array(11).fill(null),
  'Checksum', 'Canceled', 'Canceled', 'KdfLimit', null, null,
  'Checksum', 'Checksum', 'Checksum', 'InvalidOptions']);
const assets = {'/probe.js': await readFile(join(work, 'pkg/probe.js')), '/probe_bg.wasm': await readFile(join(work, 'pkg/probe_bg.wasm'))};
for (let index = 0; index < files.length; index++) assets[`/input-${index}.kdbx`] = await readFile(files[index]);
assets['/worker.js'] = `import init,{run_case,set_cancel_flag} from '/probe.js';
const fetchLocal=self.fetch;self.fetch=(input,...args)=>{const url=new URL(typeof input==='string'?input:input.url??input,self.location.href);if(url.origin!==self.location.origin)throw Error('External request');return fetchLocal(input,...args);};
self.onmessage=async({data})=>{try{const profile=typeof data==='number'?data:data.profile;const module=await init();if(data.buffer)set_cancel_flag(new Int32Array(data.buffer));const input=new Uint8Array(await fetch('/input-'+profile+'.kdbx').then(r=>r.arrayBuffer()));self.postMessage({starting:profile});const result=JSON.parse(run_case(input,profile));self.postMessage({result,linear:module.memory.buffer.byteLength,jsInput:input.byteLength});}catch(error){self.postMessage({error:String(error)});}};`;

function processes() {
  return execFileSync('ps', ['-axo', 'pid=,ppid=,rss=,comm='], {encoding: 'utf8'}).trim().split('\n').map(line => {
    const [, pid, parent, rss, name] = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/);
    return {pid:Number(pid),parent:Number(parent),rss:Number(rss)*1024,name};
  });
}
const browser = await runBrowser(process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', assets, async ({evaluate,pid:rootPid}) => {
  assert(await evaluate('crossOriginIsolated && typeof SharedArrayBuffer!=="undefined"'));
  assert(rootPid, 'Missing test Chrome PID');
  let peakRss = 0, samples = 0;
  const sample = () => { const all=processes();const ids=new Set([rootPid]);for(let pass=0;pass<all.length;pass++){const before=ids.size;for(const p of all)if(ids.has(p.parent))ids.add(p.pid);if(before===ids.size)break;}peakRss=Math.max(peakRss,all.filter(p=>ids.has(p.pid)).reduce((n,p)=>n+p.rss,0));samples++; };
  sample(); const baselineRss = peakRss; const timer = setInterval(sample, 100);
  try {
    await evaluate(`(()=>{let heartbeat=0;const timer=setInterval(()=>heartbeat++,10);const results=[];let profile=0;const worker=new Worker('/worker.js',{type:'module'});worker.onerror=e=>globalThis.probeResult={error:e.message};worker.onmessage=({data})=>{if(data.starting!==undefined){globalThis.probePhase=data.starting;return;}if(data.error){globalThis.probeResult=data;return;}results.push(data);if(++profile<${files.length})worker.postMessage(profile);else{worker.terminate();clearInterval(timer);globalThis.probeResult={results,heartbeat};}};worker.postMessage(profile);})()`);
    const deadline = Date.now() + 240000;
    for (;;) {
      const result = await evaluate('globalThis.probeResult??null');
      if (result) {
        assert(!result.error, JSON.stringify(result));
        const cooperative = await evaluate(`new Promise((accept,reject)=>{
          const buffer=new SharedArrayBuffer(8),state=new Int32Array(buffer);let heartbeat=0,requested=0;
          const timer=setInterval(()=>heartbeat++,10);const worker=new Worker('/worker.js',{type:'module'});
          const timeout=setTimeout(()=>finish(new Error('Shared cancel deadline')),30000);
          const poll=setInterval(()=>{if(!requested&&Atomics.load(state,1)>=100){requested=performance.now();Atomics.store(state,0,1);}},2);
          function finish(error,data){clearTimeout(timeout);clearInterval(timer);clearInterval(poll);worker.terminate();if(error)reject(error);else accept({...data,heartbeat,checkpoints:Atomics.load(state,1),afterSignalMs:performance.now()-requested});}
          worker.onerror=e=>finish(new Error(e.message));worker.onmessage=({data})=>{if(data.starting!==undefined)return;if(data.error)finish(new Error(data.error));else finish(null,data);};
          worker.postMessage({profile:0,buffer});
        })`);
        assert.equal(cooperative.result.error,'Canceled');
        assert(cooperative.result.budget_released && cooperative.result.rust_after_drop===0);
        assert(cooperative.checkpoints>=100 && cooperative.afterSignalMs<2000);
        const cancel = await evaluate(`new Promise((accept,reject)=>{
          let heartbeat=0,lateResults=0,terminated=false;const timer=setInterval(()=>heartbeat++,10);
          const worker=new Worker('/worker.js',{type:'module'});
          const timeout=setTimeout(()=>finish(new Error('Cancel worker deadline')),30000);
          function finish(error){clearTimeout(timeout);clearInterval(timer);worker.terminate();if(error)reject(error);else accept({terminated,lateResults,heartbeat});}
          worker.onerror=e=>finish(new Error(e.message));
          worker.onmessage=({data})=>{if(data.starting===10){setTimeout(()=>{worker.terminate();terminated=true;setTimeout(()=>finish(),150);},20);}else{lateResults++;finish(new Error('Unexpected result from canceled worker'));}};
          worker.postMessage(10);
        })`);
        assert(cancel.terminated && cancel.lateResults===0 && cancel.heartbeat>2);
        sample();
        return {...result,cooperative,cancel,baselineRss,peakRss,rssSamples:samples};
      }
      assert(Date.now() < deadline, 'KDBX browser deadline');
      console.log(`Browser profile ${await evaluate('globalThis.probePhase??null')}`);
      await delay(1000);
    }
  } finally { clearInterval(timer); }
}, {isolated:true});
for (let i=0;i<expected.length;i++) {
  const actual=browser.results[i];
  for(const key of ['profile','input','records','plan_bytes','digest','error','budget_released'])assert.deepEqual(actual.result[key],expected[i][key],`profile ${i}, ${key}`);
  assert(actual.linear < 256*1024*1024);
  assert(actual.result.realloc_upper_bound < 192*1024*1024);
  assert.equal(actual.result.rust_after_drop,0);
}
assert(browser.heartbeat > 10);
const result = {work,sourceRoot:root,native:expected,browser};
await writeFile(join(work, 'result.json'), JSON.stringify(result,null,2));
console.log(JSON.stringify(result,null,2));
