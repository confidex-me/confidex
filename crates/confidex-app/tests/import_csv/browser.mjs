import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile, copyFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import {sampleRss} from './performance/rss.mjs';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const chrome = process.argv[2];
const profile = process.argv[3] === '--profile';
const load = profile || process.argv[3] === '--load';
assert(chrome && process.argv.length <= (load ? 4 : 3), 'usage: node browser.mjs CHROME [--load|--profile]');
const check = profile ? 'check_csv_profile' : load ? 'check_csv_load' : 'check_csv';
const {runBrowser} = await import(new URL('../../../../tools/browser-run.mjs', import.meta.url));
const {assets} = await import(new URL('../../../../apps/confidex/web/assets.mjs', import.meta.url));
const temp = await mkdtemp(join(tmpdir(), 'confidex-csv-probe-'));
function run(program, args, env = process.env) {
  const result = spawnSync(program, args, {stdio: 'inherit', env});
  assert.equal(result.status, 0, result.error?.message ?? program);
}
try {
  await mkdir(join(temp, 'src')); await mkdir(join(temp, 'web'));
  const p = path => JSON.stringify(join(root, path));
  await writeFile(join(temp, 'Cargo.toml'), `[package]
name="confidex-csv-browser-probe"
version="0.0.0"
edition="2024"
[lib]
crate-type=["cdylib"]
[dependencies]
confidex-app={path=${p('crates/confidex-app')}}
confidex-storage={path=${p('crates/confidex-storage')}}
confidex-vault={path=${p('crates/confidex-vault')},features=["browser"]}
wasm-bindgen="=0.2.130"
wasm-bindgen-futures="=0.4.80"
js-sys="=0.3.107"
serde="1"
serde_json="1"
serde-wasm-bindgen="0.6"
zeroize="1"
`);
  await copyFile(join(root, 'Cargo.lock'), join(temp, 'Cargo.lock'));
  await copyFile(join(root, 'apps/confidex/web/storage.js'), join(temp, 'web/storage.js'));
  await writeFile(join(temp, 'src/lib.rs'), `#[path=${p('apps/confidex/src/browser_store.rs')}]
mod browser_store;
#[path=${p('crates/confidex-app/tests/import_csv/load.rs')}]
mod load;
#[path=${p('crates/confidex-app/tests/import_csv/browser.rs')}]
mod probe;
`);
  const target = process.env.CARGO_TARGET_DIR ?? join(temp, 'target');
  run(process.env.CONFIDEX_TEST_CARGO ?? 'cargo', ['build', '--release', '--offline',
    '--manifest-path', join(temp, 'Cargo.toml'), '--target', 'wasm32-unknown-unknown'],
    {...process.env, CARGO_TARGET_DIR: target, RUSTFLAGS: '-C link-arg=--max-memory=268435456'});
  const bundle = join(temp, 'bundle');
  run(process.env.CONFIDEX_TEST_BINDGEN ?? 'wasm-bindgen', [
    join(target, 'wasm32-unknown-unknown/release/confidex_csv_browser_probe.wasm'),
    '--target', 'web', '--out-dir', bundle, '--out-name', 'app']);
  const files = await assets(bundle);
  files['/'] = Buffer.from('<title>Public CSV import check</title>');
  files['/csv-worker.js'] = Buffer.from(`
import init, {${check}} from '/app.js';
const realFetch=self.fetch;
self.fetch=(input,...args)=>{const url=new URL(typeof input==='string'?input:input.url??input,self.location.href);
  if(url.origin!==self.location.origin)throw Error('External request');return realFetch(input,...args);};
let wasm;
self.addEventListener('error',event=>self.postMessage({error:event.message,memoryBytes:wasm?.memory.buffer.byteLength}));
try {wasm=await init();
  const clock=${profile}?(()=>{let previous=performance.now(),resolutionMs=Infinity;
    for(let i=0;i<50000;i++){const now=performance.now();if(now>previous)resolutionMs=Math.min(resolutionMs,now-previous);previous=now;}
    return {isolated:self.crossOriginIsolated,resolutionMs};})():null;
  const started=performance.now();self.postMessage({phase:'start',at:started});
  self.postMessage({done:await ${check}(),elapsedMs:performance.now()-started,memoryBytes:wasm.memory.buffer.byteLength,clock});}
catch(error){self.postMessage({error:String(error)});}
`);
  const result = await runBrowser(chrome, files, async ({evaluate,pid}) => {
    const rss=profile?sampleRss(pid):null;
    try {
      await evaluate(`(()=>{
      let heartbeat=0;const stages=[];const timer=setInterval(()=>heartbeat++,10);
      const worker=new Worker('/csv-worker.js',{type:'module'});
      const timeout=setTimeout(()=>finish({error:'CSV probe timeout'}),${profile ? 180000 : load ? 1800000 : 90000});
      function finish(data){if(globalThis.csvResult)return;clearTimeout(timeout);clearInterval(timer);worker.terminate();globalThis.csvResult={...data,heartbeat,stages};}
      worker.onerror=event=>setTimeout(()=>finish({error:'CSV worker failure: '+event.message+' at '+event.filename+':'+event.lineno}),100);
      worker.onmessage=({data})=>{if(data.phase){stages.push(data);globalThis.csvPhase=data;}else finish(data);};
    })()`);
      for (let polls=0;;polls++) {
        const result=await evaluate('globalThis.csvResult ?? null');
        if(result) {
          assert(!result.error,JSON.stringify(result));
          if(rss)result.browserRss=rss.result();
          result.browser=await evaluate('({userAgent:navigator.userAgent,hardwareConcurrency:navigator.hardwareConcurrency})');
          return result;
        }
        if(load && polls%10===0)console.log('CSV load running: '+polls+'s '+JSON.stringify(await evaluate('globalThis.csvPhase ?? null')));
        await delay(1000);
      }
    } finally {rss?.stop();}
  },{isolated:profile});
  if(profile) {
    const report=JSON.parse(result.done);
    assert.equal(report.records,10000);
    assert(report.input_bytes>0&&report.encoded_bytes>0);
    assert(result.browserRss.samples>1&&result.browserRss.maxProcesses>1);
    assert(result.clock.isolated&&result.clock.resolutionMs>0&&result.clock.resolutionMs<=0.01,'profile needs the isolated high-resolution clock');
    const names=['inspect','read','map','validate','review','seal','commit','commit_release','index','other'];
    const times=names.map(name=>report[name+'_ms']);
    assert(times.every(time=>Number.isFinite(time)&&time>=0));
    assert(Math.abs(times.reduce((a,b)=>a+b,0)-report.total_ms)<0.001,'stage times do not sum to total');
  } else assert.equal(result.done, load
    ? '10000 records,parse,review,seal,commit,search,reopen,duplicate skip'
    : 'preview,2 sealed records,exact fields,reopen,duplicate skip,row reorder,protected search');
  assert(result.heartbeat > 0, 'main thread did not run');
  assert(result.memoryBytes > 0 && result.memoryBytes <= 256 * 1024 * 1024, 'WASM memory profile');
  console.log(JSON.stringify(result));
} finally {
  await rm(temp, {recursive: true, force: true});
}
