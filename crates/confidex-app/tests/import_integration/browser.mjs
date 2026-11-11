import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile, copyFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const chrome = process.argv[2];
const kdbx = process.argv[3] === '--kdbx';
assert(chrome && (process.argv.length === 3 || process.argv.length === 4 && kdbx), 'usage: node browser.mjs CHROME [--kdbx]');
const check = kdbx ? 'check_kdbx_store' : 'check_integration';
const {runBrowser} = await import(new URL('../../../../tools/browser-run.mjs', import.meta.url));
const {assets} = await import(new URL('../../../../apps/confidex/web/assets.mjs', import.meta.url));
const temp = await mkdtemp(join(tmpdir(), 'confidex-integration-probe-'));
function run(program, args, env = process.env) {
  const result = spawnSync(program, args, {stdio: 'inherit', env});
  assert.equal(result.status, 0, result.error?.message ?? program);
}
try {
  await mkdir(join(temp, 'src')); await mkdir(join(temp, 'web'));
  const p = path => JSON.stringify(join(root, path));
  await writeFile(join(temp, 'Cargo.toml'), `[package]
name="confidex-import-integration-probe"
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
serde-wasm-bindgen="0.6"
serde_json="1"
zeroize="1"
zip={version="=9.0.4",default-features=false,features=["deflate-flate2"]}
`);
  await copyFile(join(root, 'Cargo.lock'), join(temp, 'Cargo.lock'));
  await copyFile(join(root, 'apps/confidex/web/storage.js'), join(temp, 'web/storage.js'));
  await writeFile(join(temp, 'src/lib.rs'), `#[path=${p('apps/confidex/src/browser_store.rs')}]
mod browser_store;
#[path=${p('crates/confidex-app/tests/import_integration/cases.rs')}]
mod cases;
#[path=${p('crates/confidex-app/tests/import_integration/proof.rs')}]
mod proof;
#[path=${p('crates/confidex-app/tests/import_integration/browser.rs')}]
mod probe;
`);
  const target = process.env.CARGO_TARGET_DIR ?? join(temp, 'target');
  run(process.env.CONFIDEX_TEST_CARGO ?? 'cargo', ['build', '--release', '--offline',
    '--manifest-path', join(temp, 'Cargo.toml'), '--target', 'wasm32-unknown-unknown'],
    {...process.env, CARGO_TARGET_DIR: target, RUSTFLAGS: '-C link-arg=--max-memory=268435456'});
  const bundle = join(temp, 'bundle');
  run(process.env.CONFIDEX_TEST_BINDGEN ?? 'wasm-bindgen', [
    join(target, 'wasm32-unknown-unknown/release/confidex_import_integration_probe.wasm'),
    '--target', 'web', '--out-dir', bundle, '--out-name', 'app']);
  const files = await assets(bundle);
  files['/'] = Buffer.from('<title>Public import integration check</title>');
  files['/integration-worker.js'] = Buffer.from(`
import init, {${check}} from '/app.js';
const realFetch=self.fetch;
self.fetch=(input,...args)=>{const url=new URL(typeof input==='string'?input:input.url??input,self.location.href);
  if(url.origin!==self.location.origin)throw Error('External request');return realFetch(input,...args);};
let wasm;
self.addEventListener('error',event=>self.postMessage({error:event.message,memoryBytes:wasm?.memory.buffer.byteLength}));
try {wasm=await init();const started=performance.now();self.postMessage({phase:'start',at:started});
  self.postMessage({done:await ${check}(),elapsedMs:performance.now()-started,memoryBytes:wasm.memory.buffer.byteLength});}
catch(error){self.postMessage({error:String(error)});}
`);
  const result = await runBrowser(chrome, files, async ({evaluate, command, url}) => {
    const origin = new URL(url).origin;
    const rpc = async (method, params) => {
      const response = await command(method, params);
      assert(!response.error, JSON.stringify(response));
      return response.result;
    };
    await evaluate(`(()=>{
    let heartbeat=0;const stages=[];const timer=setInterval(()=>heartbeat++,10);
    const worker=globalThis.integrationWorker=new Worker('/integration-worker.js',{type:'module'});
    const timeout=setTimeout(()=>finish({error:'Import probe timeout'}),1800000);
    function finish(data){if(globalThis.integrationResult)return;clearTimeout(timeout);clearInterval(timer);worker.terminate();globalThis.integrationResult={...data,heartbeat,stages};}
    worker.onerror=event=>setTimeout(()=>finish({error:'Import worker failure: '+event.message+' at '+event.filename+':'+event.lineno}),100);
    worker.onmessage=({data})=>{
      if(typeof data.quota==='boolean')globalThis.integrationQuota=data.quota;
      else if(data.phase){stages.push(data);globalThis.integrationPhase=data;}else finish(data);
    };
  })()`);
    let overridden = false;
    try {
      for (let polls=0;;polls++) {
        const result=await evaluate('globalThis.integrationResult ?? null');
        if(result) {assert(!result.error,JSON.stringify(result));return result;}
        const quota=await evaluate('globalThis.integrationQuota ?? null');
        if(typeof quota==='boolean') {
          await evaluate('globalThis.integrationQuota=null');
          await rpc('Storage.overrideQuotaForOrigin', quota ? {origin,quotaSize:1} : {origin});
          overridden=quota;
          const state=await rpc('Storage.getUsageAndQuota',{origin});
          assert.equal(state.overrideActive,quota,JSON.stringify(state));
          if(quota) {
            assert.equal(state.quota,1);
            console.log('Waiting for the IndexedDB free-space cache to expire');
            await delay(35000);
          }
          await evaluate(`globalThis.integrationWorker.postMessage({quotaReady:${quota}})`);
        }
        if(polls%10===0)console.log('Import integration poll '+polls+' '+JSON.stringify(await evaluate('globalThis.integrationPhase ?? null')));
        await delay(1000);
      }
    } finally {
      if(overridden)await rpc('Storage.overrideQuotaForOrigin',{origin});
    }
  });
  const kdbxNames = ['kdbx-password','kdbx-keyfile','kdbx-both','kdbx-empty-password','kdbx-empty-password-keyfile'];
  assert.deepEqual(JSON.parse(result.done), kdbx ? kdbxNames.map(format=>({format,items:3,records:1})) : [
    {format:'bitwarden-personal',items:3,records:3},
    {format:'bitwarden-organization',items:1,records:1},
    {format:'onepassword',items:4,records:3},
    {format:'keepass',items:3,records:1},
    {format:'csv',items:2,records:2},
    {format:'bitwarden-zip',items:3,records:3},
    {format:'bitwarden-encrypted',items:3,records:3},
    ...kdbxNames.map(format=>({format,items:3,records:1})),
  ]);
  if(kdbx) {
    assert.deepEqual(result.stages.filter(stage=>stage.phase==='done').map(stage=>stage.name), kdbxNames);
    assert.deepEqual(result.stages.filter(stage=>stage.phase==='changes').map(stage=>stage.name), kdbxNames);
  } else {
    for(const name of ['session-isolation','input-rejection','concurrent','insert-failure','quota','index-recovery']) {
      assert(result.stages.some(stage=>stage.name===name&&stage.phase==='done'),name+' did not finish');
    }
    const serviced = result.stages.filter(stage=>stage.phase==='service-done').map(stage=>stage.name);
    assert.deepEqual(serviced,['bitwarden-personal','bitwarden-organization','onepassword','keepass','csv','bitwarden-zip','bitwarden-encrypted',...kdbxNames]);
  }
  assert(result.heartbeat > 0, 'main thread did not run');
  assert(result.memoryBytes > 0 && result.memoryBytes <= 256 * 1024 * 1024, 'WASM memory profile');
  console.log(JSON.stringify(result));
} finally {
  await rm(temp, {recursive: true, force: true});
}
