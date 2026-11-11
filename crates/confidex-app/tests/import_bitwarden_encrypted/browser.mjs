import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile, copyFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const chrome = process.argv[2];
assert(chrome, 'usage: node browser.mjs CHROME');
const {runBrowser} = await import(new URL('../../../../tools/browser-run.mjs', import.meta.url));
const {assets} = await import(new URL('../../../../apps/confidex/web/assets.mjs', import.meta.url));
const temp = await mkdtemp(join(tmpdir(), 'confidex-encrypted-probe-'));
function run(program, args, env = process.env) {
  const result = spawnSync(program, args, {stdio: 'inherit', env});
  assert.equal(result.status, 0, result.error?.message ?? program);
}
try {
  await mkdir(join(temp, 'src')); await mkdir(join(temp, 'web'));
  const p = path => JSON.stringify(join(root, path));
  await writeFile(join(temp, 'Cargo.toml'), `[package]
name="confidex-encrypted-browser-probe"
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
`);
  await copyFile(join(root, 'Cargo.lock'), join(temp, 'Cargo.lock'));
  await copyFile(join(root, 'apps/confidex/web/storage.js'), join(temp, 'web/storage.js'));
  await writeFile(join(temp, 'src/lib.rs'), `#[path=${p('apps/confidex/src/browser_store.rs')}]
mod browser_store;
#[path=${p('crates/confidex-app/tests/import_bitwarden_encrypted/browser.rs')}]
mod probe;
`);
  const target = process.env.CARGO_TARGET_DIR ?? join(temp, 'target');
  run(process.env.CONFIDEX_TEST_CARGO ?? 'cargo', ['build', '--release', '--offline',
    '--manifest-path', join(temp, 'Cargo.toml'), '--target', 'wasm32-unknown-unknown'],
    {...process.env, CARGO_TARGET_DIR: target, RUSTFLAGS: '-C link-arg=--max-memory=268435456'});
  const bundle = join(temp, 'bundle');
  run(process.env.CONFIDEX_TEST_BINDGEN ?? 'wasm-bindgen', [
    join(target, 'wasm32-unknown-unknown/release/confidex_encrypted_browser_probe.wasm'),
    '--target', 'web', '--out-dir', bundle, '--out-name', 'app']);
  const files = await assets(bundle);
  files['/'] = Buffer.from('<title>Public encrypted import check</title>');
  files['/encrypted-worker.js'] = Buffer.from(`
import init, {check_encrypted} from '/app.js';
const realFetch=self.fetch;
self.fetch=(input,...args)=>{const url=new URL(typeof input==='string'?input:input.url??input,self.location.href);
  if(url.origin!==self.location.origin)throw Error('External request');return realFetch(input,...args);};
try {const wasm=await init();self.postMessage({done:await check_encrypted(),memoryBytes:wasm.memory.buffer.byteLength});}
catch(error){self.postMessage({error:String(error)});}
`);
  const result = await runBrowser(chrome, files, async ({evaluate}) => evaluate(`new Promise((resolve,reject)=>{
    let heartbeat=0;const timer=setInterval(()=>heartbeat++,10);
    const worker=new Worker('/encrypted-worker.js',{type:'module'});
    const timeout=setTimeout(()=>finish(Error('Encrypted probe timeout')),90000);
    function finish(error,done,memoryBytes){clearTimeout(timeout);clearInterval(timer);worker.terminate();error?reject(error):resolve({done,heartbeat,memoryBytes});}
    worker.onerror=()=>finish(Error('Encrypted worker failure'));
    worker.onmessage=({data})=>data.error?finish(Error(data.error)):finish(null,data.done,data.memoryBytes);
  })`));
  assert.equal(result.done, 'authenticated preview,3 sealed records,exact fields,reopen,duplicate skip,protected search');
  assert(result.heartbeat > 0, 'main thread did not run');
  assert(result.memoryBytes > 0 && result.memoryBytes <= 256 * 1024 * 1024, 'WASM memory profile');
  console.log(JSON.stringify(result));
} finally {
  await rm(temp, {recursive: true, force: true});
}
