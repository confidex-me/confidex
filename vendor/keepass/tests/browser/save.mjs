import assert from 'node:assert/strict';
import {readFile, writeFile, mkdir, mkdtemp} from 'node:fs/promises';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {runBrowser} from '../../../../tools/browser-run.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const library = resolve(here, '../..');
const root = resolve(library, '../..');
const work = await mkdtemp(join(dirname(root), 'confidex-kdbx-save-browser-'));
const target = process.env.CARGO_TARGET_DIR ?? join(work, 'target');
await mkdir(join(work, 'pkg'));
await mkdir(join(work, 'fixtures'));
await writeFile(join(work, 'Cargo.toml'), `[package]
name="confidex-kdbx-save-browser-probe"
version="0.0.0"
edition="2021"
[lib]
crate-type=["cdylib"]
path=${JSON.stringify(join(here, 'save.rs'))}
[dependencies]
keepass={path=${JSON.stringify(library)},features=["save_kdbx4"]}
wasm-bindgen="=0.2.130"
js-sys="=0.3.107"
base64="0.23"
zeroize="1"
argon2={version="=0.6.0",default-features=false}
[profile.release]
lto=true
codegen-units=1
[workspace]
`);
const lock = (await readFile(join(here, 'probe.lock'), 'utf8'))
  .replace('name = "confidex-kdbx-browser-probe"', 'name = "confidex-kdbx-save-browser-probe"')
  .replace(' "base64",\n "js-sys",\n "keepass",\n "quick-xml",\n "sha2",', ' "argon2",\n "base64",\n "js-sys",\n "keepass",');
await writeFile(join(work, 'Cargo.lock'), lock);
const env = {...process.env, CARGO_TARGET_DIR: target,
  RUSTFLAGS: `${process.env.RUSTFLAGS ?? ''} -C link-arg=--max-memory=268435456`};
async function run(command, args) {
  await new Promise((accept, reject) => {
    const child = spawn(command, args, {env, stdio: 'inherit'});
    child.on('error', reject);
    child.on('exit', code => code === 0 ? accept() : reject(new Error(`${command}: exit ${code}`)));
  });
}
console.log(JSON.stringify({work}));
await run(process.env.CARGO ?? 'cargo', ['build','--locked','--release','--target','wasm32-unknown-unknown','--manifest-path',join(work,'Cargo.toml')]);
await run(process.env.WASM_BINDGEN ?? 'wasm-bindgen', [join(target,'wasm32-unknown-unknown/release/confidex_kdbx_save_browser_probe.wasm'),'--target','web','--out-name','probe','--out-dir',join(work,'pkg')]);
const assets = {
  '/probe.js': await readFile(join(work,'pkg/probe.js')),
  '/probe_bg.wasm': await readFile(join(work,'pkg/probe_bg.wasm')),
  '/worker.js': `import init,{probe} from '/probe.js'; self.onmessage=async()=>{try{
    const module=await init(); const started=performance.now(); const result=JSON.parse(probe());
    self.postMessage({...result,ms:performance.now()-started,linear:module.memory.buffer.byteLength});
  }catch(error){self.postMessage({error:String(error)});}};`,
};
const result = await runBrowser(process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', assets,
  `new Promise((accept,reject)=>{let heartbeat=0; const timer=setInterval(()=>heartbeat++,10);
    const worker=new Worker('/worker.js',{type:'module'});worker.onerror=reject;
    worker.onmessage=event=>{clearInterval(timer);worker.terminate();accept({...event.data,heartbeat});};worker.postMessage(null);})`);
assert(!result.error, JSON.stringify(result));
assert.equal(result.files.length,5);
assert(result.cancel && result.linear < 256 * 1024 * 1024 && result.heartbeat > 10);
for (const file of result.files) {
  assert.match(file.name,/^(password|keyfile|both|empty-password|empty-both)$/);
  const bytes = Buffer.from(file.base64,'base64');
  assert.equal(bytes.length,file.bytes);
  await writeFile(join(work,'fixtures',`${file.name}.kdbx`),bytes);
  delete file.base64;
}
await writeFile(join(work,'fixtures/public.key'),Buffer.alloc(32,7));
console.log(JSON.stringify({result,work},null,2));
