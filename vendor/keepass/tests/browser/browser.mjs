import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, mkdtemp } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { runBrowser } from '../../../../tools/browser-run.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const library = resolve(here, '../..');
const root = resolve(library, '../..');
const work = await mkdtemp(join(dirname(root), 'confidex-kdbx-browser-'));
const target = process.env.CARGO_TARGET_DIR ?? join(work, 'target');
await mkdir(join(work, 'pkg'), { recursive: true });
const source = join(here, 'probe.rs');
const manifest = `[package]\nname="confidex-kdbx-browser-probe"\nversion="0.0.0"\nedition="2021"\n[lib]\ncrate-type=["cdylib"]\npath=${JSON.stringify(source)}\n[dependencies]\nkeepass={path=${JSON.stringify(library)}}\nwasm-bindgen="=0.2.130"\njs-sys="=0.3.107"\nquick-xml="0.42"\nbase64="0.23"\nzeroize="1"\nsha2="0.11"\n[profile.release]\nlto=true\ncodegen-units=1\n[workspace]\n`;
await writeFile(join(work, 'Cargo.toml'), manifest);
await writeFile(join(work, 'Cargo.lock'), await readFile(join(here, 'probe.lock')));
const env = { ...process.env, CARGO_TARGET_DIR: target, CONFIDEX_KDBX_ROOT: library,
  CONFIDEX_APP_KDBX: join(root, 'crates/confidex-app/tests/import_fixtures/kdbx'),
  RUSTFLAGS: `${process.env.RUSTFLAGS ?? ''} -C link-arg=--max-memory=268435456` };
async function run(command, args) {
  await new Promise((accept, reject) => {
    const child = spawn(command, args, {env, stdio: 'inherit'});
    child.on('error', reject);
    child.on('exit', code => code === 0 ? accept() : reject(new Error(`${command}: exit ${code}`)));
  });
}
await run(process.env.CARGO ?? 'cargo', ['build','--locked','--release','--target','wasm32-unknown-unknown','--manifest-path',join(work,'Cargo.toml')]);
await run(process.env.WASM_BINDGEN ?? 'wasm-bindgen', [join(target,'wasm32-unknown-unknown/release/confidex_kdbx_browser_probe.wasm'),'--target','web','--out-name','probe','--out-dir',join(work,'pkg')]);
const assets = {
  '/probe.js': await readFile(join(work,'pkg/probe.js')),
  '/probe_bg.wasm': await readFile(join(work,'pkg/probe_bg.wasm')),
  '/worker.js': `import init,{probe} from '/probe.js';
    self.onmessage=async()=>{try{
      const module=await init(); const started=performance.now(); const result=JSON.parse(probe());
      let zeroRun=0; let current=0;
      for(const byte of new Uint8Array(module.memory.buffer)){
        if(byte===0){current++;zeroRun=Math.max(zeroRun,current);}else{current=0;}
      }
      self.postMessage({...result,zeroRun,ms:performance.now()-started,linear:module.memory.buffer.byteLength});
    }catch(error){self.postMessage({error:String(error)});}};`,
};
const result = await runBrowser(process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', assets,
  `new Promise((accept,reject)=>{let heartbeat=0;const timer=setInterval(()=>heartbeat++,10);const worker=new Worker('/worker.js',{type:'module'});worker.onerror=reject;worker.onmessage=event=>{clearInterval(timer);worker.terminate();accept({...event.data,heartbeat});};worker.postMessage(null);})`);
assert(!result.error, JSON.stringify(result));
assert.equal(result.databases,8);
assert(result.protected >= 10);
assert(result.large_argon_rejected && result.wrong_key_rejected && result.cancel);
assert(result.linear < 256 * 1024 * 1024);
assert(result.zeroRun >= 63 * 1024 * 1024, 'the exercised Argon2 allocation was not cleared');
assert(result.heartbeat > 10);
console.log(JSON.stringify({result,work},null,2));
