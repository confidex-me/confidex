// Measure the real UI's logical cancel separately from completion of bounded work.
import assert from 'node:assert/strict';
import {readFile, writeFile, mkdir} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';

const [sourcePath, bundlePath, outputPath] = process.argv.slice(2);
assert(outputPath, 'Pass APP_SOURCE WASM_BUNDLE OUTPUT; only public fixtures are used.');
const root = resolve(sourcePath), bundle = resolve(bundlePath), output = resolve(outputPath);
await mkdir(output, {recursive:true});
const helperPath = join(root, 'apps/confidex/web/import-kdbx-ui-check.mjs');
const original = await readFile(helperPath, 'utf8');
let source = original;
function once(old, replacement) {
  const at = source.indexOf(old);
  assert(at >= 0 && source.indexOf(old, at + old.length) < 0, `Review changed UI helper: ${old}`);
  source = source.slice(0, at) + replacement + source.slice(at + old.length);
}
once("'../../../tools/browser-run.mjs'", JSON.stringify(pathToFileURL(join(root, 'tools/browser-run.mjs')).href));
once("'./assets.mjs'", JSON.stringify(pathToFileURL(join(root, 'apps/confidex/web/assets.mjs')).href));
once("const fixture=name=>fileURLToPath(new URL(`../../../crates/confidex-app/tests/import_fixtures/kdbx/${name}`,import.meta.url));",
  `const fixture=name=>join(${JSON.stringify(root)},'crates/confidex-app/tests/import_fixtures/kdbx',name);`);
once('for(const width of [1320,820,390]) {', "for(const action of ['cancel','lock']) { const width=1320;");

// Observe metadata before the production listener clears the received byte buffer.
const observe = `
globalThis.cancelProbe={events:[],beats:0};
const NativeWorker=globalThis.Worker;
globalThis.Worker=class extends NativeWorker {
  constructor(...args){super(...args);this.addEventListener('message',({data})=>{
    if(!(data instanceof Uint8Array)||data[0]!==123||data.length>4096)return;
    try {
      const reply=JSON.parse(new TextDecoder().decode(data)).result?.Ok?.VendorImport;
      if(!reply)return;
      const kind=Object.hasOwn(reply,'Err')?'Error':typeof reply.Ok==='string'?reply.Ok:Object.keys(reply.Ok??{})[0];
      const progress=reply.Ok?.Progress?.progress;
      cancelProbe.events.push({at:performance.now(),kind,phase:progress?.phase??null,current:progress?.current??null});
    }catch{}
  });}
};
`;
const assetsLine = source.split('\n').find(line=>line.startsWith('const files=await assets(bundle),storagePath='));
assert(assetsLine);
once(assetsLine, assetsLine + `
await writeFile(join(output,'cancel-assets.json'),JSON.stringify(Object.fromEntries(
  Object.entries(files).map(([name,bytes])=>[name,createHash('sha256').update(bytes).digest('hex')])
),null,2));
files['/boot.js']=Buffer.concat([Buffer.from(${JSON.stringify(observe)}),files['/boot.js']]);`);
const start = source.indexOf('    const modes=');
const end = source.indexOf('  },{viewport:', start);
assert(start >= 0 && end > start && source.indexOf('    const modes=', start + 1) < 0);
const test = `
    await open(fixture('password.kdbx'),'public-aes-cancel');
    await text('import-password','PUBLIC-FIXTURE-DATABASE');
    const before=await evaluate("kdbxDb('snapshot',[kdbxVault]).then(s=>JSON.stringify(s))");
    await evaluate('cancelProbe.events=[];cancelProbe.beats=0;cancelProbe.timer=setInterval(()=>cancelProbe.beats++,10)');
    await click('import-unlock');await until(s=>s.hits['vault-cancel']);
    let started=false;
    for(let i=0;i<1500;i++) {
      const events=await evaluate('cancelProbe.events');
      assert(!events.some(e=>e.kind==='Reviewed'||e.kind==='Error'),'Work ended before cancel was requested');
      if(events.filter(e=>e.phase==='Parse'&&e.current===0).length>=3){started=true;break;}
      await delay(20);
    }
    assert(started,'No repeated KDF progress from the real Worker');
    await shot('aes-'+action+'-running');
    const requested=await evaluate('performance.now()');
    if(action==='cancel') {
      await click('vault-cancel');await until(s=>!s.hits['vault-cancel']);
    } else {
      for(const type of ['rawKeyDown','keyUp'])await rpc('Input.dispatchKeyEvent',
        {type,key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:10});
      await until(s=>s.screen==='locking'||s.screen==='unlock');
      assert(!(await state()).bounds['import-window'],'Lock left the import window open');
    }
    const acknowledged=await evaluate('performance.now()');
    const feedbackState=await state();await shot('aes-'+action+'-feedback');
    let ready=null;
    for(let i=0;i<1500;i++) {
      const s=await state();assert(!s.hits['import-row-0'],'Canceled work exposed a usable preview');
      if(action==='cancel'?s.hits['import-choose-file']:s.screen==='unlock'&&!s.busy){ready=await evaluate('performance.now()');break;}
      await delay(40);
    }
    assert(ready!==null,'Cancellation or lock did not finish');
    if(action==='lock') {
      for(let i=0;i<10;i++) {
        await delay(40);const s=await state();
        assert.equal(s.screen,'unlock');assert(!s.bounds['import-window']&&!s.hits['import-row-0']);
      }
    }
    await shot('aes-'+action+'-finished');
    const events=await evaluate('cancelProbe.events');
    const reply=events.find(e=>e.at>=requested&&(e.kind==='Error'||e.kind==='Canceled'));
    if(action==='cancel'){assert(reply,'No terminal cancellation reply');assert(!events.some(e=>e.kind==='Reviewed'));}
    assert.equal(await evaluate("kdbxDb('snapshot',[kdbxVault]).then(s=>JSON.stringify(s))"),before,'Cancel changed storage');
    const beats=await evaluate('clearInterval(cancelProbe.timer);cancelProbe.beats');assert(beats>10);
    const result={action,uiFeedbackMs:acknowledged-requested,readyMs:ready-requested,
      workerReplyMs:reply?reply.at-requested:null,uiFeedbackBeforeReply:reply?acknowledged<reply.at:null,
      feedbackBusy:feedbackState.busy,heartbeat:beats,objects:await objects(),previewWrites:0,
      finalScreen:(await state()).screen,isolation:await evaluate('crossOriginIsolated'),events};
    await writeFile(join(output,action+'-result.json'),JSON.stringify(result,null,2));
    console.log(JSON.stringify({...result,events:events.length}));if(action==='cancel')await close();
`;
source = "import {createHash} from 'node:crypto';\n" + source.slice(0,start) + test + source.slice(end);
const generated = join(output, 'cancel-generated.mjs');
await writeFile(generated, source);
const hash = bytes=>createHash('sha256').update(bytes).digest('hex');
await writeFile(join(output,'cancel-inputs.json'),JSON.stringify({
  helperSha256:hash(original),runnerSha256:hash(source),
  fixtureSha256:hash(await readFile(join(root,'crates/confidex-app/tests/import_fixtures/kdbx/password.kdbx'))),
},null,2));
await new Promise((ok,fail)=>{
  const child=spawn(process.execPath,[generated,process.env.CHROME??'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',bundle,output,'unused-public-only'],{stdio:'inherit'});
  child.on('error',fail);child.on('exit',code=>code===0?ok():fail(new Error(`UI cancel probe exit ${code}`)));
});
