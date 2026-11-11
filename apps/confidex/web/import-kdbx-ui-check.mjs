import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,bundle,output,large]=process.argv.slice(2);
assert(large,'Pass the public 10k KDBX fixture from the adapter calibration runner.');
await mkdir(output,{recursive:true});
const fixture=name=>fileURLToPath(new URL(`../../../crates/confidex-app/tests/import_fixtures/kdbx/${name}`,import.meta.url));
const emptyKey=resolve(output,'public-empty.key');await writeFile(emptyKey,new Uint8Array());
const files=await assets(bundle),storagePath=Object.keys(files).find(path=>path.endsWith('/web/storage.js'));
for(const width of [1320,820,390]) {
  await runBrowser(chrome,files,async({command,evaluate})=>{
    const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
    const state=()=>evaluate('window.confidex?.snapshot()');
    const until=async predicate=>{for(let i=0;i<1500;i++){const s=await state();if(s&&predicate(s))return s;await delay(40);}throw Error('KDBX timeout: '+JSON.stringify(await state()));};
    const click=async id=>{
      for(let i=0;i<40;i++) {
        const s=await state(),point=s?.hits[id];if(!point){await delay(40);continue;}
        let v=s.bounds['import-window-body']??s.bounds['preferences-viewport'];
        if(/^preferences-section|^settings$|^import-close$/.test(id))v=null;
        if(v&&id!=='import-close'&&(point[1]<v[1]||point[1]>v[3])) {
          const p={x:(v[0]+v[2])/2,y:(v[1]+v[3])/2};await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...p});
          await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...p,deltaX:0,deltaY:point[1]<v[1]?-160:160});await delay(300);continue;
        }
        const [x,y]=point;await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});await delay(40);
        const fresh=(await state())?.hits[id];if(!fresh||Math.abs(fresh[0]-x)>0.5||Math.abs(fresh[1]-y)>0.5)continue;
        for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});await delay(120);return;
      }
      await writeFile(join(output,`${width}-failure.png`),Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));
      throw Error('Cannot reach '+id+': '+JSON.stringify(await state()));
    };
    const text=async(id,text)=>{
      await click(id);for(const type of ['rawKeyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});
      await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});await rpc('Input.insertText',{text});await delay(60);
    };
    const typeKeys=async value=>{
      for(const character of value) {
        const code=character==='-'?'Minus':'Key'+character;
        await rpc('Input.dispatchKeyEvent',{type:'keyDown',key:character,code,text:character,unmodifiedText:character,windowsVirtualKeyCode:character.charCodeAt(0)});
        await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:character,code,windowsVirtualKeyCode:character.charCodeAt(0)});
      }
    };
    const shot=async name=>{await delay(160);await writeFile(join(output,`${width}-${name}.png`),Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));};
    await until(s=>s.screen==='catalog'&&!s.busy);await delay(250);await click('create');await click('create-sync');
    const vaultName='PUBLIC-KDBX-DESTINATION';
    await click('name');await typeKeys(vaultName);
    const textAgent='document.querySelector(\'input[autocapitalize="off"]\')';
    await evaluate(`${textAgent}.value='PUBLIC-STALE-TEXT'`);
    await click('password');
    assert.equal(await evaluate(`${textAgent}.value`),'','The previous field left text in the browser input');
    await text('password','public-browser-kdbx-password');await text('repeat','public-browser-kdbx-password');
    await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
    await evaluate(`(async()=>{window.kdbxDb=(await import(${JSON.stringify(storagePath)})).dbCall;window.kdbxVault=(await kdbxDb('vaults',[]))[0].id.map(n=>n.toString(16).padStart(2,'0')).join('');})()`);
    assert.equal(await evaluate(`kdbxDb('vaults',[]).then(vaults=>vaults[0].name)`),vaultName);
    const objects=()=>evaluate(`kdbxDb('snapshot',[kdbxVault]).then(s=>s.objects.length)`);
    const pick=async(id,path)=>{
      await rpc('Page.enable');await rpc('Page.setInterceptFileChooserDialog',{enabled:true});await click(id);
      const {root}=await rpc('DOM.getDocument'),{nodeId}=await rpc('DOM.querySelector',{nodeId:root.nodeId,selector:'input[type=file]'});assert(nodeId);
      await rpc('DOM.setFileInputFiles',{nodeId,files:[path]});await delay(160);
    };
    const open=async(path,scope)=>{
      await click('settings');if((await state()).hits['preferences-sections'])await click('preferences-sections');await click('preferences-section-1');await click('import-records');
      await text('import-account',scope);await pick('import-choose-file',path);await click('import-review');
      await until(s=>s.hits['import-password']&&s.hits['import-use-keyfile']);
    };
    const close=async()=>{await click('import-close');await until(s=>!s.bounds['import-window']);};
    const review=async()=>{
      await until(s=>s.hits['import-row-0']);
      if((await state()).hits['import-groups']){await click('import-groups');await click('import-all-sources');}
      await click('import-row-0');await until(s=>s.bounds['import-preview']);
    };
    const modes=[['password.kdbx','PUBLIC-FIXTURE-DATABASE',false],['keyfile.kdbx',null,true],['both.kdbx','PUBLIC-FIXTURE-DATABASE',true],['empty-password.kdbx','',false],['empty-password-keyfile.kdbx','',true]];
    for(const [index,[file,password,keyfile]] of modes.entries()) {
      const before=await objects(),rows=(await state()).rows;
      await open(fixture(file),`public-kdbx-${index}`);await shot(`credentials-${index}`);
      if(password===null)await click('import-use-password');else if(password)await text('import-password',password);
      if(keyfile){await click('import-use-keyfile');assert(!(await state()).hits['import-unlock']);await pick('import-choose-keyfile',fixture('public.key'));}
      if(index===0) {
        await text('import-password','PUBLIC-WRONG-PASSWORD');await click('import-unlock');await until(s=>s.hits['import-unlock']);await shot('password-error');
        assert.equal(await objects(),before);await text('import-password','');
        await typeKeys(password);
      }
      if(width===1320&&index===2) {
        await pick('import-choose-keyfile',emptyKey);await click('import-unlock');await until(s=>s.hits['import-unlock']);await shot('empty-keyfile-error');assert.equal(await objects(),before);
        await pick('import-choose-keyfile',fixture('public.key'));
      }
      await shot(`selected-${index}`);
      for(const type of ['rawKeyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
      await review();await shot(`preview-${index}`);assert.equal(await objects(),before,'preview wrote objects');
      if((await state()).hits['import-container-ack'])await click('import-container-ack');if((await state()).hits['import-item-ack'])await click('import-item-ack');
      await click('import-apply');await until(s=>s.hits['import-done']);await shot(`result-${index}`);assert.equal(await objects(),before+1);
      await click('import-done');await until(s=>!s.bounds['import-window']&&s.rows===rows+1);
    }
    await open(fixture('password.kdbx'),'public-kdbx-0');await text('import-password','PUBLIC-FIXTURE-DATABASE');await click('import-unlock');await review();await shot('duplicate');assert(!(await state()).hits['import-apply']);assert.equal(await objects(),5);await close();
    await open(fixture('both.kdbx'),'public-kdbx-2');await click('import-use-keyfile');await pick('import-choose-keyfile',fixture('public.key'));await close();assert.equal(await objects(),5);
    await open(fixture('both.kdbx'),'public-kdbx-2');await shot('credentials-cleared');assert(!(await state()).hits['import-choose-keyfile']);await close();
    if(width===1320) {
      await open(resolve(large),'public-kdbx-10000');await text('import-password','PUBLIC-BENCH-DATABASE');
      await evaluate('window.kdbxBeats=0;window.kdbxBeatTimer=setInterval(()=>kdbxBeats++,10)');await click('import-unlock');await until(s=>s.hits['vault-cancel']);await shot('10000-progress');
      await click('vault-cancel');await until(s=>s.hits['import-choose-file']);assert.equal(await objects(),5,'cancel wrote objects');
      assert(await evaluate('clearInterval(kdbxBeatTimer);kdbxBeats')>10,'KDF blocked the main thread');await close();
    }
    console.log(JSON.stringify({width,previewWrites:0,objects:await objects(),credentialModes:5,emptyPasswordModes:2}));
  },{viewport:[width,1000],windowSize:[width,1000]});
}
