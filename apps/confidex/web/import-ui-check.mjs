import assert from 'node:assert/strict';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,bundle,output='/tmp/confidex-import-client-shots',entry='records']=process.argv.slice(2);
assert(['records','home'].includes(entry));
await mkdir(output,{recursive:true});
const file=resolve(output,'public-export.json');
await writeFile(file,JSON.stringify({encrypted:false,folders:[],items:[{id:'11111111-1111-4111-8111-111111111111',type:1,name:'Public import — Engineering / Разработка',notes:null,fields:[],login:{username:'demo@example.invalid',password:'public-hidden-password',uris:[{uri:'https://public-import.example.invalid'}]}}]}));
const big=resolve(output,'public-10000-export.json');
await writeFile(big,JSON.stringify({encrypted:false,folders:[],items:Array.from({length:10000},(_,i)=>({id:`public-item-${i}`,type:1,name:`Public account ${String(i).padStart(5,'0')}`,login:{username:'demo@example.invalid',password:'public-hidden-password',uris:[{uri:'https://public-import.example.invalid'}]}}))}));
const changed=resolve(output,'public-changed-export.json');
const updated=JSON.parse(await readFile(file,'utf8'));updated.items[0].login.password='public-updated-password';await writeFile(changed,JSON.stringify(updated));
const encrypted=fileURLToPath(new URL('../../../crates/confidex-app/tests/import_fixtures/bitwarden_encrypted_json/argon2-128.json',import.meta.url));
const restricted=resolve(output,'public-account-restricted.json');
const accountExport=JSON.parse(await readFile(encrypted,'utf8'));accountExport.passwordProtected=false;await writeFile(restricted,JSON.stringify(accountExport));
const files=await assets(bundle),storagePath=Object.keys(files).find(p=>p.endsWith('/web/storage.js'));
for(const width of [1320,820,390]) {
  await runBrowser(chrome,files,async({command,evaluate})=>{
    const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
    const state=()=>evaluate('window.confidex?.snapshot()');
    const until=async predicate=>{for(let i=0;i<900;i++){const s=await state();if(s&&predicate(s))return s;await delay(40);}throw Error('UI timeout: '+JSON.stringify(await state()));};
    const click=async id=>{
      for(let i=0;i<30;i++) {
        const s=await until(s=>s.hits[id]),[x,y]=s.hits[id];
        const v=/^preferences-section|^import-close$/.test(id)?null:s.bounds['import-window-body']??s.bounds['preferences-viewport'];
        if(!v||y>=v[1]&&y<=v[3]) {
          await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});
          await delay(40);
          const fresh=(await state())?.hits[id];if(!fresh||Math.abs(fresh[0]-x)>0.5||Math.abs(fresh[1]-y)>0.5)continue;
          for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});await delay(120);return;
        }
        const point={x:v[0]+5,y:(v[1]+v[3])/2};
        await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
        await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:y<v[1]?-180:180});await delay(100);
      }
      throw Error('Cannot reach '+id);
    };
    const text=async(id,text)=>{
      await click(id);
      for(const type of ['rawKeyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});
      await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});
      await rpc('Input.insertText',{text});await delay(50);
    };
    const capture=async name=>{await delay(200);await writeFile(join(output,`${width}-${name}.png`),Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));};
    const create=async(action,name)=>{
      await click(action);await click('create-sync');await text('name',name);
      await text('password','public-browser-import-password');await text('repeat','public-browser-import-password');
      await click('submit');await until(s=>s.screen==='key'&&!s.busy);
      assert(!(await state()).hits['continue'],'key confirmation was bypassed');
      await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
    };
    await until(s=>s.screen==='catalog'&&!s.busy);await delay(200);
    await evaluate(`(async()=>{window.importDb=(await import(${JSON.stringify(storagePath)})).dbCall;})()`);
    if(entry==='home') {
      await create('create','Existing public vault');
      await evaluate(`(async()=>{const vault=(await importDb('vaults',[]))[0];window.importOriginalId=vault.id.map(n=>n.toString(16).padStart(2,'0')).join('');window.importOriginal=JSON.stringify(await importDb('snapshot',[importOriginalId]));})()`);
      await click('vaults');await until(s=>s.screen==='catalog'&&!s.busy&&s.vaults===1);await capture('home');
      await click('import-new');await capture('new-vault');await click('cancel');await until(s=>s.screen==='catalog'&&!s.busy);
      assert.equal(await evaluate("importDb('vaults',[]).then(v=>v.length)"),1,'cancel created a vault');
      await create('import-new','Public destination');
      await until(s=>s.hits['import-choose-file']);await capture('home-import');
    } else await create('create','Public destination');
    await evaluate(`(async()=>{window.importVault=(await importDb('vaults',[])).find(v=>v.name==='Public destination').id.map(n=>n.toString(16).padStart(2,'0')).join('');})()`);
    const objects=()=>evaluate(`importDb('snapshot',[importVault]).then(s=>s.objects.length)`);
    const open=async()=>{if((await state()).bounds['import-window'])return;await click('settings');if((await state()).hits['preferences-sections'])await click('preferences-sections');await click('preferences-section-1');await click('import-records');await until(s=>s.hits['import-choose-file']);};
    const pick=async(path=file)=>{
      await rpc('Page.enable');await rpc('Page.setInterceptFileChooserDialog',{enabled:true});await click('import-choose-file');
      const {root}=await rpc('DOM.getDocument');const {nodeId}=await rpc('DOM.querySelector',{nodeId:root.nodeId,selector:'input[type=file]'});assert(nodeId);
      await rpc('DOM.setFileInputFiles',{nodeId,files:[path]});await delay(150);
    };
    if(width===1320) {
      await open();await text('import-account','public-source-account');await pick(big);
      await evaluate('window.importBeats=0;window.importBeatTimer=setInterval(()=>importBeats++,10)');
      await click('import-review');await until(s=>s.bounds['import-list']&&s.hits['import-row-0']);
      const s=await state();assert(Object.keys(s.hits).filter(k=>k.startsWith('import-row-')).length<30);
      await capture('10000-preview');assert.equal(await objects(),0);
      assert(await evaluate('clearInterval(importBeatTimer);importBeats')>10,'import blocked the main thread');
      await click('import-apply');await until(s=>s.hits['vault-cancel']);await capture('10000-seal-progress');
      await click('vault-cancel');await until(s=>s.hits['import-choose-file']);
      await click('import-close');await until(s=>!s.bounds['import-window']);assert.equal(await objects(),0,'cancel during sealing wrote objects');
      await open();await text('import-account','public-source-account');await pick(big);await click('import-review');
      await until(s=>s.hits['vault-cancel']);await writeFile(join(output,`${width}-10000-progress.png`),Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));await click('vault-cancel');await until(s=>s.hits['import-choose-file']);
      await click('import-close');await until(s=>!s.bounds['import-window']);assert.equal(await objects(),0,'cancel wrote objects');
    }
    await open();await text('import-account','public-source-account');await pick();await capture('source');await click('import-review');
    await until(s=>s.bounds['import-list']&&s.hits['import-row-0']);await capture('review');assert.equal(await objects(),0,'preview wrote objects');
    await click('import-row-0');await until(s=>s.bounds['import-preview']);await capture('preview');
    const s=await state();assert(s.bounds['import-actions'][3]<=s.bounds['import-window-body'][3]);assert(s.bounds['import-actions'][3]<s.bounds['import-notifications'][1]);
    if(s.hits['import-container-ack'])await click('import-container-ack');if(s.hits['import-item-ack'])await click('import-item-ack');
    await click('import-apply');await until(s=>s.hits['import-done']&&!s.busy);await capture('result');assert.equal(await objects(),1);
    await click('import-done');await until(s=>!s.bounds['import-window']&&s.rows===1);
    if(width===1320) {
      await open();await text('import-account','public-source-account');await pick();await click('import-review');
      await until(s=>s.bounds['import-list']);await capture('duplicate');assert.equal(await objects(),1);
      await click('import-close');await until(s=>!s.bounds['import-window']);
      await open();await text('import-account','public-source-account');await pick(changed);await click('import-review');
      await until(s=>s.hits['import-row-0']);await click('import-row-0');await until(s=>s.hits['import-update-0']);
      await click('import-update-0');await until(s=>s.hits['import-item-ack']);await capture('conflict');
      await click('import-item-ack');await click('import-apply');await until(s=>s.hits['import-done']&&!s.busy);
      await click('import-done');await until(s=>!s.bounds['import-window']&&s.rows===1);assert.equal(await objects(),2,'replacement did not keep one record with history');
    }
    for (const [label,fixture,added] of [
      ['1pux','onepassword_1pux/account.1pux',3],
      ['bitwarden-zip','bitwarden_zip/personal.zip',3],
    ]) {
      const before=await objects(),rows=(await state()).rows;
      await open();await text('import-account',`public-${label}-account`);
      await pick(fileURLToPath(new URL(`../../../crates/confidex-app/tests/import_fixtures/${fixture}`,import.meta.url)));
      await capture(`${label}-source`);await click('import-review');
      await until(s=>s.bounds['import-list']&&s.hits['import-row-0']);
      assert.equal(await objects(),before,'archive preview wrote objects');
      if((await state()).hits['import-groups']) {
        await click('import-groups');await click('import-all-sources');
      }
      await click('import-row-1');await until(s=>s.bounds['import-preview']);await capture(`${label}-attachment`);
      if((await state()).hits['import-container-ack'])await click('import-container-ack');
      if((await state()).hits['import-item-ack'])await click('import-item-ack');
      await click('import-apply');await until(s=>s.hits['import-done']&&!s.busy);await capture(`${label}-result`);
      assert.equal(await objects(),before+added,'archive commit count');
      await click('import-done');await until(s=>!s.bounds['import-window']&&s.rows===rows+added);
    }
    {
      const before=await objects(),rows=(await state()).rows;
      await open();await text('import-account','public-encrypted-account');await pick(encrypted);await click('import-review');
      await until(s=>s.hits['import-password']);await capture('password');
      await evaluate('window.passwordBeats=0;window.passwordBeatTimer=setInterval(()=>passwordBeats++,10)');
      await text('import-password','wrong-public-password');await click('import-unlock');
      await until(s=>s.hits['import-password']&&s.hits['import-unlock']);await capture('password-error');
      assert(await evaluate('clearInterval(passwordBeatTimer);passwordBeats')>10,'password KDF blocked the main thread');
      assert.equal(await objects(),before,'wrong password wrote objects');
      await text('import-password',' Public test-only 密码 é e\u0301 ');await capture('password-retry');
      for(const type of ['rawKeyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
      await until(s=>s.bounds['import-list']&&s.hits['import-row-0']);assert.equal(await objects(),before,'password preview wrote objects');
      await click('import-row-0');await until(s=>s.bounds['import-preview']);await capture('password-preview');
      if((await state()).hits['import-container-ack'])await click('import-container-ack');
      if((await state()).hits['import-item-ack'])await click('import-item-ack');
      await click('import-apply');await until(s=>s.hits['import-done']&&!s.busy);await capture('password-result');
      assert.equal(await objects(),before+3);await click('import-done');await until(s=>!s.bounds['import-window']&&s.rows===rows+3);
      await open();await text('import-account','public-encrypted-account');await pick(encrypted);await click('import-review');
      await until(s=>s.hits['import-password']);await click('import-close');await until(s=>!s.bounds['import-window']);
      assert.equal(await objects(),before+3,'canceling credentials wrote objects');
      await open();await text('import-account','public-encrypted-account');await pick(restricted);await click('import-review');
      await until(s=>s.hits['import-choose-file']&&!s.hits['import-review']&&!s.hits['vault-cancel']);
      assert(!(await state()).hits['import-password']);await capture('account-restricted');assert.equal(await objects(),before+3);
      await click('import-close');await until(s=>!s.bounds['import-window']);
    }
    if(entry==='home') {
      assert.equal(await evaluate("importDb('vaults',[]).then(v=>v.length)"),2);
      assert(await evaluate("importDb('snapshot',[importOriginalId]).then(s=>JSON.stringify(s)===importOriginal)"),'existing vault changed');
      const before=await objects();await click('vaults');await until(s=>s.screen==='catalog'&&!s.busy&&s.vaults===2);
      const index=await evaluate("importDb('vaults',[]).then(v=>v.findIndex(v=>v.name==='Public destination'))");
      await click('vault-'+index);await until(s=>s.screen==='unlock'&&!s.busy);
      await text('password','public-browser-import-password');await click('submit');await until(s=>s.screen==='open'&&!s.busy&&s.rows>0);
      await text('search','Engineering');await until(s=>s.rows===1&&!s.busy);
      assert.equal(await objects(),before,'reopen or search changed the vault');await capture('reopened-search');
    }
    console.log(JSON.stringify({width,entry,previewWrites:0,objects:await objects(),separateVault:entry==='home'}));
  },{viewport:[width,960],windowSize:[width,960]});
}
