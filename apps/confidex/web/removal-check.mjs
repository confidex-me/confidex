import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';

const [chrome,bundle,server,output='/tmp/confidex-removal-shots']=process.argv.slice(2);
assert(chrome&&bundle&&server,'Usage: removal-check.mjs CHROME BUNDLE DISPOSABLE_SERVER [SCREENSHOTS]');
const files=await assets(bundle);
files['/worker.js']=Buffer.concat([Buffer.from(`
const originalDelete=IDBObjectStore.prototype.delete;
let failRemoval=true;
IDBObjectStore.prototype.delete=function(key){
  if(this.name==='vaults'&&failRemoval){failRemoval=false;throw new DOMException('Public removal retry fixture','UnknownError');}
  return originalDelete.call(this,key);
};
`),files['/worker.js']]);
await mkdir(output,{recursive:true});
const results=[];
for(const width of [1180,390]) {
 const height=width===390?844:800;
 results.push(await runBrowser(chrome,files,async({command,evaluate})=>{
  const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
  await rpc('Page.enable');
  await rpc('Page.addScriptToEvaluateOnNewDocument',{source:`
    Object.defineProperty(navigator,'languages',{get:()=>['ru-RU']});
    Object.defineProperty(Clipboard.prototype,'writeText',{value:async text=>{window.__copied=text;}});
    window.__NativeWorker=Worker;
    window.Worker=class extends Worker {
      constructor(...args){super(...args);if(String(args[0]).endsWith('/worker.js')){
        window.__vaultWorker=this;
        this.addEventListener('message',({data})=>{try{
          const r=JSON.parse(new TextDecoder().decode(data));
          window.__reply=r.result;
          if(r.result.Ok?.Catalog)window.__catalog=r.result.Ok.Catalog;
          if(r.result.Ok?.Draft)window.__draft=r.result.Ok.Draft;
          if(r.result.Ok?.RemovalPrepared?.report)window.__removalReport=r.result.Ok.RemovalPrepared.report;
        }catch{}});
      }}
      postMessage(data,...args){try{const r=JSON.parse(new TextDecoder().decode(data));window.__generation=r.generation;window.__request=r.command;if(r.command.RemoveVault)window.__removeRequests=(window.__removeRequests??0)+1;}catch{}super.postMessage(data,...args);}
    };
    window.__catalogRefresh=()=>__vaultWorker.postMessage(new TextEncoder().encode(JSON.stringify({generation:__generation,command:'Catalog'})));
    window.__inspect=async id=>{
      const vault=id.map(b=>b.toString(16).padStart(2,'0')).join('');
      const db=await new Promise((resolve,reject)=>{const r=indexedDB.open('confidex');r.onsuccess=()=>resolve(r.result);r.onerror=reject;});
      const counts={};
      try {for(const name of db.objectStoreNames){
        const keys=await new Promise((resolve,reject)=>{const r=db.transaction(name).objectStore(name).getAllKeys();r.onsuccess=()=>resolve(r.result);r.onerror=reject;});
        counts[name]=keys.filter(key=>(Array.isArray(key)?key[0]:key)===vault).length;
      }}finally{db.close();}
      return counts;
    };
    window.__backendStart=async()=>{
      const worker=new __NativeWorker('/worker.js',{type:'module'});
      await new Promise((resolve,reject)=>{worker.onmessage=({data})=>{if(data==='ready')resolve();};worker.onerror=reject;});
      window.__backend=command=>new Promise(resolve=>{
        worker.onmessage=({data})=>resolve(JSON.parse(new TextDecoder().decode(data)).result);
        worker.postMessage(new TextEncoder().encode(JSON.stringify({generation:99,command})));
      });
    };`});
  await rpc('Page.reload');
  const state=()=>evaluate('window.confidex?.snapshot()');
  const until=async predicate=>{
    for(let i=0;i<800;i++){let s;try{s=await state();}catch{}if(s&&await predicate(s))return s;await delay(50);}
    throw Error('Removal timeout: '+JSON.stringify(await state()));
  };
  const click=async id=>{
    for(let i=0;i<60;i++){
      const s=await until(s=>s.hits[id]),[x,y]=s.hits[id];
      let viewport=null;
      if(id.startsWith('remove-')&&!['remove-vault','remove-confirm','remove-cancel'].includes(id))viewport=s.bounds['remove-body'];
      else if(id==='remove-vault')viewport=s.bounds['preferences-viewport'];
      const top=Math.max(0,viewport?.[1]??0),bottom=Math.min(height,viewport?.[3]??height);
      if(y>=top+2&&y<=bottom-2){
        for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});
        await delay(120);return;
      }
      assert(viewport,'No scroll viewport for '+id);
      const point={x:viewport[0]+8,y:(top+bottom)/2};
      await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
      await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:y<top?-160:160});await delay(120);
    }
    throw Error('Cannot scroll to '+id);
  };
  const confirm=async()=>{
    const before=await evaluate('window.__removeRequests??0');
    for(let step=0;step<2;step++){
      await click('remove-confirm');
      assert.equal(await evaluate('window.__removeRequests??0'),before);
      assert(!(await state()).busy);
    }
    await click('remove-confirm');
    assert.equal(await evaluate('window.__removeRequests??0'),before+1);
  };
  const text=async(id,value)=>{
    await click(id);
    for(const type of ['rawKeyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});
    await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});
    await rpc('Input.insertText',{text:value});await delay(100);
  };
  const shot=async name=>{await delay(200);await writeFile(`${output}/${width}-${name}.png`,Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));};
  const escape=async()=>{for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'Escape',code:'Escape',windowsVirtualKeyCode:27});await delay(200);};
  const section=async id=>{if((await state()).hits['preferences-sections'])await click('preferences-sections');await click(id);};
  await until(s=>s.screen==='catalog'&&!s.busy);
  await evaluate(`(async()=>{
    await __backendStart();window.fixture={};
    for(const [letter,name] of [['a','Public active vault'],['b','Public locked vault']]){
      const c=await __backend({Create:{name,password:'Public removal password',remember:false}});if(!c.Ok?.Created)throw Error('Create fixture failed');
      fixture[letter]=c.Ok.Created;
      let draft={record:Array(16).fill(letter==='a'?1:2),revision:null,title:name,tags:['local-tag'],fields:[]};
      for(let i=0;i<2;i++){
        const saved=await __backend({Save:{draft,epoch:100+i}});if(!saved.Ok?.Saved)throw Error('Save fixture failed');
        draft=(await __backend({Open:{record:draft.record}})).Ok.Draft;
      }
      if((await __backend({SyncConfig:{server:${JSON.stringify(server)}}})).Err)throw Error('Configure fixture failed');
      if(letter==='b')fixture.staleDraft=draft;
    }
    __catalogRefresh();
  })()`);
  await until(async s=>!s.busy&&(await evaluate('window.__catalog?.length===2')));
  const indexes=await evaluate('Object.fromEntries(__catalog.map((v,i)=>[v.name,i]))');
  await click('vault-'+indexes['Public active vault']);await until(s=>s.screen==='unlock');
  await text('secret-key',await evaluate('fixture.a.key'));
  await text('password','Public removal password');await click('submit');await until(s=>s.screen==='open'&&!s.busy&&s.hits['record-0']);
  await click('record-0');await until(s=>!s.busy&&s.hits.edit);await click('edit');await text('record-title','Public unsaved draft');
  await click('settings');await section('preferences-vault-'+indexes['Public locked vault']);
  await text('rename-name','Renamed locked vault');await shot('rename-locked');
  await evaluate("__backend({RenameVault:{vault:fixture.b.info.id,expected:fixture.b.info.name,name:'Other process'}})");
  await click('rename-save');await until(async s=>!s.busy&&(await evaluate('Boolean(window.__reply?.Ok?.RenameConflict)')));await shot('rename-conflict');
  await click('rename-save');await until(async s=>!s.busy&&(await evaluate('window.__reply?.Ok?.Renamed?.name==="Renamed locked vault"')));
  assert((await state()).editing);
  await text('rename-name','Cancelled rename');await click('rename-cancel');
  await click('remove-vault');
  await until(s=>s.bounds['remove-dialog']);await shot('locked-warning');
  await text('remove-secret-key',await evaluate('fixture.b.key'));
  await text('remove-password','Public removal password');
  await click('remove-sync');await until(async s=>!s.busy&&(await evaluate('window.__removalReport?.more===false')));
  await click('remove-copy-key');await until(async s=>!s.busy&&(await evaluate('window.__copied===fixture.b.key')));
  await click('remove-confirm');await click('remove-confirm');assert.equal(await evaluate('window.__removeRequests??0'),0);
  await click('remove-cancel');assert((await state()).editing);
  await click('remove-vault');await confirm();
  await until(async s=>!s.busy&&(await evaluate('Boolean(window.__reply?.Ok?.Removed?.result?.Err?.Storage)')));
  assert((await state()).bounds['remove-dialog']);
  const retained=await evaluate('__inspect(fixture.b.info.id)');
  assert.equal(retained.vaults,1);assert.equal(retained.objects,0);assert.equal(retained['record-tags'],0);
  await shot('cleanup-error');await confirm();
  await until(async s=>!s.busy&&(await evaluate('Boolean(window.__reply?.Ok?.Removed)')));
  assert((await state()).editing);
  const removed=await evaluate('__inspect(fixture.b.info.id)');assert(Object.values(removed).every(n=>n===0),JSON.stringify(removed));
  const intact=await evaluate('__inspect(fixture.a.info.id)');assert(intact.vaults===1&&intact.objects===2);
  const stale=await evaluate('__backend({Save:{draft:fixture.staleDraft,epoch:300}})');assert.deepEqual(stale,{Err:{Storage:'NotFound'}});
  await section('preferences-section-1');await text('rename-name','Renamed current vault');
  await click('rename-save');await until(async s=>!s.busy&&(await evaluate('window.__reply?.Ok?.Renamed?.name==="Renamed current vault"')));
  assert((await state()).editing);
  await click('remove-vault');await shot('current-warning');
  await click('remove-cancel');await escape();
  await click('settings');await section('preferences-section-1');await click('remove-vault');await confirm();
  await until(s=>s.screen==='catalog'&&!s.busy);assert(!(await state()).editing);
  const final=await evaluate('__inspect(fixture.a.info.id)');assert(Object.values(final).every(n=>n===0),JSON.stringify(final));
  return {width,lockedRemoval:true,currentRemoval:true,copy:true,sync:true,storageRetry:true,threeClickConfirmation:true,renameCurrentAndLocked:true,renameConflict:true,otherDraftPreserved:true,allStoresEmpty:true};
 },{viewport:[width,height]}));
}
const storagePath=Object.keys(files).find(path=>path.endsWith('/web/storage.js'));
assert(storagePath);
await runBrowser(chrome,{...files,'/':Buffer.from('<!doctype html><meta charset="utf-8"><title>Storage fixture</title>')},async({evaluate})=>{
 const result=await evaluate(`(async()=>{
   const vault='01'.repeat(16),record='02'.repeat(16),revision='03'.repeat(32);
   const db=await new Promise((resolve,reject)=>{
     const r=indexedDB.open('confidex',3);
     r.onupgradeneeded=()=>{
       const db=r.result;
       db.createObjectStore('vaults',{keyPath:'id'});db.createObjectStore('heads',{keyPath:['vault','record']});
       db.createObjectStore('objects',{keyPath:['vault','revision']});db.createObjectStore('sync-state');
       db.createObjectStore('record-tags',{keyPath:['vault','revision','tag']}).createIndex('lookup',['vault','tag','record','revision']);
     };r.onsuccess=()=>resolve(r.result);r.onerror=reject;
   });
   await new Promise((resolve,reject)=>{
     const tx=db.transaction([...db.objectStoreNames],'readwrite');
     tx.objectStore('vaults').add({id:vault,info:{id:Array(16).fill(1),name:'Public legacy fixture'},lock:[5]});
     tx.objectStore('objects').add({vault,record,revision,wire:new Uint8Array([7])});
     tx.objectStore('heads').add({vault,record,revision});tx.objectStore('record-tags').add({vault,record,revision,tag:'local-tag'});
     tx.objectStore('sync-state').put(new Uint8Array([8]),vault);
     tx.oncomplete=resolve;tx.onabort=reject;
   });db.close();
   const {dbCall}=await import(${JSON.stringify(storagePath)});
   await dbCall('save-key',[vault,'Public key fixture']);
   if(await dbCall('load-key',[vault])!=='Public key fixture')throw Error('Saved key was not read');
   const before=await dbCall('snapshot',[vault]);
   if(Object.hasOwn(before.vault,'rememberedKey'))throw Error('Snapshot included the saved key');
   if(before.objects.length!==1||before.objects[0].wire[0]!==7||before.heads.length!==1)throw Error('Migration changed data');
   await dbCall('rename',[vault,'Public legacy fixture','Renamed legacy fixture']);
   const renamed=await dbCall('snapshot',[vault]);
   if(renamed.vault.info.name!=='Renamed legacy fixture'||renamed.vault.lock[0]!==5||renamed.objects[0].wire[0]!==7||renamed.heads[0].revision.join()!==before.heads[0].revision.join())throw Error('Rename changed vault data');
   let renameConflict=false,invalidName=false;
   try{await dbCall('rename',[vault,'Public legacy fixture','Stale']);}catch(e){renameConflict=e==='Conflict';}
   try{await dbCall('rename',[vault,'Renamed legacy fixture','雪'.repeat(43)]);}catch(e){invalidName=e==='Invalid';}
   if(!renameConflict||!invalidName)throw Error('Rename validation failed');
   const reopened=await new Promise((resolve,reject)=>{const r=indexedDB.open('confidex');r.onsuccess=()=>resolve(r.result);r.onerror=reject;});
   const storedName=await new Promise((resolve,reject)=>{const r=reopened.transaction('vaults').objectStore('vaults').get(vault);r.onsuccess=()=>resolve(r.result.info.name);r.onerror=reject;});reopened.close();
   if(storedName!=='Renamed legacy fixture')throw Error('Rename was not persisted');
   let oldVersionBlocked=false;
   await new Promise(resolve=>{const r=indexedDB.open('confidex',3);r.onerror=()=>{oldVersionBlocked=r.error.name==='VersionError';resolve();};r.onsuccess=()=>{r.result.close();resolve();};});
   const original=IDBObjectStore.prototype.delete;
   IDBObjectStore.prototype.delete=function(key){if(this.name==='vaults')throw new DOMException('Public atomic removal fixture','UnknownError');return original.call(this,key);};
   let rolledBack=false;
   try{await dbCall('remove',[vault]);}catch{rolledBack=(await dbCall('snapshot',[vault])).objects.length===1;}
   IDBObjectStore.prototype.delete=original;
   await dbCall('clear-records',[vault]);
   const blocked=[];
   for(const [op,args] of [['rename',[vault,'Renamed legacy fixture','Blocked']],['vault',[vault]],['append',[vault,record,revision,null,new Uint8Array([7]),[]]],['sync-commit',[vault,{current:[9],previous:null,objects:[],heads:[]}]]]){
     try{await dbCall(op,args);blocked.push(false);}catch(e){blocked.push(e==='Removing');}
   }
   const pending=(await dbCall('vaults',[])).length===1;
   await dbCall('remove-key',[vault]);
   await dbCall('remove',[vault]);
   let keyRemoved=false;
   try{await dbCall('load-key',[vault]);}catch(e){keyRemoved=e==='NotFound';}
   if(!keyRemoved)throw Error('Vault removal retained the saved key');
   return {oldVersionBlocked,rolledBack,pending,blocked,empty:(await dbCall('vaults',[])).length===0};
 })()`);
 assert(result.oldVersionBlocked&&result.rolledBack&&result.pending&&result.empty&&result.blocked.every(Boolean),JSON.stringify(result));
 results.push({migrationAndStorage:result});
});
console.log(JSON.stringify(results));
