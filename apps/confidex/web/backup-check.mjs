import assert from 'node:assert/strict';
import {mkdir, readFile, stat, writeFile} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';

const [chrome,bundle,output='/tmp/confidex-backup-check'] = process.argv.slice(2);
assert(chrome && bundle, 'Usage: backup-check.mjs CHROME BUNDLE [OUTPUT]');
await mkdir(output,{recursive:true});
const files=await assets(bundle);
const storagePath=Object.keys(files).find(p=>p.endsWith('/web/storage.js'));
assert(storagePath);
const results=[];
for (const width of [1180,390]) {
  const directory=resolve(output,String(width)); await mkdir(directory,{recursive:true});
  results.push(await runBrowser(chrome,files,async ({command,evaluate})=>{
    const rpc=async(method,params={})=>{const reply=await command(method,params);assert(!reply.error,JSON.stringify(reply));return reply.result;};
    const prf = width > 1000;
    await rpc('WebAuthn.enable');
    await rpc('WebAuthn.addVirtualAuthenticator', {options:{
      protocol:'ctap2', ctap2Version:'ctap2_1', transport:'internal',
      hasResidentKey:true, hasUserVerification:true, hasPrf:prf,
      automaticPresenceSimulation:true, isUserVerified:true,
    }});
    await evaluate(`window.keyStorageWarnings=[];window.confirm=message=>{
      keyStorageWarnings.push(message);return Boolean(window.allowPlainKey);
    };`);
    if (prf) await evaluate(`
      window.passkeyAssertions=0;
      for (const method of ['create','get']) {
        const original=navigator.credentials[method].bind(navigator.credentials);
        navigator.credentials[method]=async options=>{
          const credential=await original(options);
          const extensions=credential.getClientExtensionResults();
          if (method==='create') {
            // Use a different value at registration and at assertion.
            extensions.prf={enabled:true,results:{first:Array(32).fill(42)}};
          } else {
            passkeyAssertions++;
            const first=extensions.prf?.results?.first;
            if (first instanceof ArrayBuffer) extensions.prf={results:{first:Array.from(new Uint8Array(first))}};
          }
          Object.defineProperty(credential,'getClientExtensionResults',{value:()=>extensions});
          return credential;
        };
      }
    `);
    const state=()=>evaluate('window.confidex?.snapshot()');
    const until=async(predicate)=>{
      for(let i=0;i<600;i++) {const s=await state();if(s&&predicate(s))return s;await delay(50);}
      throw Error('Backup UI timeout: '+JSON.stringify(await state()));
    };
    const click=async id=>{
      for(let i=0;i<30;i++) {
        const s=await until(s=>s.hits[id]),[x,y]=s.hits[id];
        const r=s.bounds['preferences-viewport'],top=r?.[1]??0,bottom=r?.[3]??1000;
        if(y>=top+2&&y<=bottom-2) {
          for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});
          await delay(100);return;
        }
        const point={x:r?r[0]+5:width-20,y:(top+bottom)/2};
        await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
        await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:y<top?-180:180});await delay(100);
      }
      throw Error('Cannot reach '+id);
    };
    const text=async(id,value)=>{
      await click(id);
      for(const type of ['rawKeyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});
      await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});
      await rpc('Input.insertText',{text:value});await delay(50);
    };
    const capture=async name=>writeFile(join(directory,name+'.png'),Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));
    const pick=async path=>{
      await rpc('Page.enable');await rpc('Page.setInterceptFileChooserDialog',{enabled:true});
      await click('backup-import');
      const {root}=await rpc('DOM.getDocument');
      const {nodeId}=await rpc('DOM.querySelector',{nodeId:root.nodeId,selector:'input[type=file]'});
      assert(nodeId,'ZIP picker was not created: '+JSON.stringify(await state()));
      await rpc('DOM.setFileInputFiles',{nodeId,files:[resolve(path)]});
      await until(s=>!s.busy);
    };
    const password='public-backup-browser-password';
    await until(s=>s.screen==='catalog'&&!s.busy);
    const grid=await state();
    if(width>1000)assert(Math.abs(grid.hits.import[1]-grid.hits['backup-import'][1])<1);
    else assert(grid.hits['backup-import'][1]>grid.hits.import[1]);
    await capture('catalog-grid');
    await click('create');await click('create-sync');
    await text('name','Public backup fixture');await text('password',password);await text('repeat',password);
    await click('submit');await until(s=>s.screen==='key'&&!s.busy);
    await evaluate(`(async()=>{
      window.backupDb=(await import(${JSON.stringify(storagePath)})).dbCall;
      const vault=(await backupDb('vaults',[]))[0];
      window.backupVault=vault.id.map(n=>n.toString(16).padStart(2,'0')).join('');
      navigator.clipboard.writeText=async text=>{window.backupKey=text;};
    })()`);
    await click('copy-key');
    const key=await evaluate('backupKey');assert(key.length===87);
    const stored=await evaluate(`(async()=>{
      const key=await backupDb('load-key',[backupVault]);
      return {encrypted:key instanceof Uint8Array,missing:key===null,warnings:keyStorageWarnings.length};
    })()`);
    assert.deepEqual(stored,{encrypted:prf,missing:!prf,warnings:prf?0:1});
    if (prf) assert.equal(await evaluate('passkeyAssertions'),1);

    await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
    await click('new-record');await click('template-login');await text('record-title','Public record fixture');
    await text('value-1-password','public-record-password');await click('save');await until(s=>s.rows===1&&!s.busy);
    await click('edit');await text('record-title','Public second revision');await click('save');await until(s=>!s.busy&&!s.editing);
    if(width<960)await click('back');
    await evaluate(`(async()=>{const s=await backupDb('snapshot',[backupVault]);window.backupExpected=JSON.stringify({heads:s.heads,objects:s.objects.map(o=>({head:o.head,wire:Array.from(o.wire)}))});})()`);
    await evaluate('navigator.serviceWorker.ready.then(()=>true)');
    for (let attempt=0;!await evaluate('Boolean(navigator.serviceWorker.controller)');attempt++) {
      assert(attempt<100,'service worker did not control the app');
      await delay(50);
    }
    await rpc('Network.enable');await rpc('Network.emulateNetworkConditions',{offline:true,latency:0,downloadThroughput:0,uploadThroughput:0});
    await click('sync');await until(s=>s.hits['backup-export']);await click('backup-export');
    await until(s=>s.screen==='backup'&&!s.busy);await capture('export-choice');
    assert(!(await state()).hits['backup-sync'],'disabled sync was offered as an enabled action');
    await click('backup-offline');await until(s=>s.hits['backup-save']&&!s.busy);
    await rpc('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:directory});
    await click('backup-save');
    const zip=join(directory,'confidex-backup.zip');
    for(let i=0;i<100;i++) {if(await stat(zip).catch(()=>null))break;await delay(100);}
    assert((await readFile(zip)).length>300);
    await capture('download-started');
    await click('lock');await until(s=>s.screen==='unlock'&&!s.busy);await click('vaults');await until(s=>s.screen==='catalog'&&!s.busy);
    await evaluate(`new Promise((resolve,reject)=>{const r=indexedDB.open('confidex');r.onsuccess=()=>{const db=r.result;const tx=db.transaction(Array.from(db.objectStoreNames),'readwrite');for(const n of db.objectStoreNames)tx.objectStore(n).clear();tx.oncomplete=()=>{db.close();resolve(true);};tx.onabort=()=>reject(tx.error);};})`);
    await pick(zip);await until(s=>s.screen==='import'&&!s.busy);
    assert(!(await state()).hits['sync-server']);await capture('import-credentials');
    const symbols = key.toLowerCase().replaceAll('-','');
    const invalid = (symbols[0] === 'a' ? 'b' : 'a') + symbols.slice(1,-1) + 'b';
    await text('secret-key',symbols.slice(0,-1));
    assert(!(await state()).hits['secret-key-error']);
    await text('secret-key',invalid);
    await until(s=>s.hits['secret-key-error']);
    await text('secret-key',symbols);
    await until(s=>!s.hits['secret-key-error']);
    await text('password','wrong-password');await click('submit');
    await until(s=>!s.busy&&s.error==='vault-error-auth');assert.equal(await evaluate('(async()=> (await backupDb("vaults",[])).length)()'),0);
    await evaluate('window.allowPlainKey=true');
    await text('password',password);await click('submit');await until(s=>s.screen==='open'&&!s.busy&&s.rows===1);
    assert.equal(await evaluate(`(async()=>{const s=await backupDb('snapshot',[backupVault]);return JSON.stringify({heads:s.heads,objects:s.objects.map(o=>({head:o.head,wire:Array.from(o.wire)}))})===backupExpected;})()`),true);
    assert.equal(await evaluate('(async()=>await backupDb("sync-state",[backupVault]))()'),null);
    await capture('restored-offline');
    const saved=await evaluate(`(async()=>{
      const key=await backupDb('load-key',[backupVault]);
      const snapshot=await backupDb('snapshot',[backupVault]);
      return {encrypted:key instanceof Uint8Array,plaintext:key===backupKey,leaked:Object.hasOwn(snapshot.vault,'rememberedKey')};
    })()`);
    assert.deepEqual(saved,{encrypted:prf,plaintext:!prf,leaked:false});
    await click('lock');await until(s=>s.screen==='unlock'&&!s.busy);
    assert(!(await state()).hits['secret-key']);
    await text('password',password);await click('submit');
    await until(s=>s.screen==='open'&&!s.busy&&s.rows===1);
    const beforeReload = await evaluate('performance.timeOrigin');
    await rpc('Page.reload',{ignoreCache:true});
    await until(s=>s.screen==='catalog'&&!s.busy);
    assert.notEqual(await evaluate('performance.timeOrigin'),beforeReload);
    await click('vault-0');
    await until(s=>s.screen==='unlock'&&!s.busy);
    assert(!(await state()).hits['secret-key']);
    await text('password',password);await click('submit');
    await until(s=>s.screen==='open'&&!s.busy&&s.rows===1);
    await evaluate(`(async()=>{window.backupDb=(await import(${JSON.stringify(storagePath)})).dbCall;})()`);
    await click('lock');await until(s=>s.screen==='unlock'&&!s.busy);await click('vaults');await until(s=>s.screen==='catalog'&&!s.busy);
    await pick(zip);await text('secret-key',key);await text('password',password);await click('submit');
    await until(s=>!s.busy&&s.error==='vault-error-conflict');await capture('duplicate-kept');
    assert.equal(await evaluate('(async()=> (await backupDb("vaults",[])).length)()'),1);
    return {width,prf,grid:true,offline:true,history:true,wrongPassword:true,existingVaultKept:true};
  },{viewport:[width,1000],passkeys:true}));
}
console.log(JSON.stringify(results));
