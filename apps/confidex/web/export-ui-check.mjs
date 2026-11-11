import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile,readdir,rename} from 'node:fs/promises';
import {join} from 'node:path';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {assets} from './assets.mjs';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {loadUi} from './export-load-ui.mjs';
import {cancelLoadUi,observeExportWorker} from './export-cancel-ui.mjs';
const [chrome,bundle,resultDirectory,locale='en-US',kind='synthetic'] = process.argv.slice(2);
assert(chrome&&bundle&&resultDirectory,'usage: export-ui-check.mjs CHROME EXPORT_CHECK_BUNDLE RESULTS');
const plainFormats={
  'bitwarden-zip':{index:3,filename:'bitwarden-personal.zip'},
  'keepass-xml':{index:4,filename:'confidex.xml'},
  'onepassword-1pux':{index:5,filename:'confidex.1pux'},
};
const plain=plainFormats[kind];
assert(plain||['synthetic','production','kdbx','bitwarden-encrypted','load','load-cancel'].includes(kind));
const large=kind==='load'||kind==='load-cancel';
const kdbx=kind==='kdbx',encrypted=kind==='bitwarden-encrypted';
const bitwarden=kind==='production'||encrypted;
const cryptoEnvironment=encrypted
  ? createRequire(import.meta.url)('../../../crates/confidex-app/tests/import_fixtures/bitwarden_encrypted_json/capture.cjs').environment(process.env.CONFIDEX_BITWARDEN_CRYPTO_SOURCE,process.env.CONFIDEX_BITWARDEN_SDK)
  : null;
const exportPassword=' Public export 密码 é e\u0301 ';
const salts=new Set();
const Importer=bitwarden||kind==='bitwarden-zip'
  ? createRequire(import.meta.url)('../../../crates/confidex-app/tests/export_fixtures/bitwarden_json/reader.cjs').loadImporter(process.env.CONFIDEX_BITWARDEN_SOURCE)
  : null;
const OnePasswordImporter=kind==='onepassword-1pux'
  ? createRequire(import.meta.url)('../../../crates/confidex-app/tests/export_fixtures/onepassword_1pux/reader.cjs').loadImporter(process.env.CONFIDEX_BITWARDEN_SOURCE,process.env.CONFIDEX_ONEPASSWORD_READER_SOURCE)
  : null;
await mkdir(resultDirectory,{recursive:true});
const keyfile=join(resultDirectory,'public.key');
if(kdbx)await writeFile(keyfile,Buffer.alloc(32,7));
const files=await assets(bundle);
const seedFunction=large?'seed_export_load_ui_check':bitwarden||plain?'seed_bitwarden_export_ui_check':kdbx?'seed_kdbx_export_ui_check':'seed_export_ui_check';
files['/public-export-seed.js']=Buffer.from(`import init,{${seedFunction} as seed} from '/app.js';await init();self.onmessage=async()=>self.postMessage(JSON.parse(await seed()));self.postMessage('ready');`);
const results=[];
for(const width of [1320,390]) {
  const directory=join(resultDirectory,String(width));await mkdir(directory,{recursive:true});
  results.push(await runBrowser(chrome,files,async({command,evaluate})=>{
    const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
    const snapshot=()=>evaluate('window.confidex?.snapshot()');
    const until=async(predicate)=>{const deadline=Date.now()+45000;for(;;){let s;try{s=await snapshot();}catch{}if(s&&predicate(s))return s;if(Date.now()>=deadline){await capture('failure-state');assert.fail(JSON.stringify(s));}await delay(40);}};
    const capture=async(name,settle=120)=>{if(settle)await delay(settle);await writeFile(join(directory,name+'.png'),Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));};
    const click=async(id)=>{
      for(let attempt=0;attempt<24;attempt++) {
        const s=await until(s=>s.hits[id]);const [x,y]=s.hits[id];
        const formatOption=/^export-format-\d+$/.test(id);
        const r=formatOption?s.bounds['export-format-options']:id.startsWith('preferences-section')?s.bounds['preferences-body']:id.startsWith('export-')?s.bounds['export-window-body']??s.bounds['preferences-viewport']:s.bounds['preferences-viewport'];
        const top=r?.[1]??10,bottom=r?.[3]??980;
        if(y>=top+2&&y<=bottom-2&&x>=0&&x<width) {
          await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});await delay(35);
          for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});await delay(120);return;
        }
        const point={x:formatOption?x:r?r[0]+5:width-18,y:(top+bottom)/2};
        await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
        await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:y<top?-180:180});await delay(120);
      }
      await capture('unreachable-'+id);
      const failed=await snapshot();
      assert.fail(JSON.stringify({id,hit:failed.hits[id],bounds:failed.bounds}));
    };
    const text=async(id,text)=>{await click(id);await rpc('Input.insertText',{text});await delay(50);};
    const open=async()=>{await click('settings');if(!(await snapshot()).hits['preferences-section-1'])await click('preferences-sections');await click('preferences-section-1');await click('export-records');await until(s=>s.hits['export-format']);if(kdbx||encrypted||plain){await click('export-format');await click('export-format-'+(plain?.index??(kdbx?1:2)));}await until(s=>kdbx||encrypted?s.hits['export-password']:s.hits['export-review']&&(!plain||!s.hits['export-bitwarden-profile']));};
    await until(s=>s.screen==='catalog'&&!s.busy);
    await evaluate(`new Promise((resolve,reject)=>{const worker=new Worker('/public-export-seed.js',{type:'module'});worker.onerror=()=>reject(Error('seed failed'));worker.onmessage=({data})=>{if(data==='ready')worker.postMessage('seed');else{window.publicExportSeed=data;worker.terminate();resolve(true);}};})`);
    const seed=await evaluate('publicExportSeed');
    await rpc('Page.enable');
    await rpc('Page.addScriptToEvaluateOnNewDocument',{source:`Object.defineProperty(Navigator.prototype,'languages',{get:()=>[${JSON.stringify(locale)}]});${kind==='load-cancel'?`(${observeExportWorker.toString()})();`:''}`});
    await rpc('Page.reload',{ignoreCache:true});
    await until(s=>s.vaults===1&&!s.busy&&s.locale===locale);await click('vault-0');
    await until(s=>s.screen==='unlock'&&!s.busy);
    await text('secret-key',seed.key);await text('password','public-export-contract-password');await click('submit');
    await until(s=>s.screen==='open'&&!s.busy&&(large?s.rows>0:s.rows===2));
    await rpc('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:directory});
    if(kind==='load')return loadUi({width,locale,directory,rpc,evaluate,snapshot,until,capture,click,text,open});
    if(kind==='load-cancel')return cancelLoadUi({width,locale,directory,rpc,evaluate,snapshot,until,capture,click,text,open,seed});
    if(kdbx) {
      const pick=async()=>{
        await rpc('Page.enable');await rpc('Page.setInterceptFileChooserDialog',{enabled:true});await click('export-choose-keyfile');
        const {root}=await rpc('DOM.getDocument');
        const {nodeId}=await rpc('DOM.querySelector',{nodeId:root.nodeId,selector:'input[type=file]'});assert(nodeId);
        await rpc('DOM.setFileInputFiles',{nodeId,files:[keyfile]});await until(s=>s.hits['export-review']);
      };
      const configure=async(mode,subset=true)=>{
        await open();assert(!(await snapshot()).hits['export-review'],'blank password can export');
        if(subset){await click('export-all-records');await click('export-record-0');}
        if(mode==='keyfile')await click('export-use-password');
        if(mode==='password'||mode==='both')await text('export-password','PUBLIC-EXPORT');
        if(mode!=='password') {
          await click('export-use-keyfile');assert(!(await snapshot()).hits['export-review'],'missing keyfile can export');await pick();
        }
        await capture('setup-'+mode);
      };
      const review=async()=>{
        await click('export-review');await until(s=>s.hits['export-allow-losses']);
        const s=await snapshot();assert(!s.hits['export-plaintext-ack']);assert(!s.hits['export-generate']);
        assert(s.hits['export-allow-losses'][1]<s.bounds['export-actions'][1]);
        await capture('review');await click('export-allow-losses');
      };
      const close=async()=>{await click('export-cancel');await until(s=>!s.bounds['export-window']);};
      const outputs=[];
      for(const mode of ['password','keyfile','both','empty-both']) {
        await configure(mode);await review();await click('export-generate');await until(s=>s.hits['export-save']);
        assert(!(await readdir(directory)).some(n=>n.endsWith('.kdbx')),'published before Save');await capture('ready-'+mode);
        await click('export-save');await until(s=>s.hits['export-restart']);
        const filename=join(directory,'confidex.kdbx');
        for(let i=0;;i++){try{await readFile(filename);break;}catch{assert(i<100,'KDBX download missing');await delay(80);}}
        const bytes=await readFile(filename);assert.equal(bytes.readUInt32LE(),0x9aa2d903);assert.equal(bytes.readUInt32LE(4),0xb54bfb67);
        await rename(filename,join(resultDirectory,`${width}-${mode}.kdbx`));outputs.push({mode,bytes:bytes.length});
        await close();
      }
      await configure('password',false);await review();assert(!(await snapshot()).hits['export-generate'],'duplicate fields bypassed blocked report');
      await capture('blocked');await close();
      await configure('password');await review();await click('export-generate');await until(s=>s.hits['export-save']);
      await evaluate(`window.exportOriginalClick=HTMLAnchorElement.prototype.click;HTMLAnchorElement.prototype.click=function(){throw Error('public save failure');};true`);
      await click('export-save');await until(s=>s.hits['export-restart']);await capture('save-error');
      await evaluate('HTMLAnchorElement.prototype.click=window.exportOriginalClick;true');await close();
      await configure('password');await review();await click('export-generate');await until(s=>s.hits['export-save']);await close();
      assert(!(await readdir(directory)).some(n=>n.endsWith('.kdbx')),'canceled export published');
      await configure('password');await review();await click('export-generate');await until(s=>s.hits['export-save']);
      for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:type==='keyDown'?10:0});
      await until(s=>s.screen==='unlock'&&!s.busy);assert(!(await snapshot()).bounds['export-window']);await capture('locked');
      return {width,locale,outputs,encrypted:true,explicitLossConsent:true,blocked:true,saveFailure:true,readyCancel:true,lockCleared:true};
    }
    if(plain) {
      const close=async()=>{await click('export-cancel');await until(s=>!s.bounds['export-window']);};
      const review=async(subset=true)=>{
        await open();assert(!(await snapshot()).hits['export-bitwarden-profile']);
        if(subset){await click('export-all-records');await click('export-record-0');}
        await click('export-review');await until(s=>s.hits['export-plaintext-ack']);
        assert(!(await snapshot()).hits['export-generate']);
        await click('export-plaintext-ack');assert(!(await snapshot()).hits['export-generate'],'losses need separate consent');
        await click('export-allow-losses');
      };
      const ready=async()=>{await review();await click('export-generate');await until(s=>s.hits['export-save']);};
      const downloads=[];
      for(const mode of kind==='keepass-xml'?['selected']:['selected','all']) {
        await open();
        if(mode==='selected'){await click('export-all-records');await click('export-record-0');}
        await capture(mode+'-setup');assert(!(await snapshot()).hits['export-bitwarden-profile']);
        await click('export-review');await until(s=>s.hits['export-plaintext-ack']);
        assert(!(await snapshot()).hits['export-generate']);await capture(mode+'-review');
        await click('export-plaintext-ack');assert(!(await snapshot()).hits['export-generate']);
        await click('export-allow-losses');await click('export-generate');await until(s=>s.hits['export-save']);
        assert(!(await readdir(directory)).includes(plain.filename),'published before Save');await capture(mode+'-ready');
        await click('export-save');await until(s=>s.hits['export-restart']);
        const filename=join(directory,plain.filename);
        for(let i=0;;i++){try{await readFile(filename);break;}catch{assert(i<100,'download missing');await delay(80);}}
        const bytes=await readFile(filename),target=join(resultDirectory,`${width}-${kind}-${mode}.${plain.filename.split('.').at(-1)}`);
        await rename(filename,target);
        const expectedRecords=mode==='selected'?1:2;
        let attachment;
        if(kind!=='keepass-xml') {
          const checked=JSON.parse(execFileSync('python3',[fileURLToPath(new URL('./export-archive-ui-reader.py',import.meta.url)),kind,target],{encoding:'utf8',maxBuffer:16<<20}));
          assert.equal(checked.records,expectedRecords);attachment=checked.attachmentSha256;
          const importer=kind==='bitwarden-zip'?new Importer():new OnePasswordImporter({getFeatureFlag:async flag=>{assert.equal(flag,'new-item-types');return false;}});
          const parsed=await importer.parse(checked.data);
          assert.equal(parsed.success,true);assert.equal(parsed.errors.length,0);assert.equal(parsed.ciphers.length,expectedRecords);
          assert.equal(parsed.ciphers[0].login.password,'current public password\n第二行');
          if(kind==='bitwarden-zip') {
            assert.deepEqual(Array.from(parsed.folders,f=>f.name),['demo']);
            assert.deepEqual(Array.from(parsed.folderRelationships,p=>Array.from(p)),mode==='selected'?[[0,0]]:[[0,0],[1,0]]);
          }
          if(kind==='bitwarden-zip'&&mode==='all')assert.deepEqual(Array.from(parsed.ciphers[1].fields,f=>[f.name,f.value,f.type]),[['','',0],['Same','line one\n公開',0],['Same','PUBLIC-HIDDEN',1]]);
          if(kind==='onepassword-1pux'&&mode==='all')assert(parsed.ciphers[1].fields.some(f=>f.name==='Same'&&f.value==='PUBLIC-HIDDEN'&&f.type===1));
        } else assert(bytes.subarray(0,100).toString().includes('KeePassFile'));
        downloads.push({mode,bytes:bytes.length,records:expectedRecords,attachmentSha256:attachment});await close();
      }
      if(kind==='keepass-xml') {await review(false);assert(!(await snapshot()).hits['export-generate'],'duplicate keys bypassed Blocked report');await capture('blocked');await close();}
      await ready();
      await evaluate(`window.exportOriginalClick=HTMLAnchorElement.prototype.click;HTMLAnchorElement.prototype.click=function(){throw Error('public save failure');};true`);
      await click('export-save');await until(s=>s.hits['export-restart']);await capture('save-error');
      await evaluate('HTMLAnchorElement.prototype.click=window.exportOriginalClick;true');await close();
      await ready();await close();assert(!(await readdir(directory)).includes(plain.filename),'canceled export published');
      await ready();
      for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:type==='keyDown'?10:0});
      await until(s=>s.screen==='unlock'&&!s.busy);assert(!(await snapshot()).bounds['export-window']);await capture('locked');
      assert(!(await readdir(directory)).includes(plain.filename),'locked export published');
      return {width,locale,format:kind,downloads,independentArchiveReader:kind!=='keepass-xml',explicitLossAndPlaintextConsent:true,saveFailure:true,readyCancel:true,lockCleared:true};
    }
    await open();await capture('setup');
    if(bitwarden) {
      const downloaded=[];
      for(const organization of [false,true]) {
        const profile=organization?'organization':'personal';
        if(encrypted){assert(!(await snapshot()).hits['export-review'],'blank password can export');await text('export-password',exportPassword);}
        if(organization) {
          await click('export-bitwarden-profile');await click('export-bitwarden-organization');
        } else {
          await click('export-all-records');await click('export-record-0');
        }
        await capture(profile+'-setup');
        await click('export-review');await until(s=>s.hits[encrypted?'export-allow-losses':'export-plaintext-ack']);
        assert(!(await snapshot()).hits['export-generate'],'export enabled before fresh consent');
        const consent=encrypted?'export-allow-losses':'export-plaintext-ack';
        assert((await snapshot()).hits[consent][1]<(await snapshot()).bounds['export-actions'][1]);
        await capture(profile+'-review');
        if(encrypted)assert(!(await snapshot()).hits['export-plaintext-ack']);
        else {await click('export-plaintext-ack');assert(!(await snapshot()).hits['export-generate'],'losses need separate consent');}
        await click('export-allow-losses');await click('export-generate');await until(s=>s.hits['export-save']);
        assert.equal((await readdir(directory)).filter(n=>n.endsWith('.json')).length,downloaded.length,'file published before Save');
        await capture(profile+'-ready');await click('export-save');await until(s=>s.hits['export-restart']);
        const filename=join(directory,encrypted?'bitwarden-encrypted.json':'bitwarden-'+profile+'.json');
        for(let i=0;;i++){try{await readFile(filename);break;}catch{assert(i<100,'download missing');await delay(80);}}
        const bytes=await readFile(filename);let clear=bytes.toString('utf8');
        if(encrypted) {
          const doc=JSON.parse(clear),{sdk,keys}=cryptoEnvironment;
          assert.equal(doc.encrypted,true);assert.equal(doc.passwordProtected,true);
          assert.deepEqual([doc.kdfType,doc.kdfIterations,doc.kdfMemory,doc.kdfParallelism],[1,3,64,4]);
          assert(!salts.has(doc.salt),'reused salt');salts.add(doc.salt);
          const config={toSdkConfig:()=>({argon2id:{iterations:3,memory:64,parallelism:4}})};
          const key=(await keys.deriveVaultExportKey(exportPassword,doc.salt,config)).toEncoded();
          clear=sdk.PureCrypto.symmetric_decrypt_string(doc.data,key);
          assert.match(sdk.PureCrypto.symmetric_decrypt_string(doc.encKeyValidation_DO_NOT_EDIT,key),/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
          const wrong=(await keys.deriveVaultExportKey(exportPassword.trim(),doc.salt,config)).toEncoded();
          assert.throws(()=>sdk.PureCrypto.symmetric_decrypt_string(doc.data,wrong));
          await rename(filename,join(directory,'bitwarden-'+profile+'-encrypted.json'));
        }
        const json=JSON.parse(clear);
        assert.equal(json.encrypted,false);assert.equal(json.items.length,organization?2:1);
        assert.equal(json.items[0].login.password,'current public password\n第二行');
        assert(!clear.includes('deleted public password'));
        const importer=new Importer();importer.organizationId=organization?'public-destination-organization':null;
        const parsed=await importer.parse(clear);
        assert.equal(parsed.success,true);assert.equal(parsed.errors.length,0);
        assert.equal(parsed.ciphers.length,organization?2:1);
        assert.equal(parsed.ciphers[0].login.password,'current public password\n第二行');
        assert(parsed.ciphers.every(c=>c.id===null&&c.organizationId===null&&c.key===null));
        if(organization) {
          assert.deepEqual(Array.from(parsed.collections,g=>g.name),['demo','旅行']);
          assert.deepEqual(Array.from(parsed.collectionRelationships,p=>Array.from(p)),[[0,0],[0,1],[1,0]]);
          assert.deepEqual(Array.from(parsed.ciphers[1].fields,f=>[f.name,f.value,f.type]),[
            ['','',0],['Same','line one\n公開',0],['Same','PUBLIC-HIDDEN',1]]);
        } else {
          assert.deepEqual(Array.from(parsed.folders,g=>g.name),['demo']);
          assert.deepEqual(Array.from(parsed.folderRelationships,p=>Array.from(p)),[[0,0]]);
        }
        downloaded.push({profile,bytes:bytes.length,records:parsed.ciphers.length});
        await capture(profile+'-download-started');
        await click('export-restart');await until(s=>s.hits['export-review']);
        if(encrypted){await click('export-format');await click('export-format-2');await until(s=>s.hits['export-password']);}
      }
      if(encrypted) {
        const ready=async()=>{
          assert(!(await snapshot()).hits['export-review'],'password survived restart');
          await text('export-password',exportPassword);await click('export-review');
          await until(s=>s.hits['export-allow-losses']);
          assert(!(await snapshot()).hits['export-generate'],'previous consent survived restart');
          await click('export-allow-losses');await click('export-generate');await until(s=>s.hits['export-save']);
        };
        await ready();
        await evaluate(`window.exportOriginalClick=HTMLAnchorElement.prototype.click;HTMLAnchorElement.prototype.click=function(){throw Error('public save failure');};true`);
        await click('export-save');await until(s=>s.hits['export-restart']);await capture('save-error');
        await evaluate('HTMLAnchorElement.prototype.click=window.exportOriginalClick;true');
        await click('export-cancel');await until(s=>!s.bounds['export-window']);
        await open();await ready();await capture('cancel-ready');
        await click('export-cancel');await until(s=>!s.bounds['export-window']);
        assert.equal((await readdir(directory)).filter(n=>n.endsWith('.json')).length,2,'failed or canceled export published');
        await open();
      }
      if(encrypted)await text('export-password',exportPassword);
      await click('export-review');await until(s=>s.hits[encrypted?'export-allow-losses':'export-plaintext-ack']);
      assert(!(await snapshot()).hits['export-generate'],'previous consent survived restart');
      await capture('fresh-review');
      if(encrypted){await click('export-allow-losses');await click('export-generate');await until(s=>s.hits['export-save']);}
      await rpc('Input.dispatchKeyEvent',{type:'keyDown',key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:10});
      await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:0});
      await until(s=>s.screen==='unlock'&&!s.busy);assert(!(await snapshot()).bounds['export-window']);
      await capture('locked');
      return {width,locale,downloaded,encrypted,saveFailure:encrypted,readyCancel:encrypted,independentReader:true,freshConsent:true,lockCleared:true};
    }
    await click('export-all-records');await click('export-record-0');await capture('selection');
    await click('export-review');await until(s=>s.hits['export-plaintext-ack']);
    assert(!(await snapshot()).hits['export-generate'],'plaintext export enabled without consent');await capture('review');
    assert((await snapshot()).hits['export-plaintext-ack'][1]<(await snapshot()).bounds['export-actions'][1],'consent is below actions');
    await click('export-plaintext-ack');await click('export-generate');await until(s=>s.hits['export-save']);
    assert.equal((await readdir(directory)).filter(n=>!n.endsWith('.png')).length,0,'file published before Save');await capture('ready');
    await click('export-save');await until(s=>s.hits['export-restart']);
    const filename=join(directory,'public-synthetic-export.bin');
    for(let i=0;;i++){try{await readFile(filename);break;}catch{assert(i<100,'download missing');await delay(80);}}
    const bytes=await readFile(filename);assert(bytes.length>4);assert.equal(bytes.readUInt32LE(0)+4,bytes.length,'selected export contains extra records');
    await capture('download-started');await click('export-cancel');await until(s=>!s.bounds['export-window']);
    await open();await click('export-format');await click('export-format-1');await click('export-review');await until(s=>s.hits['export-plaintext-ack']);
    assert(!(await snapshot()).hits['export-generate'],'blocked format can export');await capture('blocked');await click('export-next');await until(s=>s.hits['export-previous']&&!s.hits['export-next']);await capture('blocked-next');await click('export-previous');await until(s=>s.hits['export-next']&&!s.hits['export-previous']);await click('export-cancel');
    await until(s=>!s.bounds['export-window']);await open();await click('export-review');await until(s=>s.hits['export-allow-losses']);
    assert(!(await snapshot()).hits['export-generate']);await capture('losses');
    for(const id of ['export-allow-losses','export-plaintext-ack'])assert((await snapshot()).hits[id][1]<(await snapshot()).bounds['export-actions'][1],'consent is below actions');
    await click('export-plaintext-ack');assert(!(await snapshot()).hits['export-generate']);
    await click('export-allow-losses');await click('export-generate');await until(s=>s.hits['export-save']);
    await click('export-cancel');await until(s=>!s.bounds['export-window']);
    await open();await click('export-format');await click('export-format-2');await text('export-password','PUBLIC-MASKED-EXPORT-PASSWORD');
    await capture('credentials');await click('export-use-keyfile');assert(!(await snapshot()).hits['export-review']);await capture('credentials-keyfile-required');
    await click('export-cancel');await until(s=>!s.bounds['export-window']);
    await open();await click('export-review');await until(s=>s.hits['export-allow-losses']);
    await click('export-allow-losses');await click('export-plaintext-ack');await click('export-generate');await until(s=>s.hits['export-save']);
    await evaluate(`window.exportOriginalClick=HTMLAnchorElement.prototype.click;HTMLAnchorElement.prototype.click=function(){throw Error('public save failure');};true`);
    await click('export-save');await until(s=>s.hits['export-restart']);await capture('save-error');
    await evaluate('HTMLAnchorElement.prototype.click=window.exportOriginalClick;true');
    await click('export-cancel');await until(s=>!s.bounds['export-window']);await open();await click('export-review');await until(s=>s.hits['export-plaintext-ack']);
    await rpc('Input.dispatchKeyEvent',{type:'keyDown',key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:10});
    await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:0});
    await until(s=>s.screen==='unlock'&&!s.busy);
    assert(!(await snapshot()).bounds['export-window']);await capture('locked');
    assert.equal((await readdir(directory)).filter(n=>n.endsWith('.bin')).length,1);
    return {width,locale,bytes:bytes.length,selectedRecords:1,blocked:true,explicitLossConsent:true,saveFailure:true,lockCleared:true};
  },{viewport:[width,1000],windowSize:[width,1000]}));
}
console.log(JSON.stringify(results));
