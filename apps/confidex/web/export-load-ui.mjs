import assert from 'node:assert/strict';
import {readFile,readdir,rename} from 'node:fs/promises';
import {join} from 'node:path';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';

export async function loadUi({width,locale,directory,rpc,evaluate,snapshot,until,capture,click,text,open}) {
  const require=createRequire(import.meta.url);
  const Importer=require('../../../crates/confidex-app/tests/export_fixtures/bitwarden_json/reader.cjs').loadImporter(process.env.CONFIDEX_BITWARDEN_SOURCE);
  const OnePasswordImporter=require('../../../crates/confidex-app/tests/export_fixtures/onepassword_1pux/reader.cjs').loadImporter(process.env.CONFIDEX_BITWARDEN_SOURCE,process.env.CONFIDEX_ONEPASSWORD_READER_SOURCE);
  const crypto=require('../../../crates/confidex-app/tests/import_fixtures/bitwarden_encrypted_json/capture.cjs').environment(process.env.CONFIDEX_BITWARDEN_CRYPTO_SOURCE,process.env.CONFIDEX_BITWARDEN_SDK);
  const password='PUBLIC-UI-LOAD-export-password';
  const python=fileURLToPath(new URL('./export-load-ui-reader.py',import.meta.url));
  const formats=[['production',0,'bitwarden-personal.json'],['kdbx',1,'confidex.kdbx'],['bitwarden-encrypted',2,'bitwarden-encrypted.json'],['bitwarden-zip',3,'bitwarden-personal.zip'],['keepass-xml',4,'confidex.xml'],['onepassword-1pux',5,'confidex.1pux']];
  const close=async()=>{await click('export-cancel');await until(s=>!s.bounds['export-window']);};
  const configure=async(index)=>{
    await open();
    if(index){await click('export-format');await click('export-format-'+index);}
    if(index===1||index===2){await until(s=>s.hits['export-password']);await text('export-password',password);}
    await until(s=>s.hits['export-review']);
  };
  const review=async(index)=>{
    await configure(index);const started=performance.now();await click('export-review');await until(s=>s.hits[index===1||index===2?'export-allow-losses':'export-plaintext-ack']);
    const reviewMs=performance.now()-started;
    const losses=Boolean((await snapshot()).hits['export-allow-losses']);assert(!(await snapshot()).hits['export-generate']);
    if(index===1||index===2)assert(!(await snapshot()).hits['export-plaintext-ack']);
    if(index!==1&&index!==2){await click('export-plaintext-ack');if(losses)assert(!(await snapshot()).hits['export-generate']);}
    if(losses)await click('export-allow-losses');
    return reviewMs;
  };
  const outputs=[];
  await evaluate('window.exportLoadBeats=0;window.exportLoadTimer=setInterval(()=>exportLoadBeats++,10);true');
  await configure(0);await click('export-all-records');
  await until(s=>Object.keys(s.hits).some(id=>/^export-record-\d+$/.test(id)));
  const visible=Object.keys((await snapshot()).hits).filter(id=>/^export-record-\d+$/.test(id));
  assert(visible.length>0&&visible.length<40);assert(!(await snapshot()).hits['export-review']);
  await capture('10000-selector');await text('export-find','Public 9999');
  const filtered=await until(s=>Object.keys(s.hits).filter(id=>/^export-record-\d+$/.test(id)).length===1);
  await click(Object.keys(filtered.hits).find(id=>/^export-record-\d+$/.test(id)));
  await click('export-review');await until(s=>s.hits['export-allow-losses']);await capture('10000-filtered-review');await close();
  for(const [kind,index,filename] of formats) {
    const reviewMs=await review(index);await capture(kind+'-10000-review');
    if(index!==5){assert((await snapshot()).hits['export-next'],'large loss report has no next page');await click('export-next');await until(s=>s.hits['export-previous']);await click('export-previous');}
    const generating=performance.now();await click('export-generate');await until(s=>s.hits['export-save']);const generateMs=performance.now()-generating;
    assert(!(await readdir(directory)).includes(filename),'published before Save');await capture(kind+'-10000-ready');
    const saving=performance.now();await click('export-save');await until(s=>s.hits['export-restart']);
    const source=join(directory,filename);
    for(let i=0;;i++){try{await readFile(source);break;}catch{assert(i<100,'load download missing');await delay(80);}}
    const saveMs=performance.now()-saving;
    const target=join(directory,'10000-'+filename);await rename(source,target);
    const bytes=await readFile(target);
    const verifying=performance.now();
    let clear=bytes.toString('utf8');
    if(index===1||index===4) {
      const checked=JSON.parse(execFileSync('python3',[python,kind,target,process.env.CONFIDEX_KEEPASSXC_CLI],{input:Buffer.from(password),encoding:'utf8',maxBuffer:32<<20}));
      assert.equal(checked.records,10000);
    } else {
      if(index===2){const document=JSON.parse(clear);const config={toSdkConfig:()=>({argon2id:{iterations:3,memory:64,parallelism:4}})};const key=(await crypto.keys.deriveVaultExportKey(password,document.salt,config)).toEncoded();clear=crypto.sdk.PureCrypto.symmetric_decrypt_string(document.data,key);}
      if(index===3||index===5){const checked=JSON.parse(execFileSync('python3',[python,kind,target],{encoding:'utf8',maxBuffer:32<<20}));clear=checked.data;}
      const importer=index===5?new OnePasswordImporter({getFeatureFlag:async()=>false}):new Importer();
      const parsed=await importer.parse(clear);assert(parsed.success);assert.equal(parsed.errors.length,0);assert.equal(parsed.ciphers.length,10000);
      const seen=new Set();
      for(const item of parsed.ciphers) {
        const index=Number(item.name.replace(/^Public /,''));
        assert(Number.isInteger(index)&&index>=0&&index<10000&&!seen.has(index));seen.add(index);
        assert.equal(item.name,'Public '+index);
        assert.equal(item.login.username,'public-user-'+index);
        assert.equal(item.login.password,'PUBLIC-current-'+index);
        assert.deepEqual(Array.from(item.login.uris,uri=>uri.uri),['https://example.invalid/'+index]);
        assert(item.notes==='Public note '+index||item.fields?.some(field=>field.value==='Public note '+index&&field.type===1));
      }
    }
    const verifyMs=performance.now()-verifying;
    for(const elapsed of [reviewMs,generateMs,saveMs,verifyMs])assert(Number.isFinite(elapsed)&&elapsed>0);
    outputs.push({kind,bytes:bytes.length,records:10000,independentReader:true,reviewObservedMs:reviewMs,generateObservedMs:generateMs,saveObservedMs:saveMs,verifyMs});await close();
  }
  await configure(0);await click('export-review');await capture('10000-cancel-review');await close();
  await review(0);await click('export-generate');await until(s=>s.hits['export-save']);
  await evaluate(`window.exportOriginalClick=HTMLAnchorElement.prototype.click;HTMLAnchorElement.prototype.click=function(){throw Error('public load save failure');};true`);
  await click('export-save');await until(s=>s.hits['export-restart']);await capture('10000-save-error');
  await evaluate('HTMLAnchorElement.prototype.click=window.exportOriginalClick;true');await close();
  await review(0);await click('export-generate');await until(s=>s.hits['export-save']);await close();
  await review(0);await click('export-generate');await until(s=>s.hits['export-save']);
  for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:type==='keyDown'?10:0});
  await until(s=>s.screen==='unlock'&&!s.busy);assert(!(await snapshot()).bounds['export-window']);await capture('10000-locked');
  assert(!(await readdir(directory)).includes('bitwarden-personal.json'),'canceled or failed export published');
  const heartbeat=await evaluate('clearInterval(exportLoadTimer);exportLoadBeats');assert(heartbeat>100);
  return {width,locale,outputs,heartbeat,reviewCancel:true,saveFailure:true,readyCancel:true,lockCleared:true};
}
