import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {assets} from './assets.mjs';
import {runBrowser} from '../../../tools/browser-run.mjs';

const names=['bitwarden-personal.json','confidex.kdbx','bitwarden-encrypted.json','bitwarden-personal.zip','confidex.xml','confidex.1pux','chromium.csv'];
const sources=['bitwarden-producer','bitwarden-personal','bitwarden-organization','onepassword','keepass','csv','bitwarden-zip','bitwarden-encrypted','kdbx-password','kdbx-keyfile','kdbx-both','kdbx-empty-password','kdbx-empty-password-keyfile','native'];
const password='PUBLIC-reverse-export-password';
const args=process.argv.slice(2);
let directory,worker;
if(args[0]==='--browser') {
  const [,chrome,bundle,destination]=args;
  assert(chrome&&bundle&&destination,'Usage: export-reverse-check.mjs --browser CHROME BUNDLE PUBLIC_DIRECTORY');
  directory=destination;
  const files=await assets(bundle);
  files['/reverse-worker.js']=Buffer.from(`
import init,{sample_export_reverse} from '/app.js';
const originalFetch=self.fetch.bind(self);
self.fetch=(input,...args)=>{
  if(new URL(input.url??input,self.location.href).origin!==self.location.origin)throw Error('External fetch during export');
  return originalFetch(input,...args);
};
self.onmessage=async()=>{try{
  const wasm=await init(),outputs=JSON.parse(await sample_export_reverse());
  self.postMessage({outputs,linear:wasm.memory.buffer.byteLength});
}catch(error){self.postMessage({error:String(error)});}};
`);
  const result=await runBrowser(chrome,files,`new Promise((resolve,reject)=>{
    const worker=new Worker('/reverse-worker.js',{type:'module'});let heartbeat=0;
    const timer=setInterval(()=>heartbeat++,10);
    const timeout=setTimeout(()=>finish(Error('Reverse export timed out')),110000);
    function finish(error,data){clearInterval(timer);clearTimeout(timeout);worker.terminate();error?reject(error):resolve({...data,heartbeat});}
    worker.onerror=()=>finish(Error('Reverse export worker failed'));
    worker.onmessage=({data})=>data.error?finish(Error(data.error)):finish(null,data);
    worker.postMessage(null);
  })`);
  const expected=sources.flatMap(source=>names.map(name=>source+'/'+name));
  assert.equal(result.outputs.length,expected.length);
  assert(result.heartbeat>0&&result.linear<=256*1024*1024);
  await mkdir(directory,{recursive:true});
  for(const [index,output] of result.outputs.entries()) {
    assert.equal(output.name,expected[index]);
    await mkdir(dirname(join(directory,output.name)),{recursive:true});
    await writeFile(join(directory,output.name),Buffer.from(output.bytes));
  }
  worker={linear:result.linear,heartbeat:result.heartbeat};
} else {
  assert(args.length===1,'Usage: export-reverse-check.mjs PUBLIC_DIRECTORY');
  [directory]=args;
}
const require=createRequire(import.meta.url);
const Importer=require('../../../crates/confidex-app/tests/export_fixtures/bitwarden_json/reader.cjs').loadImporter(process.env.CONFIDEX_BITWARDEN_SOURCE);
const OnePassword=require('../../../crates/confidex-app/tests/export_fixtures/onepassword_1pux/reader.cjs').loadImporter(process.env.CONFIDEX_BITWARDEN_SOURCE,process.env.CONFIDEX_ONEPASSWORD_READER_SOURCE);
const Csv=require('../../../crates/confidex-app/tests/export_fixtures/csv/reader.cjs').loadImporter(process.env.CONFIDEX_BITWARDEN_SOURCE,process.env.CONFIDEX_CSV_READER_SOURCE,'chromium');
const crypto=require('../../../crates/confidex-app/tests/import_fixtures/bitwarden_encrypted_json/capture.cjs').environment(process.env.CONFIDEX_BITWARDEN_CRYPTO_SOURCE,process.env.CONFIDEX_BITWARDEN_SDK);
const python=fileURLToPath(new URL('./export-reverse-reader.py',import.meta.url));
const kinds=['bitwarden','kdbx','bitwarden-encrypted','bitwarden-zip','keepass-xml','onepassword-1pux','csv'];
const results=[];
for(const source of sources) {
const protectedUrl=source==='keepass'||source.startsWith('kdbx-');
for(const [index,name] of names.entries()) {
  const filename=join(directory,source,name),bytes=await readFile(filename),kind=kinds[index];
  let clear=bytes.toString('utf8');
  if(index===1||index===4) {
    const result=JSON.parse(execFileSync('python3',[python,kind,filename,process.env.CONFIDEX_KEEPASSXC_CLI,source],{input:password,encoding:'utf8'}));
    assert.equal(result.records,1);assert.equal(result.attachment,'00ff0402');
  } else {
    if(index===2) {
      const document=JSON.parse(clear),config={toSdkConfig:()=>({argon2id:{iterations:3,memory:64,parallelism:4}})};
      const key=(await crypto.keys.deriveVaultExportKey(password,document.salt,config)).toEncoded();
      clear=crypto.sdk.PureCrypto.symmetric_decrypt_string(document.data,key);
    }
    if(index===3||index===5) {
      const result=JSON.parse(execFileSync('python3',[python,kind,filename],{encoding:'utf8'}));
      assert.equal(result.attachment,'00ff0402');clear=result.data;
      if(index===5)assert(JSON.parse(clear).accounts[0].vaults[0].items[0].details.sections.every(section=>section.title===''),'cleared sections restored source titles');
    }
    if(index===6)assert.equal(JSON.parse(execFileSync('python3',[python,kind,filename],{encoding:'utf8'})).rows,1);
    for(const removed of ['PUBLIC-FIXTURE-PASSWORD','PUBLIC-FIXTURE-ORG','PUBLIC-FIXTURE-OLD','PUBLIC-FIXTURE-HIDDEN','PUBLIC-FIXTURE-FUTURE','PUBLIC-FIXTURE-PIN','PUBLIC-FIXTURE-GUARDED','PUBLIC-FIXTURE-PLUGIN','alice@example.invalid','mail.example.invalid','https://second.example.invalid','PUBLIC-FIXTURE-CREDENTIAL','GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ','old public password','deleted public password','current public password'])assert(!clear.includes(removed),source+'/'+kind+': stale source replayed: '+removed);
    const importer=index===5?new OnePassword({getFeatureFlag:async()=>false}):index===6?new Csv():new Importer();
    const parsed=await importer.parse(clear);assert(parsed.success);assert.equal(parsed.errors.length,0);assert.equal(parsed.ciphers.length,1);
    const item=parsed.ciphers[0];
    assert.equal(item.name,'PUBLIC-current-title');
    assert.equal(item.login.username,'current-user@example.invalid');
    assert.equal(item.login.password,'PUBLIC-current-password\n第二行');
    const expected=index===6?['https://current.example.invalid/edited?q=1&v=2']:[...(protectedUrl&&index===5?[]:['https://current.example.invalid/edited?q=1&v=2']),...(index===5?[]:['https://added.example.invalid/'])];
    assert.deepEqual(Array.from(item.login.uris??[],uri=>uri.uri),expected,source+'/'+kind);
    if(protectedUrl&&index===5)assert(item.fields.some(field=>field.name==='URL'&&field.value==='https://current.example.invalid/edited?q=1&v=2'&&field.type===1),source+'/'+kind+': protected URL became public');
    if(index===5)assert(item.fields.some(field=>field.name==='Secondary URL'&&field.value==='https://added.example.invalid/'&&field.type===0),'1PUX section URL did not reach the independent reader');
    if(index===5)assert(item.notes.includes('PUBLIC-current-note\n\nLast line'));
    else assert.equal(item.notes,'PUBLIC-current-note\n\nLast line');
    if(index!==6) {
      let value=item.login.totp;
      if(index===5) {
        const field=item.fields.find(field=>field.name==='One-time code');
        assert(field&&field.type===0,'1PUX current TOTP did not reach the independent reader');
        value=field.value;
      }
      const otp=new URL(value);
      for(const [key,value] of Object.entries({secret:'MZXW6YTBOI',algorithm:'SHA512',digits:'8',period:'60'}))assert.equal(otp.searchParams.get(key),value);
    }
  }
  results.push({source,kind,bytes:bytes.length,currentValues:true,independentReader:true});
}
console.error('Checked public reverse source: '+source);
}
console.log(JSON.stringify({sources:sources.length,formats:results,worker}));
