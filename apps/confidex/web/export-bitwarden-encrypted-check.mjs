import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {assets} from './assets.mjs';
import {runBrowser} from '../../../tools/browser-run.mjs';
const [chrome,bundle,directory]=process.argv.slice(2);
assert(chrome&&bundle&&directory,'Usage: export-bitwarden-encrypted-check.mjs CHROME BUNDLE PUBLIC_OUTPUT_DIRECTORY');
const files=await assets(bundle);
files['/encrypted-export-worker.js']=Buffer.from(`
import init,{check_export,sample_bitwarden_encrypted_export} from '/app.js';
const originalFetch=self.fetch.bind(self);
self.fetch=(input,...args)=>{
  if(new URL(input.url??input,self.location.href).origin!==self.location.origin)throw Error('External fetch during export');
  return originalFetch(input,...args);
};
self.onmessage=async()=>{try{
  const wasm=await init();await check_export('bitwarden-encrypted');await check_export('bitwarden-encrypted-store');
  const outputs=[sample_bitwarden_encrypted_export(0),sample_bitwarden_encrypted_export(1)];
  const original=self.crypto.getRandomValues;const failures=[];
  for(const allowed of [0,1,2,3]) {
    let calls=0,refused=false;
    try {
      self.crypto.getRandomValues=function(bytes){if(++calls>allowed)throw Error('Injected entropy failure');return original.call(this,bytes);};
      try {sample_bitwarden_encrypted_export(0);}catch(error){refused=String(error)==='Writer';}
    }finally{self.crypto.getRandomValues=original;}
    if(!refused||calls!==allowed+1)throw Error('Entropy failure did not fail closed');failures.push({allowed,calls});
  }
  if(sample_bitwarden_encrypted_export(0).length<100)throw Error('Retry after failure failed');
  self.postMessage({outputs,failures,linear:wasm.memory.buffer.byteLength});
}catch(error){self.postMessage({error:String(error)});}};
`);
const result=await runBrowser(chrome,files,`new Promise((resolve,reject)=>{
  const worker=new Worker('/encrypted-export-worker.js',{type:'module'});let heartbeat=0;
  const timer=setInterval(()=>heartbeat++,10);worker.onerror=reject;
  worker.onmessage=({data})=>{clearInterval(timer);worker.terminate();resolve({...data,outputs:data.outputs?.map(b=>Array.from(b)),heartbeat});};worker.postMessage(null);
})`);
assert(!result.error,JSON.stringify(result));assert.equal(result.outputs.length,2);assert.equal(result.failures.length,4);
assert(result.heartbeat>0&&result.linear<=256*1024*1024);
await mkdir(directory,{recursive:true});
const profiles=['personal','organization'];
for(const [i,bytes] of result.outputs.entries())await writeFile(join(directory,profiles[i]+'.json'),Buffer.from(bytes));
console.log(JSON.stringify({directory,files:result.outputs.map((b,i)=>({profile:profiles[i],bytes:b.length})),failures:result.failures,linear:result.linear,heartbeat:result.heartbeat}));
