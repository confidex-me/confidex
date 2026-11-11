import assert from 'node:assert/strict';
import {mkdir, writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {assets} from './assets.mjs';
import {runBrowser} from '../../../tools/browser-run.mjs';

const [chrome, bundle, destination, registry] = process.argv.slice(2);
assert(!registry || registry === '--registry');
assert(chrome && bundle && destination, 'usage: export-kdbx-check.mjs CHROME BUNDLE PUBLIC_OUTPUT_DIRECTORY');
const files = await assets(bundle);
files['/kdbx-worker.js'] = Buffer.from(`
import init,{sample_kdbx_export,check_export} from '/app.js';
const originalFetch=self.fetch.bind(self);
self.fetch=(input,...args)=>{
  if(new URL(input.url??input,self.location.href).origin!==self.location.origin)throw Error('External fetch during export');
  return originalFetch(input,...args);
};
self.onmessage=async()=>{try{
  const wasm=await init();const outputs=[];
  if(${Boolean(registry)})await check_export('kdbx-registry');
  for(let mode=0;mode<5;mode++)outputs.push(sample_kdbx_export(mode));
  const originalRandom=self.crypto.getRandomValues;
  const entropyFailures=[];
  for(const allowed of [0,1]){
    let calls=0,refused=false;
    try{
      self.crypto.getRandomValues=function(bytes){if(++calls>allowed)throw Error('Injected entropy failure');return originalRandom.call(this,bytes);};
      try{sample_kdbx_export(0);}catch(error){refused=String(error)==='Writer';}
    }finally{self.crypto.getRandomValues=originalRandom;}
    if(!refused||calls!==allowed+1)throw Error('Entropy failure did not fail closed');
    entropyFailures.push({allowed,calls});
  }
  if(sample_kdbx_export(0).length<100)throw Error('Retry after entropy failure failed');
  self.postMessage({outputs,entropyFailures,linear:wasm.memory.buffer.byteLength});
}catch(error){self.postMessage({error:String(error)});}};
`);
const result = await runBrowser(chrome,files,`new Promise((resolve,reject)=>{
  const worker=new Worker('/kdbx-worker.js',{type:'module'});let heartbeat=0;
  const timer=setInterval(()=>heartbeat++,10);
  worker.onerror=reject;
  worker.onmessage=({data})=>{clearInterval(timer);worker.terminate();resolve({...data,heartbeat,outputs:data.outputs?.map(bytes=>Array.from(bytes))});};
  worker.postMessage(null);
})`);
assert(!result.error,JSON.stringify(result));
assert.equal(result.outputs.length,5);
assert.equal(result.entropyFailures.length,2);
assert(result.heartbeat>0 && result.linear<=256*1024*1024);
await mkdir(destination,{recursive:true});
const names=['password','keyfile','both','empty-password','empty-both'];
for(const [index,bytes] of result.outputs.entries()) {
  await writeFile(join(destination,`${names[index]}.kdbx`),Buffer.from(bytes));
}
await writeFile(join(destination,'public.key'),Buffer.alloc(32,7));
console.log(JSON.stringify({directory:destination,files:result.outputs.map((b,i)=>({name:names[i],bytes:b.length})),entropyFailures:result.entropyFailures,linear:result.linear,heartbeat:result.heartbeat}));
