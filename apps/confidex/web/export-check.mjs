import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import {assets} from './assets.mjs';
import {runBrowser} from '../../../tools/browser-run.mjs';

const [chrome, bundle, kind = 'synthetic'] = process.argv.slice(2);
assert(chrome && bundle, 'usage: export-check.mjs CHROME EXPORT_CHECK_WASM_BUNDLE');
assert(['synthetic', 'production', 'load', 'faults'].includes(kind));
const longRun = kind === 'load' || kind === 'faults';
const files = await assets(bundle);
files['/export-check-worker.js'] = Buffer.from(`
import init, {check_export,seed_export_check,profile_export_load,profile_export_faults} from '/app.js';
const originalFetch=self.fetch.bind(self);
self.fetch=(input,...args)=>{
  if(new URL(input.url??input,self.location.href).origin!==self.location.origin)throw Error('External fetch during export');
  return originalFetch(input,...args);
};
const wasm=await init();
self.onmessage=async({data:mode})=>{
  if(mode==='seed'){try{self.postMessage({seed:JSON.parse(await seed_export_check())});}catch{self.postMessage({error:true,mode});}return;}
  if(mode==='load'){try{const report=JSON.parse(await profile_export_load());self.postMessage({done:mode,report,linearBytes:wasm.memory.buffer.byteLength});}catch(error){self.postMessage({error:String(error),mode});}return;}
  if(mode==='faults'){try{await check_export('storage-failure');const report=JSON.parse(await profile_export_faults());self.postMessage({done:mode,report,linearBytes:wasm.memory.buffer.byteLength});}catch(error){self.postMessage({error:String(error),mode});}return;}
  try {await check_export(mode);self.postMessage({done:mode,linearBytes:wasm.memory.buffer.byteLength});}
  catch(error) {self.postMessage({error:String(error),mode});}
};
self.postMessage({ready:true});
`);
const results = await runBrowser(chrome, files, async ({evaluate}) => {
  const results = [];
  const modes = ['locales', 'bitwarden', 'bitwarden-encrypted', 'bitwarden-encrypted-store', 'bitwarden-zip', 'csv', 'csv-setup', 'onepassword', 'keepass', 'kdbx', 'current', 'field-sources', 'field-sources-service', 'consent', 'invalidation', 'changed', 'cancel', 'tombstones'];
  modes.push('storage-failure');
  modes.push(...(kind === 'production' ? ['bitwarden-flow', 'kdbx-registry', 'plain-formats', 'csv-factory'] : ['protocol', 'service']));
  for (const mode of longRun ? [kind] : modes) {
    const expression = `new Promise((resolve,reject)=>{
      const worker=new Worker('/export-check-worker.js',{type:'module'});
      let heartbeat=0;
      const timer=setInterval(()=>heartbeat++,10);
      const timeout=setTimeout(()=>finish(Error('Export check timed out')),${longRun ? 300000 : 110000});
      function finish(error,result){clearTimeout(timeout);clearInterval(timer);worker.terminate();error?reject(error):resolve({...result,heartbeat});}
      worker.onerror=()=>finish(Error('Export worker failed'));
      worker.onmessage=({data})=>{
        if(data.ready)worker.postMessage(${JSON.stringify(mode)});
        else if(data.error)finish(Error('Export assertion failed: '+data.mode+': '+data.error));
        else if(data.done)finish(null,data);
      };
    })`;
    let result;
    if (longRun) {
      await evaluate(`window.exportLoadResult={};(${expression}).then(value=>window.exportLoadResult={value},error=>window.exportLoadResult={error:String(error)});true`);
      for (;;) {
        const state = await evaluate('window.exportLoadResult');
        assert(!state.error, state.error);
        if (state.value) { result = state.value; break; }
        await delay(1000);
      }
    } else result = await evaluate(expression);
    assert.equal(result.done, mode);
    if (mode === 'faults') {
      const report = result.report;
      assert.equal(report.records, 10000);
      assert.equal(report.objects_checked, 10002);
      assert.equal(report.entropy_injected, true);
      assert.equal(report.runs.length, 7);
      assert.equal(new Set(report.runs.map(run => run.format)).size, 7);
      for (const run of report.runs) {
        const expected = ['cancel-mid-read', 'cancel-during-write', 'cancel-after-write', 'storage-mid-read', 'storage-before-write', 'storage-after-write', 'entropy-review-token', 'entropy-ready-token', 'cancel-ready', 'lock-ready'];
        if (['kdbx', 'bitwarden-encrypted-json'].includes(run.format)) expected.push('entropy-crypto-writer');
        assert.deepEqual([...run.cases].sort(), expected.sort());
        assert(run.recovered_bytes > 262144);
      }
    }
    assert(result.heartbeat > 0, 'Main thread did not run while export worker was busy');
    assert(result.linearBytes <= 256 * 1024 * 1024, 'Export exceeded the WASM memory profile');
    results.push(result);
  }
  if (kind !== 'synthetic') return results;
  const queued = await evaluate(`(async()=>{
    const seed=await new Promise((resolve,reject)=>{
      const worker=new Worker('/export-check-worker.js',{type:'module'});
      worker.onerror=()=>{worker.terminate();reject(Error('seed failed'));};
      worker.onmessage=({data})=>{if(data.ready)worker.postMessage('seed');else if(data.seed){worker.terminate();resolve(data.seed);}else if(data.error){worker.terminate();reject(Error('seed failed'));}};
    });
    const worker=new Worker('/worker.js',{type:'module'});
    const encode=new TextEncoder(),decode=new TextDecoder();
    let pending,readyResolve,cancelOp=0,progress=0;
    const ready=new Promise(resolve=>readyResolve=resolve);
    worker.onmessage=({data})=>{
      if(data==='ready'){readyResolve();return;}
      if(data.length===0){pending?.resolve({empty:true});pending=null;return;}
      try {
        let json,body;
        if(data[0]===123){try{json=JSON.parse(decode.decode(data));body=new Uint8Array();}catch{}}
        if(!json){const size=new DataView(data.buffer,data.byteOffset,data.byteLength).getUint32(0,true);json=JSON.parse(decode.decode(data.subarray(4,4+size)));body=data.subarray(4+size);}
        if(json.__attachment_bytes!==body.length)throw Error('frame length');
        const event=json.result?.Ok?.VendorExport?.Ok?.Progress;
        if(event){progress++;if(event.operation===cancelOp){worker.postMessage({cancelExport:cancelOp});cancelOp=0;}return;}
        pending?.resolve({json,body});pending=null;
      }catch(error){pending?.reject(error);pending=null;}
    };
    worker.onerror=()=>{pending?.reject(Error('production worker failed'));pending=null;};
    async function call(command,body=new Uint8Array()){
      const meta=encode.encode(JSON.stringify({generation:93,command,__attachment_bytes:body.length}));
      let packet=meta;
      if(body.length){packet=new Uint8Array(4+meta.length+body.length);new DataView(packet.buffer).setUint32(0,meta.length,true);packet.set(meta,4);packet.set(body,4+meta.length);}
      return request(packet);
    }
    function request(data){
      if(pending)throw Error('overlapping test request');
      return new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>{pending=null;reject(Error('production export timed out'));},30000);
        pending={resolve:value=>{clearTimeout(timer);resolve(value);},reject:error=>{clearTimeout(timer);reject(error);}};
        worker.postMessage(data,data instanceof Uint8Array?[data.buffer]:[]);
      });
    }
    const value=reply=>reply.json?.result?.Ok?.VendorExport;
    try{
      await ready;
      if(!(await request({unexpected:true})).empty)throw Error('invalid control was accepted');
      const unlock=await call({Unlock:{vault:seed.info.id,password:'public-export-contract-password',key:seed.key,remember:false}});
      if(!unlock.json.result.Ok.Opened)throw Error('unlock');
      if(value(await call({VendorExport:'Begin'})).Ok.Begun.formats.length!==3)throw Error('catalog');
      const prepare=operation=>call({VendorExport:{Prepare:{operation,created_at:1735689600,format:'keepass-xml',options:'Plain',selection:'All'}}});
      const review=value(await prepare(81)).Ok.Reviewed.review;
      cancelOp=82;
      const canceled=value(await call({VendorExport:{Generate:{operation:82,token:review.token,consent:'Lossless'}}}));
      if(canceled.Err?.Export!=='Canceled')throw Error('live cancel did not stop artifact release');
      const fresh=value(await prepare(83)).Ok.Reviewed.review;
      worker.postMessage({cancelImport:84});
      const output=value(await call({VendorExport:{Generate:{operation:84,token:fresh.token,consent:'Lossless'}}})).Ok.Ready.ready;
      let offset=0,chunks=0,total=0;
      do{
        const reply=await call({VendorExport:{Chunk:{token:output.token,offset}}});
        const chunk=value(reply).Ok.Chunk.chunk;
        if(chunk.offset!==offset||chunk.bytes.length!==0||reply.body.length>262144)throw Error('chunk framing');
        total+=reply.body.length;chunks++;offset=chunk.next;
      }while(offset!==null);
      if(total!==output.bytes||chunks<2)throw Error('file collection');
      await call('Lock');
      if(value(await call({VendorExport:{Chunk:{token:output.token,offset:0}}})).Err!=='InvalidSession')throw Error('stale artifact survived lock');
      return {done:'worker-queue',chunks,total,progress,liveCancel:true,cancelChannelsIndependent:true};
    }finally{worker.terminate();}
  })()`);
  assert.equal(queued.done, 'worker-queue');
  results.push(queued);
  return results;
});
console.log(JSON.stringify(results));
