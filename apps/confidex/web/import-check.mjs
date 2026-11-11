import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {pathToFileURL} from 'node:url';
import {assets} from './assets.mjs';

const [playwright, chrome, bundle] = process.argv.slice(2);
assert(playwright && chrome && bundle, 'usage: import-check.mjs PLAYWRIGHT CHROME IMPORT_CHECK_WASM_BUNDLE');
const {chromium} = await import(pathToFileURL(playwright).href);
const files = await assets(bundle);
files['/'] = Buffer.from('<title>Public WASM import checks</title>');
files['/import-worker.js'] = Buffer.from(`
import init, {check_import} from '/app.js';
await init();
self.importCheckCanceled=false;
self.onmessage=({data})=>{if(data==='cancel')self.importCheckCanceled=true;};
const mode=new URL(self.location.href).searchParams.get('mode');
if(mode==='atomic') {
  const add=IDBObjectStore.prototype.add;let inserts=0;
  IDBObjectStore.prototype.add=function(...args){
    if(this.name==='objects'&&++inserts===2)throw new DOMException('Public quota fixture','QuotaExceededError');
    return add.apply(this,args);
  };
}
try {self.postMessage({done:JSON.parse(await check_import(mode))});}
catch {self.postMessage({error:true});}
`);
const server = createServer((req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  const file = files[path];
  res.statusCode = file ? 200 : 404;
  res.setHeader('Content-Type', path.endsWith('.wasm') ? 'application/wasm' : path.endsWith('.js') ? 'text/javascript' : 'text/html');
  res.end(file ?? 'missing');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const browser = await chromium.launch({headless:true,executablePath:chrome});
try {
  const page = await browser.newPage();
  const origin = `http://127.0.0.1:${server.address().port}`;
  const external=[];
  page.on('request', request => {if(!request.url().startsWith(origin))external.push(request.url());});
  await page.goto(`${origin}/`);
  const results={};
  for(const mode of ['atomic','cancel']) {
    results[mode]=await page.evaluate(mode=>new Promise((resolve,reject)=>{
      const worker=new Worker(`/import-worker.js?mode=${mode}`,{type:'module'});
      let heartbeat=0,sealProgress=0;
      const timer=setInterval(()=>heartbeat++,10);
      const timeout=setTimeout(()=>finish(Error('WASM import check timed out')),120000);
      function finish(error,result){clearInterval(timer);clearTimeout(timeout);worker.terminate();error?reject(error):resolve({...result,heartbeat,sealProgress});}
      worker.onerror=()=>finish(Error('WASM import worker failed'));
      worker.onmessage=({data})=>{
        if(data.error)finish(Error('WASM import assertion failed'));
        else if(data.done)finish(null,data.done);
        else if(data.phase===2){sealProgress++;if(mode==='cancel'&&data.current>=1)worker.postMessage('cancel');}
      };
    }),mode);
    assert(results[mode].heartbeat>0,'main thread did not run while import worker was busy');
  }
  assert.deepEqual({...results.atomic,heartbeat:0,sealProgress:0},{imported:2,objects:3,quotaRollback:true,catalogConflict:true,secretExcluded:true,repeatSkipped:true,reopened:true,heartbeat:0,sealProgress:0});
  assert(results.cancel.canceled && results.cancel.objects===0 && results.cancel.sealProgress>=2);
  assert.equal(external.length,0,'import fetched an external resource');
  console.log(JSON.stringify(results));
} finally {
  await browser.close();
  await new Promise(resolve=>server.close(resolve));
}
