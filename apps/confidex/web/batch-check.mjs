import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';

const [playwright, chrome] = process.argv.slice(2);
if (!playwright) throw Error('usage: batch-check.mjs /path/to/playwright [chrome]');
const {chromium} = await import(pathToFileURL(playwright).href);
const source = await readFile(new URL('./storage.js', import.meta.url));
const server = createServer((req, res) => {
  res.setHeader('Content-Type', req.url === '/storage.js' ? 'text/javascript' : 'text/html');
  res.end(req.url === '/storage.js' ? source : '<title>Public batch fixtures</title>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const browser = await chromium.launch({headless:true, ...(chrome ? {executablePath:chrome} : {})});
try {
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const result = await page.evaluate(async () => {
    const {dbCall} = await import('/storage.js');
    const check = (ok, message) => { if (!ok) throw Error(message); };
    const hex = values => Array.from(values, b => b.toString(16).padStart(2,'0')).join('');
    const vault = '01'.repeat(16);
    const head = (id, version=1) => {
      const record = new Uint8Array(16), revision = new Uint8Array(32);
      new DataView(record.buffer).setUint32(0,id,false); revision.set(record); revision[31] = version;
      return {record:Array.from(record),revision:Array.from(revision)};
    };
    const batch = (previous, ids, version=1) => ({previous,
      objects:ids.map(id => ({head:head(id,version),wire:new Uint8Array(32).fill(id%256),tags:['fixture']})),
      heads:ids.map(id => ({head:head(id,version),expected:previous.find(h => hex(h.record)===hex(head(id).record))?.revision ?? null})),
    });
    const all = async () => {
      const output=[]; let after=null;
      for (;;) {
        const rows = await dbCall('heads',[vault,after]);
        if (!rows.length) return output;
        output.push(...rows); after=hex(rows.at(-1).record);
      }
    };
    const fails = async (op, args, expected) => {
      let error;
      try { await dbCall(op,args); } catch (value) { error=value; }
      check(error===expected, `${op}: expected ${expected}, got ${String(error)}`);
    };
    await dbCall('create',[{info:{id:Array(16).fill(1),name:'Public batch fixture'},lock:[1]}]);
    await dbCall('record-batch',[vault,batch([],[1])]);
    await dbCall('sync-commit',[vault,{previous:null,current:new Uint8Array([7]),objects:[],heads:[]}]);
    const commit = batch(await all(),[2,3]);
    const add = IDBObjectStore.prototype.add;
    let inserts=0;
    IDBObjectStore.prototype.add = function(...args) {
      if (this.name==='objects' && ++inserts===2) throw new DOMException('Public quota fixture','QuotaExceededError');
      return add.apply(this,args);
    };
    try { await fails('record-batch',[vault,commit],'Quota'); }
    finally { IDBObjectStore.prototype.add=add; }
    check((await all()).length===1,'quota failure published partial heads');
    for (const object of commit.objects) await fails('object',[vault,hex(object.head.revision)],'NotFound');
    await dbCall('record-batch',[vault,commit]);
    check((await all()).length===3,'batch did not publish every head');
    await fails('record-batch',[vault,commit],'Conflict');
    const stale=batch(await all(),[4]);
    await dbCall('append',[vault,hex(head(9).record),hex(head(9).revision),null,new Uint8Array([9]),[]]);
    await fails('record-batch',[vault,stale],'Conflict');
    check((await dbCall('head',[vault,hex(head(4).record)]))===null,'concurrent insertion left a partial import');
    await dbCall('record-batch',[vault,batch(await all(),[1],2)]);
    const old = await dbCall('object',[vault,hex(head(1).revision)]);
    check(old.length===32 && old[0]===1,'old revision was changed');
    const collision=batch(await all(),[8]);
    collision.objects[0].head.revision=head(1).revision;
    collision.heads[0].head.revision=head(1).revision;
    await fails('record-batch',[vault,collision],'Conflict');
    check(await dbCall('head',[vault,hex(head(8).record)])===null,'revision collision changed heads');
    const invalid=batch(await all(),[5]); invalid.objects[0].tags=['same','same'];
    await fails('record-batch',[vault,invalid],'Limit');
    const unicode=batch(await all(),[5]); unicode.objects[0].tags=['\ue000','\u{10000}'];
    await dbCall('record-batch',[vault,unicode]);
    const reversed=batch(await all(),[6]); reversed.objects[0].tags=['\u{10000}','\ue000'];
    await fails('record-batch',[vault,reversed],'Limit');
    const duplicate=batch(await all(),[6,6]);
    await fails('record-batch',[vault,duplicate],'Invalid');
    const oversized=batch(await all(),[5]); oversized.objects[0].wire=new Uint8Array(4065669);
    await fails('record-batch',[vault,oversized],'Limit');
    const previous=await all();
    const tenThousand=batch(previous,Array.from({length:10000},(_,i)=>i+1000));
    const started=performance.now();
    await dbCall('record-batch',[vault,tenThousand]);
    const elapsed=performance.now()-started;
    const current=await all();
    check(current.length===previous.length+10000,'10k commit was truncated');
    const last=await dbCall('object',[vault,hex(head(10999).revision)]);
    check(last.length===32 && last[0]===10999%256,'10k object bytes changed');
    check((await dbCall('tagged-heads',[vault,'fixture',null])).length===128,'tag index was not committed');
    check(Array.from(await dbCall('sync-state',[vault])).join(',')==='7','batch changed synchronization checkpoint');
    await fails('record-batch',[vault,tenThousand],'Conflict');
    await dbCall('clear-records',[vault]);
    await fails('record-batch',[vault,batch([],[1])],'Removing');
    return {records:10000,atomic:true,quotaRollback:true,catalogConflict:true,historyPreserved:true,typedWire:true,elapsedMs:elapsed};
  });
  assert.equal(result.records,10000);
  console.log(JSON.stringify(result));
} finally {
  await browser.close();
  await new Promise(resolve => server.close(resolve));
}
