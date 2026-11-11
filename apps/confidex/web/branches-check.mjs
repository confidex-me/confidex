import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';

const [playwright, chrome] = process.argv.slice(2);
if (!playwright) throw Error('usage: branches-check.mjs /path/to/playwright [chrome]');
const {chromium} = await import(pathToFileURL(playwright).href);
const source = await readFile(new URL('./storage.js', import.meta.url));
const server = createServer((req, res) => {
  const script = req.url.startsWith('/storage.js');
  res.setHeader('Content-Type', script ? 'text/javascript' : 'text/html');
  res.end(script ? source : '<title>Public branch fixtures</title>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const browser = await chromium.launch({headless:true, ...(chrome ? {executablePath:chrome} : {})});
try {
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const result = await page.evaluate(async () => {
    const check = (ok, message) => { if (!ok) throw Error(message); };
    const hex = values => Array.from(values, b => b.toString(16).padStart(2,'0')).join('');
    const vault = '01'.repeat(16), record = Array(16).fill(2), recordKey = hex(record);
    const head = n => { const revision = Array(32).fill(0); revision[0]=n>>8; revision[1]=n%256; return {record,revision}; };
    const object = n => ({head:head(n),wire:new Uint8Array([n>>8,n%256]),tags:n%2 ? ['branch'] : ['branch','even']});
    const request = value => new Promise((resolve,reject) => { value.onsuccess=()=>resolve(value.result); value.onerror=()=>reject(value.error); });
    const done = tx => new Promise((resolve,reject) => { tx.oncomplete=resolve; tx.onabort=()=>reject(tx.error); });
    const open = indexedDB.open('confidex',4);
    open.onupgradeneeded = () => {
      const db=open.result;
      db.createObjectStore('vaults',{keyPath:'id'});
      db.createObjectStore('heads',{keyPath:['vault','record']});
      db.createObjectStore('objects',{keyPath:['vault','revision']});
      db.createObjectStore('sync-state');
      db.createObjectStore('record-tags',{keyPath:['vault','revision','tag']}).createIndex('lookup',['vault','tag','record','revision']);
    };
    const legacy=await request(open);
    const tx=legacy.transaction(Array.from(legacy.objectStoreNames),'readwrite'), complete=done(tx);
    tx.objectStore('vaults').add({id:vault,info:{id:Array(16).fill(1),name:'Public branch fixture'},lock:[1]});
    tx.objectStore('heads').add({vault,record:recordKey,revision:hex(head(0).revision)});
    tx.objectStore('objects').add({vault,record:recordKey,revision:hex(head(0).revision),wire:object(0).wire});
    const otherVault='03'.repeat(16);
    tx.objectStore('vaults').add({id:otherVault,info:{id:Array(16).fill(3),name:'Public migration sibling'},lock:[2]});
    tx.objectStore('heads').add({vault:otherVault,record:recordKey,revision:hex(head(0).revision)});
    tx.objectStore('objects').add({vault:otherVault,record:recordKey,revision:hex(head(0).revision),wire:object(0).wire});
    for(const tag of object(0).tags) tx.objectStore('record-tags').add({vault,record:recordKey,revision:hex(head(0).revision),tag});
    tx.objectStore('sync-state').put(new Uint8Array([7]),vault);
    await complete; legacy.close();
    const {dbCall}=await import('/storage.js');
    const fails = async (operation,args,expected) => {
      let error; try { await dbCall(operation,args); } catch(value) { error=value; }
      check(error===expected,`${operation}: expected ${expected}, got ${String(error)}`);
    };
    const add=IDBObjectStore.prototype.add;
    let copied=0;
    IDBObjectStore.prototype.add=function(...args) {
      if(this.name==='branch-heads' && ++copied===2) throw new DOMException('Public migration fixture','QuotaExceededError');
      return add.apply(this,args);
    };
    try { await fails('vaults',[],'Storage'); } finally { IDBObjectStore.prototype.add=add; }
    const unchanged=await request(indexedDB.open('confidex',4));
    check(unchanged.version===4,'failed migration changed version');
    check(unchanged.transaction('heads').objectStore('heads').keyPath.length===2,'failed migration changed head schema');
    check((await request(unchanged.transaction('heads').objectStore('heads').getAll())).length===2,'failed migration lost heads');
    unchanged.close();
    check((await dbCall('vaults',[])).length===2,'retry after failed migration did not open');
    check((await dbCall('branch-heads',[otherVault,null,null])).length===1,'migration changed another vault');
    const migrated=await request(indexedDB.open('confidex',5));
    check(migrated.transaction('heads').objectStore('heads').keyPath.length===3,'head key did not include revision'); migrated.close();
    check((await dbCall('object',[vault,hex(head(0).revision)])).join(',')==='0,0','migration changed wire');
    let checkpoint=new Uint8Array([7]);
    for(let start=1;start<270;start+=90) {
      const objects=Array.from({length:Math.min(90,270-start)},(_,i)=>object(start+i));
      const current=new Uint8Array([start%256]);
      await dbCall('publish-branches',[vault,{previous:checkpoint,current,objects,heads:objects.map(o=>({head:o.head,expected:null}))}]); checkpoint=current;
    }
    const all=async(tag=null) => {
      const rows=[]; let after=null;
      for(;;) {
        const page=await dbCall('branch-heads',[vault,after,tag]);
        if(!page.length) return rows;
        rows.push(...page); after=page.at(-1);
      }
    };
    check((await all()).length===270,'branch pagination dropped tips');
    check((await all('even')).length===135,'tag pagination dropped tips');
    await fails('heads',[vault,null],'Conflict');
    await fails('head',[vault,recordKey],'Conflict');
    const peer=await import('/storage.js?peer');
    const commits=[900,901].map(n=>({previous:checkpoint,current:new Uint8Array([n%256]),objects:[object(n)],heads:[{head:head(n),expected:head(0).revision}]}));
    const results=await Promise.allSettled([dbCall('publish-branches',[vault,commits[0]]),peer.dbCall('publish-branches',[vault,commits[1]])]);
    check(results.filter(r=>r.status==='fulfilled').length===1,'concurrent writers did not have one winner');
    const loser=results[0].status==='rejected'?0:1, winner=1-loser;
    check(results[loser].reason==='Conflict','wrong concurrent writer error');
    await fails('object',[vault,hex(head(900+loser).revision)],'NotFound');
    checkpoint=commits[winner].current;
    const merged=object(902);
    await dbCall('publish-branches',[vault,{previous:checkpoint,current:new Uint8Array([6]),objects:[merged],heads:[1,2].map(n=>({head:merged.head,expected:head(n).revision}))}]);
    checkpoint=new Uint8Array([6]);
    check((await all()).length===269,'multi-parent revision changed unrelated tips');
    const quota={previous:checkpoint,current:new Uint8Array([8]),objects:[object(903),object(904)],heads:[903,904].map(n=>({head:head(n),expected:null}))};
    let inserts=0;
    IDBObjectStore.prototype.add=function(...args) {
      if(this.name==='objects' && ++inserts===2) throw new DOMException('Public quota fixture','QuotaExceededError');
      return add.apply(this,args);
    };
    try { await fails('publish-branches',[vault,quota],'Quota'); } finally { IDBObjectStore.prototype.add=add; }
    check((await all()).length===269,'quota failure left partial tips');
    for(const n of [903,904]) await fails('object',[vault,hex(head(n).revision)],'NotFound');
    check((await dbCall('sync-state',[vault])).join(',')==='6','quota failure changed checkpoint');
    const duplicate={...quota,heads:[quota.heads[0],quota.heads[0]]};
    await fails('publish-branches',[vault,duplicate],'Invalid');
    await fails('object',[vault,hex(head(903).revision)],'NotFound');
    const consumed={...quota,heads:[903,904].map(n=>({head:head(n),expected:head(3).revision}))};
    await fails('publish-branches',[vault,consumed],'Invalid');
    const scope={...quota,objects:[{...object(903),head:{record:Array(16).fill(3),revision:head(903).revision}}],heads:[quota.heads[0]]};
    await fails('publish-branches',[vault,scope],'NotFound');
    await fails('object',[vault,hex(head(903).revision)],'NotFound');
    const malformed={...quota,objects:[{...object(903),head:{record:[],revision:head(903).revision}}],heads:[]};
    await fails('publish-branches',[vault,malformed],'Invalid');
    const bad={...quota,objects:[{...object(903),wire:new Uint8Array([9])}],heads:[{head:head(903),expected:head(0).revision}]};
    await fails('publish-branches',[vault,bad],'Conflict');
    check((await all()).length===269,'stale selected tip changed branches');
    await dbCall('publish-branches',[vault,{previous:checkpoint,current:new Uint8Array([10]),objects:[object(905)],heads:[]}]);
    check((await all()).length===269,'staging an object published a tip');
    const snapshot=await dbCall('snapshot',[vault]);
    check(snapshot.heads.length===269 && snapshot.objects.length===273,'snapshot dropped branch history');
    await dbCall('remove',[vault]); await dbCall('restore',[snapshot]);
    check((await all()).length===269,'restore dropped branch tips');
    for(const item of snapshot.objects) {
      const wire=await dbCall('object',[vault,hex(item.head.revision)]);
      check(wire.join(',')===item.wire.join(','),'restore changed wire');
    }
    const batch={previous:await all(),objects:[object(906),object(907)],heads:[906,907].map((n,i)=>({head:head(n),expected:head(i+3).revision}))};
    inserts=0;
    IDBObjectStore.prototype.add=function(...args) {
      if(this.name==='objects' && ++inserts===2) throw new DOMException('Public batch quota fixture','QuotaExceededError');
      return add.apply(this,args);
    };
    try { await fails('record-batch',[vault,batch],'Quota'); } finally { IDBObjectStore.prototype.add=add; }
    check((await all()).length===269,'batch quota failure changed branch tips');
    for(const n of [906,907]) await fails('object',[vault,hex(head(n).revision)],'NotFound');
    await dbCall('record-batch',[vault,batch]);
    const updated=await all();
    check(updated.length===269 && updated.some(h=>hex(h.revision)===hex(head(906).revision)) && updated.some(h=>hex(h.revision)===hex(head(907).revision)),'batch lost selected branch updates');
    check(!updated.some(h=>[3,4].some(n=>hex(h.revision)===hex(head(n).revision))),'batch retained consumed tips');
    await fails('record-batch',[vault,batch],'Conflict');
    check((await dbCall('snapshot',[vault])).objects.length===275,'batch lost historical objects');
    return {tips:269,objects:275,migrationRollback:true,concurrentWriters:true,quotaRollback:true,restore:true,branchBatch:true};
  });
  await page.reload();
  const reopened=await page.evaluate(async()=>{
    const {dbCall}=await import('/storage.js'); const vault='01'.repeat(16);
    const snapshot=await dbCall('snapshot',[vault]);
    await dbCall('clear-records',[vault]);
    if((await dbCall('branch-heads',[vault,null,null])).length) throw Error('clear left branch tips');
    if((await dbCall('branch-heads',['03'.repeat(16),null,null])).length!==1) throw Error('clear changed another vault');
    let error; try { await dbCall('publish-branches',[vault,{previous:null,current:[],objects:[],heads:[]}]); } catch(value) { error=value; }
    if(error!=='Removing') throw Error('removed vault accepted branch publication');
    return snapshot.heads.length;
  });
  assert.equal(reopened,269);
  console.log(JSON.stringify({...result,reopened,cleared:true}));
} finally {
  await browser.close();
  await new Promise(resolve=>server.close(resolve));
}
