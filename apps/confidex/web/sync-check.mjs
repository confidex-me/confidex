import assert from 'node:assert/strict';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';

const [chrome, bundle, server, remoteUrl] = process.argv.slice(2);
assert(chrome && bundle && server, 'Usage: node sync-check.mjs CHROME WASM_BUNDLE SERVER [APP_URL]');
const files = await assets(bundle);
const password = 'public-sync-browser-fixture';
const record = Array(16).fill(3);
const options = remoteUrl ? {remoteUrl} : {};

async function connect(page) {
  await page.evaluate(`(async () => {
    const worker = new Worker('/worker.js', {type:'module'});
    await new Promise((resolve,reject) => {
      worker.onmessage = event => { if (event.data === 'ready') resolve(); };
      worker.onerror = () => reject(Error('fixture worker failed'));
    });
    window.backend = command => new Promise((resolve,reject) => {
      worker.onerror = () => reject(Error('fixture worker failed'));
      worker.onmessage = ({data}) => {
        if (!(data instanceof Uint8Array) || !data.length) {reject(Error('empty worker reply'));return;}
        try {
          let reply,offset=0;
          try {reply=JSON.parse(new TextDecoder().decode(data));}
          catch {
            offset=4+new DataView(data.buffer,data.byteOffset,data.byteLength).getUint32(0,true);
            if(offset>data.length)throw Error('invalid fixture frame');
            reply=JSON.parse(new TextDecoder().decode(data.subarray(4,offset)));
          }
          const attachmentLength=offset===0?0:data.length-offset;
          if((reply.__attachment_bytes??0)!==attachmentLength)throw Error('invalid fixture attachment');
          if(Array.isArray(reply.result?.Ok?.Backup))reply.result.Ok.Backup=Array.from(data.subarray(offset||data.length));
          if ('Err' in reply.result) reject(Error(JSON.stringify(reply.result.Err)));
          else resolve(reply.result.Ok);
        } catch(error) {reject(error);}
        finally {data.fill(0);}
      };
      const attachment=command.InspectBackup?.archive??[];
      if(attachment.length)command.InspectBackup.archive=[];
      const json = new TextEncoder().encode(JSON.stringify({generation:1,command,__attachment_bytes:attachment.length}));
      const bytes=attachment.length?new Uint8Array(4+json.length+attachment.length):json;
      if(attachment.length) {
        new DataView(bytes.buffer).setUint32(0,json.length,true);
        bytes.set(json,4);bytes.set(attachment,4+json.length);
      }
      worker.postMessage(bytes,[bytes.buffer]);
    });
    window.drain = async server => {
      let downloaded=0, uploaded=0, paginated=false;
      for (let step=0;step<256;step++) {
        const {Synced:report} = await backend({Sync:{server}});
        if (report.conflicts.length) throw Error('branching stopped synchronization');
        downloaded += report.downloaded; uploaded += report.uploaded;
        paginated ||= report.downloaded === 16 && report.more;
        if (!report.more) return {...report, downloaded, uploaded, paginated};
      }
      throw Error('sync did not converge');
    };
  })()`);
  const call = async command => {
    try {return await page.evaluate(`backend(${JSON.stringify(command)})`);}
    catch(error) {throw new Error(`fixture command ${typeof command==='string'?command:Object.keys(command)[0]} failed`,{cause:error});}
  };
  const drain = () => page.evaluate(`drain(${JSON.stringify(server)})`);
  return {page, call, drain};
}

const result = await runBrowser(chrome,files,async firstPage => {
  const a = await connect(firstPage);
  const {Created:created} = await a.call({Create:{name:'Public sync fixture A',password,remember:false}});
  assert.equal(created.key.replaceAll('-','').length,77);
  const original = {record, revision:null, title:'Original',tags:['fixture'],fields:[
    {source:null,name:'Protected note',type_name:'note/v1',values:{text:'Public original note'},opaque:0,protected:true},
    {source:null,name:'Password',type_name:'password/v1',values:{password:'public-value-fixture'},opaque:0,protected:false},
  ]};
  await a.call({Save:{draft:original,epoch:100}});
  for (let index=0;index<17;index++) {
    await a.call({Save:{draft:{record:Array(16).fill(20+index),revision:null,title:`Extra ${index}`,tags:[],fields:[]},epoch:100}});
  }
  await a.call({SyncConfig:{server}});
  const initial = await a.drain();
  assert.equal(initial.uploaded,18);
  assert.equal(initial.conflicts.length,0);
  assert.equal(await a.call({CheckSync:{server}}),'SyncUnchanged');

  const restored = await runBrowser(chrome,files,async secondPage => {
    const b = await connect(secondPage);
    await b.call({Import:{name:'Public sync fixture B',password,key:created.key,server,remember:false}});
    const imported = await b.drain();
    assert.equal(imported.downloaded,18);
    assert(imported.paginated,'bootstrap did not follow multiple server pages');
    const open = async (client,head) => (await client.call({OpenRevision:head})).Draft;
    const list = async (client,tag=null) => (await client.call({List:{after:null,tag}})).Rows.rows;
    const save = async (client,draft,epoch) => (await client.call({Save:{draft,epoch}})).Saved;
    const local = (await b.call({Open:{record}})).Draft;
    assert.equal(local.title,'Original');
    assert.deepEqual(local.tags,['fixture']);
    assert.equal((await list(b,'fixture')).length,1);
    assert(local.fields[0].protected);
    const remote = structuredClone(local);
    local.title='Device B change';remote.title='Device A change';
    local.tags=['device-b'];remote.tags=['device-a'];
    const branchB=await save(b,local,200), branchA=await save(a,remote,200);
    await a.drain();await b.drain();await a.drain();
    for(const client of [a,b]) {
      assert.equal((await list(client,'device-a')).length,1);
      assert.equal((await list(client,'device-b')).length,1);
      assert.equal((await open(client,branchA)).title,'Device A change');
      assert.equal((await open(client,branchB)).title,'Device B change');
    }
    const tagA=await open(a,branchA), tagB=await open(b,branchB);
    tagA.tags=['tag-only-a'];tagB.tags=['tag-only-b'];
    const taggedA=await save(a,tagA,250), taggedB=await save(b,tagB,250);
    await a.drain();await b.drain();await a.drain();
    assert.equal((await list(a,'tag-only-a')).length,1);
    assert.equal((await list(a,'tag-only-b')).length,1);
    const stale=await open(b,taggedB), peer=await open(a,taggedB);
    peer.title='Peer edited the open branch';
    const peerHead=await save(a,peer,260);
    await a.drain();await b.drain();
    stale.title='My unsaved content';
    const saved=await save(b,stale,260);
    await b.drain();await a.drain();
    assert.equal((await open(a,peerHead)).title,'Peer edited the open branch');
    assert.equal((await open(a,saved)).title,'My unsaved content');
    assert.equal((await open(a,taggedA)).title,'Device A change');

    await secondPage.command('Network.enable',{});
    await secondPage.command('Network.emulateNetworkConditions',{offline:true,latency:0,downloadThroughput:-1,uploadThroughput:-1});
    await b.call('Lock');
    await b.call({Unlock:{vault:created.info.id,password,key:created.key,remember:false}});
    const offline=await open(b,saved);
    offline.title='Offline change';
    const offlineHead=await save(b,offline,300);
    await secondPage.command('Network.emulateNetworkConditions',{offline:false,latency:0,downloadThroughput:-1,uploadThroughput:-1});
    await b.drain();await a.drain();
    assert.equal((await open(a,offlineHead)).title,'Offline change');
    assert.equal((await open(a,peerHead)).title,'Peer edited the open branch');
    const wide=[];
    for(let index=0;index<20;index++) {
      const draft=structuredClone(stale);
      draft.title='Equal parallel fixture';draft.tags=['wide'];
      wide.push(await save(b,draft,400));
    }
    assert.equal(new Set(wide.map(h=>h.revision.join(','))).size,20);
    await b.drain();await a.drain();
    for(const client of [a,b]) assert.equal((await list(client,'wide')).length,20);
    const late=await open(a,wide[0]);
    await b.call({Delete:{record,expected:wide[0].revision,epoch:450}});
    await b.drain();await a.drain();
    assert.equal((await list(a,'wide')).length,19);
    late.title='Late child after deletion';
    const lateHead=await save(a,late,500);
    await a.drain();await b.drain();
    assert.equal((await list(b,'wide')).length,20);
    assert.equal((await list(b)).length,40);
    const {History:history}=await b.call({History:{record,cursor:{head:lateHead.revision,offset:0}}});
    assert.equal(history.revisions.length,5);
    assert(history.revisions.every(revision=>!revision.merged));
    const storage=Object.keys(files).find(path=>path.endsWith('/web/storage.js'));
    const snapshot=client=>client.page.evaluate(`(async()=>{
      const {dbCall}=await import(${JSON.stringify(storage)});
      const state=await dbCall('snapshot',[${JSON.stringify(created.info.id.map(n=>n.toString(16).padStart(2,'0')).join(''))}]);
      return {heads:state.heads,objects:state.objects.map(o=>({head:o.head,wire:Array.from(o.wire)}))};
    })()`);
    const left=await snapshot(a),right=await snapshot(b);
    assert.deepEqual(left,right,'devices did not retain identical signed history');
    assert.equal(left.heads.length,41);
    assert.equal(left.objects.length,47);
    const {Backup:archive}=await b.call('ExportBackup');
    assert(Array.isArray(archive) && archive.length>0);
    await runBrowser(chrome,files,async thirdPage=>{
      const c=await connect(thirdPage);
      await c.call({InspectBackup:{archive}});
      await c.call({RestoreBackup:{name:'Public branch backup',password,key:created.key,remember:false}});
      assert.equal((await list(c)).length,40);
      assert.deepEqual(await snapshot(c),left,'ZIP restore changed branch tips or signed history');
    },options);
    return {restored:true,branches:24,identicalPayloadBranches:20,objects:47,offline:true,paginated:true,staleDraft:true,lateChild:true,wireEqual:true,zip:true};
  },options);

  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes=new Uint8Array(48);
  const text=created.key.replaceAll('-','');
  for(let digit=0;digit<text.length;digit++) {
    const value=alphabet.indexOf(text[digit]);assert(value>=0);
    for(let bit=0;bit<5 && digit*5+bit<384;bit++) {
      const offset=digit*5+bit;bytes[offset>>3]|=((value>>(4-bit))&1)<<(7-(offset&7));
    }
  }
  bytes[38]=(bytes[38]&15)|0x50;
  const hex=Array.from(bytes.slice(32),byte=>byte.toString(16).padStart(2,'0')).join('');
  bytes.fill(0);
  const publicId=`${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
  const scope=created.info.id.map(byte=>byte.toString(16).padStart(2,'0')).join('');
  return {...restored,publicId,scope};
},options);
console.log(JSON.stringify(result));
