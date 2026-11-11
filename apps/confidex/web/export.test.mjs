import assert from 'node:assert/strict';
import {saveExport} from './export.js';
const originals={document:globalThis.document,setTimeout:globalThis.setTimeout,create:URL.createObjectURL,revoke:URL.revokeObjectURL};
try {
  for(const failure of [null,'append','click']) {
    const revoked=[],timers=[];let removed=false,blob;
    const link={remove(){removed=true;},click(){if(failure==='click')throw Error('public test');}};
    globalThis.document={createElement:()=>link,body:{append(){if(failure==='append')throw Error('public test');}}};
    globalThis.setTimeout=(f,ms)=>{assert.equal(ms,60000);timers.push(f);};
    URL.createObjectURL=value=>{blob=value;return 'blob:public-test';};
    URL.revokeObjectURL=url=>revoked.push(url);
    if(failure)assert.throws(()=>saveExport(new Uint8Array([1,2,3]),'public.json','application/json'));
    else saveExport(new Uint8Array([1,2,3]),'public.json','application/json');
    assert(removed);assert.equal(link.download,'public.json');assert.equal(blob.type,'application/json');
    assert.deepEqual(Array.from(new Uint8Array(await blob.arrayBuffer())),[1,2,3]);
    if(failure){assert.equal(timers.length,0);assert.deepEqual(revoked,['blob:public-test']);}
    else {assert.deepEqual(revoked,[]);assert.equal(timers.length,1);timers[0]();assert.deepEqual(revoked,['blob:public-test']);}
  }
} finally {
  globalThis.document=originals.document;globalThis.setTimeout=originals.setTimeout;
  URL.createObjectURL=originals.create;URL.revokeObjectURL=originals.revoke;
}
console.log('export download cleanup: success, append failure, click failure passed');
