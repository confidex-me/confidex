import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';

const result = await runBrowser(process.argv[2], {
  '/storage.js': await readFile(new URL('./storage.js', import.meta.url)),
}, async ({evaluate, command}) => {
  await evaluate(`(async () => {
    const {dbCall:call} = await import('/storage.js');
    const vault = '01'.repeat(16), tag = 'local-private-tag-銀行';
    await call('create', [{info:{id:Array(16).fill(1),name:'Tag fixture'},lock:[1]}]);
    const record = n => n.toString(16).padStart(32,'0');
    const revision = n => n.toString(16).padStart(64,'0');
    for (let n=0;n<260;n++) await call('append',[vault,record(n),revision(n),null,new Uint8Array([1]),[tag]]);
    const hex = bytes => bytes.map(b=>b.toString(16).padStart(2,'0')).join('');
    const first = await call('tagged-heads',[vault,tag,null]);
    const second = await call('tagged-heads',[vault,tag,hex(first.at(-1).record)]);
    const last = await call('tagged-heads',[vault,tag,hex(second.at(-1).record)]);
    if (first.length!==128 || second.length!==128 || last.length!==4) throw Error('tag pagination');
    if ((await call('tagged-heads',['02'.repeat(16),tag,null])).length) throw Error('vault scope');
    if ((await call('tagged-heads',[vault,tag.toUpperCase(),null])).length) throw Error('case folding');
    const head = {record:Array(16).fill(0),revision:Array(32).fill(255)};
    const commit = {previous:null,current:[1],objects:[{head,wire:[2],tags:['replacement']}],heads:[{head,expected:Array(32).fill(9)}]};
    try { await call('sync-commit',[vault,commit]); throw Error('accepted stale head'); }
    catch (error) { if (error!=='Conflict') throw error; }
    if (await call('sync-state',[vault])!==null) throw Error('checkpoint advanced');
    if ((await call('tagged-heads',[vault,'replacement',null])).length) throw Error('partial tag index');
    try { await call('object',[vault,'ff'.repeat(32)]); throw Error('partial object'); }
    catch (error) { if (error!=='NotFound') throw error; }
    commit.heads[0].expected=Array(32).fill(0);
    await call('sync-commit',[vault,commit]);
    if ((await call('tagged-heads',[vault,tag,null]))[0].record.every(b=>b===0)) throw Error('stale tags');
    if ((await call('tagged-heads',[vault,'replacement',null])).length!==1) throw Error('missing tags');
    await call('append',[vault,record(0),'fe'.repeat(32),'ff'.repeat(32),new Uint8Array([3]),[]]);
    if ((await call('tagged-heads',[vault,'replacement',null])).length) throw Error('deleted tags');
    return true;
  })()`);
  await evaluate('window.__beforeTagReload = true');
  await command('Page.reload', {});
  for (let attempt=0;attempt<100;attempt++) {
    try {
      if (!await evaluate('document.readyState === "complete" && !window.__beforeTagReload')) continue;
      const count = await evaluate(`(async () => {
        const {dbCall} = await import('/storage.js');
        return (await dbCall('tagged-heads',['01'.repeat(16),'local-private-tag-銀行','00'.repeat(14)+'00ff'])).length;
      })()`);
      assert.equal(count,4);
      return {pagination:true,atomicRollback:true,currentHeadsOnly:true,reload:true};
    } catch (error) { if (attempt===99) throw error; }
  }
});
console.log(JSON.stringify(result));
