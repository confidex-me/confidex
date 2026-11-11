import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {assets} from './assets.mjs';
import {runBrowser} from '../../../tools/browser-run.mjs';
const [chrome,bundle,output]=process.argv.slice(2);
assert(chrome&&bundle&&output,'usage: branch-ui-check.mjs CHROME BUNDLE RESULTS');
await mkdir(output,{recursive:true});
const files=await assets(bundle),storage=Object.keys(files).find(p=>p.endsWith('/web/storage.js'));
files['/public-branch-seed.js']=Buffer.from("import init,{seed_branches_ui_check as seed} from '/app.js';await init();self.onmessage=async()=>self.postMessage(JSON.parse(await seed()));self.postMessage('ready');");
const results=[];
for(const width of [1320,390]) {
  results.push(await runBrowser(chrome,files,async({command,evaluate})=>{
    const rpc=async(method,params={})=>{const response=await command(method,params);assert(!response.error,JSON.stringify(response));return response.result;};
    const state=()=>evaluate('window.confidex?.snapshot()');
    const capture=async name=>{await delay(150);await writeFile(join(output,`${width}-${name}.png`),Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));};
    const until=async predicate=>{const deadline=Date.now()+45000;for(;;){const s=await state();if(s&&predicate(s))return s;if(Date.now()>deadline){await capture('failure');assert.fail(JSON.stringify(s));}await delay(40);}};
    const click=async id=>{
      for(let attempt=0;attempt<30;attempt++) {
        const s=await until(s=>s.hits[id]),[x,y]=s.hits[id];
        if(y>5&&y<990&&x>0&&x<width) {
          await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});await delay(50);
          const fresh=(await state()).hits[id]; if(!fresh||Math.abs(fresh[1]-y)>1)continue;
          for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});
          await delay(120);return;
        }
        const viewport=s.bounds['record-viewport']??[0,0,width,1000];
        await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',x:viewport[0]+10,y:(viewport[1]+viewport[3])/2,deltaX:0,deltaY:y<5?-220:220});await delay(120);
      }
      assert.fail(`unreachable ${id}`);
    };
    const text=async(id,value,replace=false)=>{
      await click(id);
      if(replace) {
        await rpc('Input.dispatchKeyEvent',{type:'keyDown',key:'Meta',code:'MetaLeft',modifiers:4});
        for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});
        await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});
      }
      await rpc('Input.insertText',{text:value});await delay(80);
    };
    await until(s=>s.screen==='catalog'&&!s.busy);
    const seed=await evaluate("new Promise((resolve,reject)=>{const worker=new Worker('/public-branch-seed.js',{type:'module'});worker.onerror=reject;worker.onmessage=({data})=>{if(data==='ready')worker.postMessage('seed');else{worker.terminate();resolve(data);}};})");
    await rpc('Page.reload',{ignoreCache:true});
    await until(s=>s.vaults===1&&!s.busy);await click('vault-0');
    await until(s=>s.screen==='unlock'&&!s.busy);
    await text('secret-key',seed.created.key);await text('password','public-export-contract-password');await click('submit');
    await until(s=>s.screen==='open'&&!s.busy&&s.rows===2);
    assert.equal((await state()).error,null);
    await evaluate(`(async()=>{window.branchDb=(await import(${JSON.stringify(storage)})).dbCall;window.branchVault=${JSON.stringify(seed.created.info.id)}.map(n=>n.toString(16).padStart(2,'0')).join('');window.branchBefore=await branchDb('snapshot',[branchVault]);return true;})()`);
    await capture('parallel-list');
    await click('record-1');await until(s=>!s.busy&&s.hits.edit);await capture('selected');
    const inspect=()=>evaluate(`(async()=>{const snapshot=await branchDb('snapshot',[branchVault]);const equal=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);const sibling=branchBefore.heads[0],selected=branchBefore.heads[1];const object=(s,h)=>s.objects.find(o=>equal(o.head.revision,h.revision));return {heads:snapshot.heads.length,objects:snapshot.objects.length,sibling:snapshot.heads.some(h=>equal(h.revision,sibling.revision))&&equal(object(snapshot,sibling).wire,object(branchBefore,sibling).wire),oldSelected:snapshot.heads.some(h=>equal(h.revision,selected.revision))};})()`);
    for(const [index,title] of ['Edited selected branch','Edited selected branch again'].entries()) {
      await click('edit');await until(s=>s.editing&&s.hits['record-title']);await text('record-title',title,true);
      await capture(`editing-${index}`);await click('save');await until(s=>!s.busy&&!s.editing&&s.rows===2);
      assert.equal((await state()).error,null);
      const data=await inspect();assert.equal(data.heads,2);assert(data.sibling);assert(!data.oldSelected);assert.equal(data.objects,5+index);
    }
    await capture('saved');
    await click('history-toggle');
    const history=await until(s=>!s.busy&&s.bounds['history-row-4']);
    assert.equal(history.error,null);assert(!history.bounds['history-row-5']);
    await capture('selected-history');
    return {width,rows:2,selectedEdits:2,...await inspect()};
  },{viewport:[width,1000],windowSize:[width,1000]}));
}
console.log(JSON.stringify(results));
