import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';

const [chrome,bundle,output='/tmp/confidex-history-shots']=process.argv.slice(2);
assert(chrome&&bundle,'Usage: history-check.mjs CHROME BUNDLE [SCREENSHOTS]');
const files=await assets(bundle);
await mkdir(output,{recursive:true});
const results=[];
for(const width of [1180,390]) {
 results.push(await runBrowser(chrome,files,async({command,evaluate})=>{
  const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
  await rpc('Page.enable');
  await rpc('Page.addScriptToEvaluateOnNewDocument',{source:`
    Object.defineProperty(navigator,'languages',{get:()=>['ru-RU']});
    window.__NativeWorker=Worker;
    window.Worker=class extends Worker {
      constructor(...args) { super(...args); if(String(args[0]).endsWith('/worker.js')) {
        window.__vaultWorker=this;
        this.addEventListener('message',({data})=>{try{
          const r=JSON.parse(new TextDecoder().decode(data));
          if(r.generation===999) { window.__engineResolve?.(r.result); } else {
            window.__reply=r.result;
            if(r.result.Ok?.Draft) window.__lastDraft=r.result.Ok.Draft;
          }
        }catch{}});
      }}
      postMessage(data,...args) {try {const r=JSON.parse(new TextDecoder().decode(data));window.__generation=r.generation;window.__request=r.command;}catch{}super.postMessage(data,...args);}
    };
    window.__engine=command=>new Promise(resolve=>{
      const worker=window.__vaultWorker;
      window.__engineResolve=resolve;
      __NativeWorker.prototype.postMessage.call(worker,new TextEncoder().encode(JSON.stringify({generation:999,command})));
    });
    window.__syncDone=()=>{
      window.__reply=null;
      __NativeWorker.prototype.postMessage.call(__vaultWorker,new TextEncoder().encode(JSON.stringify({generation:__generation,command:{SyncConfig:{server:null}}})));
    };`});
  await rpc('Page.reload');
  const state=()=>evaluate('window.confidex?.snapshot()');
  const until=async predicate=>{
    for(let i=0;i<800;i++){let s;try{s=await state();}catch{}if(s&&await predicate(s))return s;await delay(50);}
    throw Error('History timeout: '+JSON.stringify(await state()));
  };
  const click=async id=>{
    for(let i=0;i<45;i++) {
      const s=await until(s=>s.hits[id]),[x,y]=s.hits[id];
      let viewport=null;
      if(id==='history-toggle'||id==='history-more'||/^history-view-\d+$/.test(id))viewport=s.bounds['record-viewport'];
      if(/^history-(reveal|copy)-/.test(id))viewport=s.bounds['history-view-viewport'];
      const top=Math.max(0,viewport?.[1]??0),bottom=Math.min(1100,viewport?.[3]??1100);
      if(y>=top+2&&y<=bottom-2) {
        for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});
        await delay(120);return;
      }
      const point={x:viewport[2]+4,y:(top+bottom)/2};
      await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
      await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:y<top?-200:200});await delay(120);
    }
    throw Error('Cannot scroll to '+id);
  };
  const text=async(id,value)=>{
    await click(id);
    for(const type of ['rawKeyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});
    await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});
    await rpc('Input.insertText',{text:value});await delay(100);
  };
  const shot=async name=>{
    await delay(250);
    await writeFile(`${output}/${width}-${name}.png`,Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));
  };
  await until(async s=>s.screen==='catalog'&&!s.busy&&(await evaluate('Boolean(window.__vaultWorker)')));
  assert.equal((await state()).locale,'ru');await delay(250);
  await click('create');await until(s=>s.screen==='create');await click('create-sync');
  await text('name','Public history fixture');await text('password','Public password');await text('repeat','Public password');
  await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');
  await until(s=>s.screen==='open'&&!s.busy);await click('new-record');await click('template-login');
  await text('record-title','Public original title');await text('value-1-password','Public original password');await click('save');
  await until(s=>!s.busy&&!s.editing&&s.hits.edit);
  await evaluate(`(async()=>{
    let draft=structuredClone(__lastDraft);
    draft.fields[1].name='password';
    draft.fields.push({source:null,source_key:null,name:'api-key',type_name:'secret/v1',values:{secret:'Public API fixture'},opaque:0,protected:false});
    for(let i=1;i<=18;i++){
      draft.title='Public revision '+i;
      draft.fields[1].values.password='Public historical password '+i;
      draft.fields[3].values.secret='Public historical API '+i;
      const saved=await __engine({Save:{draft,epoch:Date.UTC(2026,10,9,12,i)}});
      if(!saved.Ok?.Saved)throw Error('Fixture save failed');
      const opened=await __engine({Open:{record:draft.record}});
      if(!opened.Ok?.Draft)throw Error('Fixture open failed');
      draft=opened.Ok.Draft;
    }
  })()`);
  await evaluate('__syncDone()');await until(async s=>!s.busy&&(await evaluate('Boolean(__reply?.Ok?.Rows)')));
  if((await state()).hits.back)await click('back');
  await click('record-0');
  await until(async s=>!s.busy&&s.hits.edit&&(await evaluate('__lastDraft.title'))==='Public revision 18');
  await click('edit');await text('record-title','Public unsaved current draft');
  await click('history-toggle');await until(s=>!s.busy&&s.hits['history-view-0']);
  await shot('history-page-one');
  await click('history-more');await until(s=>!s.busy&&s.hits['history-view-18']);
  await shot('history-two-pages');
  await click('history-view-0');await until(s=>!s.busy&&s.hits['history-reveal-1-password']);
  assert.equal((await state()).editing,true);
  const preview=await evaluate('__reply.Ok.Historical.draft');
  assert.equal(preview.title,'Public revision 18');
  const rect=(await state()).bounds['history-window'];assert(rect[0]>=-1&&rect[1]>=-1&&rect[2]<=width+1&&rect[3]<=1101);
  await shot('historical-hidden');
  await click('history-reveal-1-password');await shot('historical-revealed');
  await click('history-close');await until(s=>!s.bounds['history-window']);
  assert.equal((await state()).editing,true,'closing history cancelled the editor');
  await click('save');
  await until(async s=>!s.busy&&!s.editing&&(await evaluate('__lastDraft.title'))==='Public unsaved current draft');
  assert.equal((await state()).error,null);
  await click('delete');await click('confirm-delete');
  await until(s=>!s.busy&&s.rows===0&&s.hits.trash);
  await click('trash');await until(s=>!s.busy&&s.hits['trash-record-0']);
  await shot('trash');
  await click('trash-record-0');
  await until(s=>!s.busy&&s.hits['history-reveal-1-password']&&s.hits['trash-restore']);
  assert.equal(await evaluate('__reply.Ok.Historical.draft.title'),'Public unsaved current draft');
  await shot('trash-preview');
  await click('trash-restore');
  await until(s=>!s.busy&&!s.bounds['history-window']&&!s.hits['trash-record-0']);
  await shot('trash-empty');
  await click('trash-back');await until(s=>!s.busy&&s.rows===1);
  await click('record-0');
  await until(s=>!s.busy&&s.hits.edit);
  assert.equal(await evaluate('__lastDraft.fields[1].values.password'),'Public historical password 18');
  return {width,pagination:true,historicalView:true,draftPreserved:true,trashRestored:true};
 },{viewport:[width,1100]}));
}
console.log(JSON.stringify(results));
