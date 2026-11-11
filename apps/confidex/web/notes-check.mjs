import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,directory,shots]=process.argv.slice(2);assert(chrome&&directory&&shots);await mkdir(shots,{recursive:true});const results=[],language='en-US';
for(const viewport of [[1180,1000],[390,1000]])results.push(await runBrowser(chrome,await assets(directory),async({command,evaluate,url})=>{
 const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
 const snapshot=()=>evaluate('window.confidex?.snapshot()');
 const until=async p=>{const deadline=Date.now()+25000;for(;;){const s=await snapshot();if(s&&p(s))return s;assert(Date.now()<deadline,JSON.stringify(s));await delay(50);}};
 const location=(s,id)=>s.hits[id]??(s.bounds[id]&&[(s.bounds[id][0]+s.bounds[id][2])/2,(s.bounds[id][1]+s.bounds[id][3])/2]);
 const click=async(id,activate=true)=>{
  let state=await until(s=>location(s,id));
  const host=s=>/^(?:add-(?:.+\/v1|section)|section-\d+-add-.+\/v1)$/.test(id)?s.bounds['field-menu']:/^template-(?!search$|close$|empty$)/.test(id)?s.bounds['template-viewport']:/^(tag-(?!error$)|value-|field-(name|handle)-|record-title$|large-\d+-|copy-\d+-|reveal-\d+-|protected-\d+)/.test(id)?s.bounds['record-viewport']:null;
  for(let n=0;;n++){
   const r=host(state),top=Math.max(r?.[1]??15,15),bottom=Math.min(r?.[3]??viewport[1]-15,viewport[1]-15),y=location(state,id)[1];
   if(y>=top+2&&y<=bottom-2)break;
   assert(n<25,'cannot reach '+id);const card=state.bounds['form-card'];const point={x:r?r[0]+4:card?card[0]+4:viewport[0]-24,y:r?(top+bottom)/2:viewport[1]/2};
   await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:y<top?-160:160});await delay(150);state=await snapshot();
  }
  let[x,y]=location(state,id);for(let n=0;n<8;n++){
   await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});await delay(70);const point=location(await snapshot(),id);if(!point)break;
   const stable=Math.abs(point[0]-x)<0.5&&Math.abs(point[1]-y)<0.5;[x,y]=point;if(stable)break;
  }
  if(activate)for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});await delay(150);
 };
 const text=async(id,text)=>{await click(id);for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});if(text)await rpc('Input.insertText',{text});else for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'Backspace',code:'Backspace',windowsVirtualKeyCode:8});await delay(100);};
 const capture=async name=>{const r=await rpc('Page.captureScreenshot',{format:'png'});await writeFile(`${shots}/${language}-${viewport[0]}-${name}.png`,Buffer.from(r.data,'base64'));};


 await rpc('Browser.grantPermissions',{origin:url,permissions:['clipboardReadWrite','clipboardSanitizedWrite']});
 await rpc('Page.enable');await rpc('Page.addScriptToEvaluateOnNewDocument',{source:`Object.defineProperty(navigator,'languages',{get:()=>['en-US']});`});await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);
 const observe=async()=>evaluate(`window.__lastSave=null;const post=Worker.prototype.postMessage;Worker.prototype.postMessage=function(data,...args){try{const end=data[0]===123?0:4+new DataView(data.buffer,data.byteOffset,4).getUint32(0,true);const m=JSON.parse(new TextDecoder().decode(end?data.subarray(4,end):data));const save=m.command?.Save??m.command?.SaveRevision;if(save)__lastSave=save.draft;}catch{}return post.call(this,data,...args);};`);
 await observe();
 await click('create');await until(s=>s.screen==='create');if((await snapshot()).hits['create-sync'])await click('create-sync');await text('name','Public note fixture');await text('password','public-notes-fixture');await text('repeat','public-notes-fixture');await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
 await click('new-record');await click('template-empty');await text('record-title','Plain note');await click('add-field');await click('add-note/v1');await text('field-name-0','Notes');await text('value-0-text','Public plain note plainnoteproof');assert(!(await snapshot()).hits['protected-0']);await click('save');await until(s=>s.hits.edit&&!s.busy);
 await evaluate(`(async()=>{const seed=structuredClone(__lastSave),worker=new Worker('/worker.js',{type:'module'});await new Promise((resolve,reject)=>{worker.onmessage=e=>{if(e.data==='ready')resolve();};worker.onerror=reject;});const backend=command=>new Promise((resolve,reject)=>{worker.onmessage=({data})=>{const reply=JSON.parse(new TextDecoder().decode(data));data.fill(0);if('Err'in reply.result)reject(Error(JSON.stringify(reply.result.Err)));else resolve(reply.result.Ok);};const bytes=new TextEncoder().encode(JSON.stringify({generation:1,command}));worker.postMessage(bytes,[bytes.buffer]);});const {Catalog:vaults}=await backend('Catalog');await backend({Unlock:{vault:vaults[0].id,password:'public-notes-fixture',key:'',remember:true}});const {Draft:plain}=await backend({Open:{record:seed.record}});plain.sections=[{name:'Section',start:0,count:1}];await backend({Save:{draft:plain,epoch:Date.now()}});for(const [title,type,marker]of [['Secure note','secure-note/v1','secretnoteproof'],['Protected note','note/v1','protectednoteproof']]){const draft=structuredClone(seed);draft.record=Array.from(crypto.getRandomValues(new Uint8Array(16)));draft.title=title;draft.sections=[{name:'Section',start:0,count:1}];draft.fields[0].type_name=type;draft.fields[0].protected=true;draft.fields[0].values.text='Public protected note '+marker;await backend({Save:{draft,epoch:Date.now()}});}await backend('Lock');worker.terminate();return true;})()`);
 await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);await click('vault-0');await until(s=>s.screen==='unlock'&&!s.busy);await text('password','public-notes-fixture');await click('submit');await until(s=>s.screen==='open'&&!s.busy);await observe();
 const select=async title=>{if(!(await snapshot()).hits.search)await click('back');await text('search',title);await until(s=>s.rows===1&&!s.busy);await click('record-0');await until(s=>s.hits.edit&&!s.busy);};
 for(const [title,prefix,protectedNote,kind]of [['Plain note','plain',false,'note/v1'],['Secure note','secure',true,'secure-note/v1'],['Protected note','protected',true,'secure-note/v1']]){
  await select(title);let state=await snapshot();assert.equal(Boolean(state.hits['protected-0']),protectedNote);assert.equal(Boolean(state.hits['reveal-0-text']),protectedNote);await capture(prefix+'-view');
  if(protectedNote){await click('reveal-0-text');assert((await snapshot()).hits['copy-0-text']);await click('reveal-0-text');}
  await click('edit');await until(s=>s.editing);assert.equal(Boolean((await snapshot()).hits['protected-0']),protectedNote);await capture(prefix+'-edit');
  if(!protectedNote){await text('value-0-text','Discarded public fixture');await click('cancel-edit');await until(s=>s.hits.edit&&!s.busy);const copied=(await snapshot()).copied;await click('copy-0-text');await until(s=>s.copied===copied+1);assert.equal(await evaluate('navigator.clipboard.readText()'),'Public plain note plainnoteproof');await click('edit');await text('value-0-text','Public plain note plainnoteproof edited');}
  await click('save');await until(s=>s.hits.edit&&!s.busy);const saved=await evaluate('__lastSave');assert.equal(saved.fields[0].type_name,kind);assert.equal(saved.fields[0].protected,protectedNote);assert(saved.fields[0].source!==null);assert.deepEqual(saved.sections.map(({name,start,count})=>({name,start,count})),[{name:'Section',start:0,count:1}]);assert.equal(Boolean((await snapshot()).hits['reveal-0-text']),protectedNote);
 }
 if(!(await snapshot()).hits.search)await click('back');for(const [query,count]of [['plainnoteproof',1],['secretnoteproof',0],['protectednoteproof',0]]){await text('search',query);await until(s=>s.rows===count&&!s.busy);assert.equal((await snapshot()).error,null);}
 return {viewport,plainHasNoToggle:true,secureAndProtectedRemainProtected:true,sectionsAndSourcesPreserved:true,cancelAndSave:true,searchExclusion:true};
},{viewport,windowSize:viewport}));
await writeFile(`${shots}/results.json`,JSON.stringify(results,null,2));console.log(JSON.stringify(results,null,2));
