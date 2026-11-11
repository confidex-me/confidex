import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,directory,shots]=process.argv.slice(2);assert(chrome&&directory&&shots);await mkdir(shots,{recursive:true});const results=[];
for(const language of ['en-US','ru'])for(const viewport of [[1180,1000],[390,1000]])results.push(await runBrowser(chrome,await assets(directory),async({command,evaluate})=>{
 const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
 const snapshot=()=>evaluate('window.confidex?.snapshot()');
 const until=async p=>{const deadline=Date.now()+25000;for(;;){const s=await snapshot();if(s&&p(s))return s;assert(Date.now()<deadline,JSON.stringify(s));await delay(50);}};
 const location=(s,id)=>s.hits[id]??(s.bounds[id]&&[(s.bounds[id][0]+s.bounds[id][2])/2,(s.bounds[id][1]+s.bounds[id][3])/2]);
 const click=async(id,activate=true)=>{
  let state=await until(s=>location(s,id));
  const host=s=>/^template-(?!search$|close$|empty$)/.test(id)?s.bounds['template-viewport']:/^(tag-(?!error$)|value-|field-(name|handle)-|record-title$|large-\d+-|copy-\d+-|reveal-\d+-|protected-\d+)/.test(id)?s.bounds['record-viewport']:null;
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

 await rpc('Page.enable');await rpc('Page.addScriptToEvaluateOnNewDocument',{source:`Object.defineProperty(navigator,'languages',{get:()=>[${JSON.stringify(language)}]});`});await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);
 await evaluate(`window.__tagSaves=[];const post=Worker.prototype.postMessage;Worker.prototype.postMessage=function(data,...args){try{const end=data[0]===123?0:4+new DataView(data.buffer,data.byteOffset,4).getUint32(0,true);const m=JSON.parse(new TextDecoder().decode(end?data.subarray(4,end):data));const save=m.command?.Save??m.command?.SaveRevision;if(save)__tagSaves.push(save.draft);}catch{}return post.call(this,data,...args);};`);
 const key=async(name,code,number)=>{for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:name,code,windowsVirtualKeyCode:number});await delay(150);};
 await click('create');await until(s=>s.screen==='create');if((await snapshot()).hits['create-sync'])await click('create-sync');await text('name','Public tag fixture');await text('password','public-tags-fixture');await text('repeat','public-tags-fixture');await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
 await click('new-record');await click('template-login');await until(s=>s.editing&&s.hits['value-0-username']);await text('record-title','Tagged public fixture');await text('value-0-username','public@example.test');await text('value-1-password','public-password-fixture');await text('value-3-text','Public note fixture');
 await click('tag-remove-0');
 await text('tag-input',' Work ');await click('tag-add');await until(s=>s.hits['tag-remove-0']);
 await text('tag-input','Personal, public');await key('Enter','Enter',13);await until(s=>s.hits['tag-remove-1']);assert.equal(await evaluate('__tagSaves.length'),0);
 await text('tag-input','Work');await until(s=>s.bounds['tag-error']&&!s.hits.save&&!s.hits['tag-add']);await until(s=>s.bounds['tag-add'][3]<=s.bounds['record-viewport'][3]+1);let state=await snapshot();assert(state.hits['tag-input'][1]<state.bounds['record-viewport'][3]);assert(state.bounds['tag-error'][1]>=state.bounds.save[3]);assert(state.bounds['tag-error'][1]>=state.bounds['cancel-edit'][3]);assert(state.bounds['tag-error'][3]<=state.bounds['record-footer'][3]+1);await capture('tags-error');await key('Enter','Enter',13);assert.equal(await evaluate('__tagSaves.length'),0);
 await text('tag-input','é'.repeat(129));await until(s=>s.bounds['tag-error']&&!s.hits.save);await key('Enter','Enter',13);assert.equal(await evaluate('__tagSaves.length'),0);
 await text('tag-input','日本語');await until(s=>s.hits.save&&s.hits['tag-add']);await until(s=>s.bounds['tag-add'][3]<=s.bounds['record-viewport'][3]+1);await capture('tags-editor');const focused=(await snapshot()).hits['tag-input'][1],host=(await snapshot()).bounds['record-viewport'];await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x:host[0]+4,y:(host[1]+host[3])/2});await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',x:host[0]+4,y:(host[1]+host[3])/2,deltaX:0,deltaY:-240});await delay(300);assert((await snapshot()).hits['tag-input'][1]>focused+20,'focused tag input must allow manual scrolling');await click('save');await until(s=>s.hits.edit&&!s.busy);const first=await evaluate('__tagSaves.at(-1)');assert.deepEqual(first.tags,['Work','Personal, public','日本語']);assert.equal(first.fields[0].values.username,'public@example.test');assert.equal(first.fields[1].values.password,'public-password-fixture');assert.equal(first.fields[3].values.text,'Public note fixture');
 await click('edit');await until(s=>s.editing);await click('tag-remove-0');await text('tag-input','Cancelled');await click('cancel-edit');await until(s=>s.hits.edit&&!s.busy);assert.equal(await evaluate('__tagSaves.length'),1);
 await click('edit');await click('tag-remove-0');await text('tag-input','Replaced');await click('save');await until(s=>s.hits.edit&&!s.busy);const second=await evaluate('__tagSaves.at(-1)');assert.deepEqual([...second.tags].sort(),['Replaced','Work','日本語'].sort());assert.equal(second.fields[1].values.password,'public-password-fixture');assert(second.fields.every(f=>f.source!==null));
 await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);await click('vault-0');await until(s=>s.screen==='unlock'&&!s.busy);await text('password','public-tags-fixture');await click('submit');await until(s=>s.screen==='open'&&!s.busy);await click('record-0');await until(s=>s.hits.edit);await capture('tags-reloaded');
 const stored=await evaluate(`(async()=>{const worker=new Worker('/worker.js',{type:'module'});await new Promise((resolve,reject)=>{worker.onmessage=e=>{if(e.data==='ready')resolve();};worker.onerror=reject;});const backend=command=>new Promise((resolve,reject)=>{worker.onmessage=({data})=>{const reply=JSON.parse(new TextDecoder().decode(data));data.fill(0);if('Err'in reply.result)reject(Error(JSON.stringify(reply.result.Err)));else resolve(reply.result.Ok);};const bytes=new TextEncoder().encode(JSON.stringify({generation:1,command}));worker.postMessage(bytes,[bytes.buffer]);});const {Catalog:vaults}=await backend('Catalog');await backend({Unlock:{vault:vaults[0].id,password:'public-tags-fixture',key:'',remember:true}});const {Rows:{rows}}=await backend({List:{after:null,tag:null}});const {Draft:draft}=await backend({Open:{record:rows[0].head.record}});const proof={tags:draft.tags,kinds:draft.fields.map(f=>f.type_name),username:draft.fields[0].values.username,note:draft.fields[3].values.text};await backend('Lock');worker.terminate();return proof;})()`);
 assert.deepEqual(stored.tags,['Replaced','Work','日本語'].sort());assert.deepEqual(stored.kinds,['username/v1','password/v1','url/v1','note/v1']);assert.equal(stored.username,'public@example.test');assert.equal(stored.note,'Public note fixture');
 if(!(await snapshot()).hits.search)await click('back');await text('search','#Replaced');await until(s=>s.rows===1&&!s.busy);await text('search','#Personal, public');await until(s=>s.rows===0&&!s.busy);assert.equal((await snapshot()).error,null);
 return {language,viewport,addAndEnter:true,commaAndUnicodeTags:true,duplicateAndByteLimit:true,pendingSaved:true,cancelAndRemove:true,reloadAndIndex:true};
},{viewport,windowSize:viewport}));
await writeFile(`${shots}/results.json`,JSON.stringify(results,null,2));console.log(JSON.stringify(results,null,2));
