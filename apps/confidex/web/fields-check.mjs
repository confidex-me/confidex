import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,directory,shots]=process.argv.slice(2);assert(chrome&&directory&&shots,'provide Chrome, WASM bundle and screenshots paths');await mkdir(shots,{recursive:true});const results=[];
for(const viewport of [[1320,900],[390,900]])results.push(await runBrowser(chrome,await assets(directory),async({command,evaluate,url})=>{
 const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
 const snapshot=()=>evaluate('window.confidex?.snapshot()');
 const until=async p=>{const deadline=Date.now()+25000;for(;;){const s=await snapshot();if(s&&p(s))return s;assert(Date.now()<deadline,JSON.stringify(s));await delay(50);}};
 const click=async id=>{
  let state=await until(s=>s.hits[id]);
  const host=s=>/^(?:add-(?:.+\/v1|section)|section-\d+-add-.+\/v1)$/.test(id)?s.bounds['field-menu']:/^template-(?!search$|close$|empty$)/.test(id)?s.bounds['template-viewport']:/^(value-|field-(name|handle)-|record-title$|large-\d+-|copy-\d+-|reveal-\d+-|protected-\d+)/.test(id)?s.bounds['record-viewport']:null;
  for(let n=0;;n++){
   const r=host(state),top=Math.max(r?.[1]??15,15),bottom=Math.min(r?.[3]??viewport[1]-15,viewport[1]-15),y=state.hits[id][1];
   if(y>=top+2&&y<=bottom-2)break;
   assert(n<25,'cannot reach '+id);const card=state.bounds['form-card'];const point={x:r?r[0]+4:card?card[0]+4:viewport[0]-24,y:r?(top+bottom)/2:viewport[1]/2};
   await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:y<top?-160:160});await delay(150);state=await snapshot();
  }
  let[x,y]=state.hits[id];for(let n=0;n<8;n++){
   await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});await delay(70);const point=(await snapshot()).hits[id];if(!point)break;
   const stable=Math.abs(point[0]-x)<0.5&&Math.abs(point[1]-y)<0.5;[x,y]=point;if(stable)break;
  }
  for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});await delay(150);
 };
 const text=async(id,text)=>{await click(id);for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});if(text)await rpc('Input.insertText',{text});else for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'Backspace',code:'Backspace',windowsVirtualKeyCode:8});await delay(100);};
 const capture=async name=>{const r=await rpc('Page.captureScreenshot',{format:'png'});await writeFile(`${shots}/${viewport[0]}-${name}.png`,Buffer.from(r.data,'base64'));};
 await rpc('Browser.grantPermissions',{origin:url,permissions:['clipboardReadWrite','clipboardSanitizedWrite']});
 await until(s=>s.screen==='catalog'&&!s.busy);await delay(250);await click('create');await until(s=>s.screen==='create');await text('name','Personal');await text('password','public-client-fixture');await text('repeat','public-client-fixture');await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
 const key=async(name,code,number)=>{for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:name,code,windowsVirtualKeyCode:number});await delay(150);};
 await click('new-record');await until(s=>s.hits['template-login']);await capture('templates');
 const window=(await snapshot()).bounds['template-window'];
 assert(window[0]>=0&&window[1]>=0&&window[2]<=viewport[0]&&window[3]<=viewport[1]);
 if(viewport[0]<600)assert.deepEqual(window,[0,0,...viewport]);
 await key('Escape','Escape',27);await until(s=>!s.bounds['template-window']);assert(!(await snapshot()).editing);
 await click('new-record');await text('template-search','no matching template');await until(s=>!s.hits['template-login']&&!s.hits['template-api-key']);
 await click('template-close');await until(s=>!s.bounds['template-window']);
 await click('new-record');await text('template-search','API');await key('Enter','Enter',13);
 await until(s=>s.editing&&s.hits['value-0-username']&&s.hits['value-1-secret']);assert(!(await snapshot()).hits['value-0-secret']);
 await click('cancel-edit');await until(s=>!s.editing);assert.equal((await snapshot()).rows,0);
 await click('new-record');await click('template-empty');await until(s=>s.editing);
 assert(!(await snapshot()).bounds['field-0']);await click('cancel-edit');await until(s=>!s.editing);
 await click('new-record');await until(s=>s.hits['template-login']);
 await text('template-search','API');await until(s=>s.hits['template-api-key']&&!s.hits['template-login']);
 await text('template-search','');await click('template-login');await until(s=>s.editing&&s.hits['value-2-url']);
 await text('record-title','Mixed secret');await text('value-0-username','alice@example.test');
 const value='public-password-fixture';await text('value-1-password',value);await text('value-2-url','https://example.test');
 await text('field-name-1','Deployment token');
 const before=await snapshot();let [x,y]=before.hits['field-handle-1'];
 await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});
 await rpc('Input.dispatchMouseEvent',{type:'mousePressed',x,y,button:'left',clickCount:1});
 await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x:x+8,y:y-8,buttons:1});await delay(100);
 const dropY=before.bounds['field-0'][1]+2;
 await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y:dropY,buttons:1});await delay(150);
 await rpc('Input.dispatchMouseEvent',{type:'mouseReleased',x,y:dropY,button:'left',clickCount:1});
 await until(s=>s.hits['value-0-password']&&s.hits['value-1-username']);
 await text('value-3-text','Ordinary searchable note');
 await click('add-field');await click('add-secret/v1');await text('field-name-4','Deployment token');await text('value-4-secret','public-api-fixture');
 await click('add-field');await click('add-secure-note/v1');await click('reveal-5-text');await text('value-5-text','Private note fixture');
 const revealedNote=(await snapshot()).bounds['field-5'];await click('reveal-5-text');
 const hiddenNote=(await snapshot()).bounds['field-5'];assert(revealedNote.every((v,i)=>Math.abs(v-hiddenNote[i])<1));await capture('secure-note-hidden');
 await click('add-field');await click('add-text/v1');await text('value-6-text','Public plain field');
 await click('record-title');await capture('independent-edit');await click('save');await until(s=>!s.busy&&s.hits.edit);
 assert((await snapshot()).hits['value-0-password']);await capture('independent-view');
 await click('field-name-5');await capture('secure-note-view');
 const count=(await snapshot()).copied;await click('copy-0-password');await until(s=>s.copied===count+1);
 assert.equal(await evaluate('navigator.clipboard.readText()'),value);
 await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);await click('vault-0');await until(s=>s.screen==='unlock'&&!s.busy);
 await text('password','public-client-fixture');await click('submit');await until(s=>s.screen==='open'&&!s.busy);
 await click('record-0');await until(s=>s.hits.edit&&s.hits['value-0-password']);
 await capture('reloaded');
 const stored=await evaluate(`(async()=>{
  const worker=new Worker('/worker.js',{type:'module'});
  await new Promise((resolve,reject)=>{worker.onmessage=e=>{if(e.data==='ready')resolve();};worker.onerror=()=>reject(Error('worker fixture'));});
  const backend=command=>new Promise((resolve,reject)=>{
   worker.onmessage=({data})=>{const reply=JSON.parse(new TextDecoder().decode(data));data.fill(0);if('Err'in reply.result)reject(Error(JSON.stringify(reply.result.Err)));else resolve(reply.result.Ok);};
   const bytes=new TextEncoder().encode(JSON.stringify({generation:1,command}));worker.postMessage(bytes,[bytes.buffer]);
  });
  const {Catalog:vaults}=await backend('Catalog');
  await backend({Unlock:{vault:vaults[0].id,password:'public-client-fixture',key:'',remember:true}});
  const {Rows:{rows}}=await backend({List:{after:null,tag:null}});
  const {Draft:draft}=await backend({Open:{record:rows[0].head.record}});
  const proof={kinds:draft.fields.map(f=>f.type_name),names:draft.fields.map(f=>f.name),secure:draft.fields[5].protected,value:draft.fields[5].values.text,sourceParts:draft.fields.some(f=>f.source_key)};
  await backend('Lock');worker.terminate();return proof;
 })()`);
 assert.deepEqual(stored.kinds,['password/v1','username/v1','url/v1','note/v1','secret/v1','secure-note/v1','text/v1']);
 assert.equal(stored.names[0],'Deployment token');assert.equal(stored.names[4],stored.names[0]);
 assert.equal(stored.secure,true);assert.equal(stored.value,'Private note fixture');assert(!stored.sourceParts);
 return {viewport,templateSearch:true,templateKeyboard:true,templateCancel:true,apiAndEmpty:true,independentDrag:true,rename:true,mixedFields:true,secureNote:true,saveReload:true,copy:true};

},{viewport,windowSize:viewport}));
console.log(JSON.stringify(results,null,2));
