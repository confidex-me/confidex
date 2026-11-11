import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,directory,shots]=process.argv.slice(2);assert(chrome&&directory&&shots,'provide Chrome, WASM bundle and screenshots paths');await mkdir(shots,{recursive:true});const results=[];
for(const viewport of [[1180,1000],[390,1000]])results.push(await runBrowser(chrome,await assets(directory),async({command,evaluate,url})=>{
 const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
 const snapshot=()=>evaluate('window.confidex?.snapshot()');
 const until=async p=>{const deadline=Date.now()+25000;for(;;){const s=await snapshot();if(s&&p(s))return s;assert(Date.now()<deadline,JSON.stringify(s));await delay(50);}};
 const click=async id=>{
  let state=await until(s=>s.hits[id]);
  const host=s=>/^(?:add-(?:.+\/v1|section)|section-\d+-add-.+\/v1)$/.test(id)?s.bounds['field-menu']:/^template-(?!search$|close$|empty$)/.test(id)?s.bounds['template-viewport']:/^(section-\d+-(?:name|handle|remove|add)$|value-|field-(name|handle)-|record-title$|copy-\d+-)/.test(id)?s.bounds['record-viewport']:null;
  for(let n=0;;n++){
   const r=/-(day|month)-\d+$/.test(id)?null:host(state),top=Math.max(r?.[1]??15,15),bottom=Math.min(r?.[3]??viewport[1]-15,viewport[1]-15),y=state.hits[id][1];
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
 await until(s=>s.screen==='catalog'&&!s.busy);await delay(250);await click('create');await until(s=>s.screen==='create');if((await snapshot()).hits['create-sync'])await click('create-sync');await text('name','Personal');await text('password','public-client-fixture');await text('repeat','public-client-fixture');await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
 const key=async(name,code,number)=>{for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:name,code,windowsVirtualKeyCode:number});await delay(150);};

 await click('new-record'); await click('template-empty'); await until(s=>s.editing);
 await text('record-title','Public sections');
 const addSection=async index=>{await click('add-field');await click('add-section');await text(`section-${index}-name`,'Same');};
 const addText=async(index,value,section)=>{
  if(section===undefined){await click('add-field');await click('add-text/v1');}
  else{await click(`section-${section}-add`);await click(`section-${section}-add-text/v1`);}
  await text(`value-${index}-text`,value);
 };
 await addText(0,'Public prefix');
 await addSection(0); await addText(1,'Public A',0);
 await addSection(1); await addText(2,'Public B',1);
 await addSection(2); await addText(3,'Public tail');
 await click('section-0-handle'); await key('ArrowDown','ArrowDown',40);
 await click('field-handle-1');
 let state=await snapshot(); const [x,y]=state.hits['field-handle-1'];
 // Keep the empty destination visible before starting the drag.
 const target=state.hits['section-2-name']; assert(target[1]<viewport[1]-15);
 await rpc('Input.dispatchMouseEvent',{type:'mousePressed',x,y,button:'left',clickCount:1});
 for(const [mx,my] of [[x,y+20],target,target]){await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x:mx,y:my,button:'left',buttons:1});await delay(120);}
 await rpc('Input.dispatchMouseEvent',{type:'mouseReleased',x:target[0],y:target[1],button:'left',clickCount:1});await delay(200);
 await addText(1,'Public new',0);
 await click('section-0-remove');
 await click('section-0-handle'); await key('ArrowDown','ArrowDown',40);
 await addSection(2);
 await capture('sections-edit');
 await click('save'); await until(s=>!s.busy&&s.hits.edit);
 const expected=['Public prefix','Public new','Public B','Public A','Public tail'];
 const check=async()=>{
  for(const [index,value] of expected.entries()){
   const before=(await snapshot()).copied; await click(`copy-${index}-text`);
   await until(s=>s.copied===before+1); assert.equal(await evaluate('navigator.clipboard.readText()'),value);
  }
  assert((await snapshot()).bounds['section-2'],'empty section is preserved');
 };
 await check(); await capture('sections-view');
 await click('edit');await click('section-0-handle');await key('ArrowDown','ArrowDown',40);
 await click('cancel-edit');await until(s=>!s.busy&&s.hits.edit);await check();
 await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);
 await click('vault-0');await until(s=>s.screen==='unlock'&&!s.busy);
 await text('password','public-client-fixture');await click('submit');await until(s=>s.screen==='open'&&!s.busy);
 await click('record-0');await until(s=>s.hits.edit);await check();await capture('sections-reopened');
 return {viewport,duplicateNames:true,emptySection:true,fieldAndSectionReorder:true,dragIntoEmpty:true,ungroupKeepsValues:true,cancel:true,encryptedSaveReload:true};
},{viewport,windowSize:viewport}));
console.log(JSON.stringify(results,null,2));
