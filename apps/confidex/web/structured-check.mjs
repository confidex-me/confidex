import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,directory,shots]=process.argv.slice(2);assert(chrome&&directory&&shots,'provide Chrome, WASM bundle and screenshots paths');await mkdir(shots,{recursive:true});const results=[];
for(const viewport of [[1180,1000],[760,1000],[390,1000]])results.push(await runBrowser(chrome,await assets(directory),async({command,evaluate,url})=>{
 const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
 const snapshot=()=>evaluate('window.confidex?.snapshot()');
 const until=async p=>{const deadline=Date.now()+25000;for(;;){const s=await snapshot();if(s&&p(s))return s;assert(Date.now()<deadline,JSON.stringify(s));await delay(50);}};
 const click=async id=>{
  let state=await until(s=>s.hits[id]);
  const host=s=>/^(?:add-(?:.+\/v1|section)|section-\d+-add-.+\/v1)$/.test(id)?s.bounds['field-menu']:/^template-(?!search$|close$|empty$)/.test(id)?s.bounds['template-viewport']:/^(section-\d+-(?:name|handle|remove|add)$|location-|date-|value-|field-(name|handle)-|record-title$|large-\d+-|copy-\d+-|reveal-\d+-|protected-\d+)/.test(id)?s.bounds['record-viewport']:null;
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
 const notification=async(ids,name)=>{
  const s=await until(s=>s.error&&s.bounds['form-error']),r=s.bounds['form-error'],card=s.bounds['form-card'],inset=viewport[0]<600?17:25;
  assert(r[1]>Math.max(...ids.map(id=>s.hits[id][1])),'notification follows the last action row');
  assert(Math.abs(r[0]-card[0]-inset)<1&&Math.abs(card[2]-r[2]-inset)<1,'notification fills the form');
  await capture(name);
 };
 await rpc('Browser.grantPermissions',{origin:url,permissions:['clipboardReadWrite','clipboardSanitizedWrite']});
 await until(s=>s.screen==='catalog'&&!s.busy);await delay(250);await click('create');await until(s=>s.screen==='create');if((await snapshot()).hits['create-sync'])await click('create-sync');await click('submit');await notification(['submit','cancel'],'create-notification');await text('name','Personal');await text('password','public-client-fixture');await text('repeat','public-client-fixture');await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
 const key=async(name,code,number)=>{for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:name,code,windowsVirtualKeyCode:number});await delay(150);};

 await click('new-record');
 await click('template-empty');
 await until(s=>s.editing);
 await text('record-title','Public calendar values');
 await click('add-field'); await click('add-section');
 await text('section-0-name','Public group');
 const dates=[];
 for(const [kind,input,pick,expected] of [
  ['date/v1','29/02/2024','day-1','01/02/2024'],
  ['month-year/v1','02/2024','month-12','12/2024'],
 ]){
  await click('section-0-add'); await click(`section-0-add-${kind}`);
  const index=dates.length;
  const state=await until(s=>Object.keys(s.hits).filter(id=>/^date-.*-input$/.test(id)).length===index+1);
  const inputId=Object.keys(state.hits).filter(id=>/^date-.*-input$/.test(id)).find(id=>!dates.some(date=>date.inputId===id));
  const prefix=inputId.slice(0,-6);
  const inputRect=state.bounds[inputId],opener=state.hits[`${prefix}-picker`],copy=state.hits[`${prefix}-copy`];
  assert(inputRect&&opener[0]>inputRect[0]&&opener[0]<inputRect[2]&&opener[1]>inputRect[1]&&opener[1]<inputRect[3],'calendar opener is inside the value');
  assert(Math.abs(copy[1]-opener[1])<1,'copy stays on the value row');
  assert(!state.hits[`${prefix}-clear`],'no separate clear button');
  await text(inputId,'partial');
  assert(!(await snapshot()).hits.save);
  await text(inputId,input);
  await until(s=>s.hits.save);
  await click(`${prefix}-picker`);
  await until(s=>s.hits[`${prefix}-${pick}`]);
  await capture(kind==='date/v1'?'day-picker':'month-picker');
  await click(`${prefix}-picker`); await until(s=>!s.hits[`${prefix}-${pick}`]);
  await click(`${prefix}-picker`); await until(s=>s.hits[`${prefix}-${pick}`]);
  await click(`${prefix}-${pick}`);
  await text(`field-name-${index}`,'Same');
  dates.push({inputId,expected});
 }
 await capture('compact-edit');
 for(const index of [0,1]){
  const state=await snapshot(),type=state.bounds[`field-type-${index}`],remove=state.hits[`remove-${index}`];
  assert(type&&type[2]<remove[0]&&Math.abs((type[1]+type[3])/2-remove[1])<1,'type is beside delete');
 }
 await click('field-handle-1');
 await key('ArrowUp','ArrowUp',38);
 await click('record-title');
 await click('save');
 await until(s=>!s.busy&&s.hits.edit);
 const checkCopies=async()=>{
  for(const [index,expected] of ['12/2024','01/02/2024'].entries()){
   const before=(await snapshot()).copied;
   await click(`copy-${index}-date`);
   await until(s=>s.copied===before+1);
   assert.equal(await evaluate('navigator.clipboard.readText()'),expected);
  }
 };
 await checkCopies();
 await capture('calendar-view');
 await click('edit');
 const invalid=Object.keys((await snapshot()).hits).find(id=>/^date-.*-input$/.test(id));
 await text(invalid,'bad');
 assert(!(await snapshot()).hits.save);
 await click('cancel-edit');
 await until(s=>!s.busy&&s.hits.edit);
 await checkCopies();
 await rpc('Page.reload');
 await until(s=>s.screen==='catalog'&&!s.busy);
 await click('vault-0');
 await until(s=>s.screen==='unlock'&&!s.busy);
 await click('submit');await notification(['submit','vaults'],'unlock-notification');
 await text('password','wrong-public-password');await click('submit');await until(s=>!s.busy&&s.error==='vault-error-auth');await notification(['submit','vaults'],'unlock-auth-notification');
 await text('password','public-client-fixture');
 await click('submit');
 await until(s=>s.screen==='open'&&!s.busy);
 await click('record-0');
 await until(s=>s.hits.edit);
 await checkCopies();
 await capture('calendar-reopened');
 await click('edit');
 await click('section-0-add'); await click('section-0-add-location/v1');
 const location=await until(s=>Object.keys(s.hits).some(id=>/^location-\d+-name$/.test(id)));
 const locationPrefix=Object.keys(location.hits).find(id=>/^location-\d+-name$/.test(id)).slice(0,-5);
 await text(`${locationPrefix}-name`,'Public place');
 await text('field-name-2','Office');
 await text(`${locationPrefix}-latitude`,'91');
 assert(!(await snapshot()).hits.save);
 await text(`${locationPrefix}-longitude`,'4.90');
 assert(!(await snapshot()).hits.save);
 await text(`${locationPrefix}-latitude`,'52,37');
 await until(s=>s.hits.save);
 await capture('location-edit');
 await click('save'); await until(s=>!s.busy&&s.hits.edit);
 const checkLocation=async()=>{
  for(const [name,expected] of [['name','Public place'],['latitude','52.37'],['longitude','4.9']]){
   const before=(await snapshot()).copied;
   await click(`copy-2-${name}`);
   await until(s=>s.copied===before+1);
   assert.equal(await evaluate('navigator.clipboard.readText()'),expected);
  }
 };
 await checkLocation();
 await click('edit');
 const prefix=Object.keys((await snapshot()).hits).find(id=>/^location-\d+-name$/.test(id)).slice(0,-5);
 await text(`${prefix}-latitude`,'NaN');
 assert(!(await snapshot()).hits.save);
 await click('cancel-edit'); await until(s=>!s.busy&&s.hits.edit);
 await checkLocation();
 await rpc('Page.reload');
 await until(s=>s.screen==='catalog'&&!s.busy);
 await click('vault-0'); await until(s=>s.screen==='unlock'&&!s.busy);
 await text('password','public-client-fixture'); await click('submit');
 await until(s=>s.screen==='open'&&!s.busy);
 await click('record-0'); await until(s=>s.hits.edit);
 await checkCopies(); await checkLocation();
 assert((await snapshot()).bounds['section-0'],'typed fields remain grouped after reopening');
 await capture('location-reopened');
 return {viewport,calendar:true,monthYear:true,location:true,section:true,validation:true,renameAndReorder:true,copy:true,cancel:true,encryptedSaveReload:true};
},{viewport,windowSize:viewport}));
console.log(JSON.stringify(results,null,2));
