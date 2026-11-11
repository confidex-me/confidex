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
 const click=async(id,activate=true)=>{
  let state=await until(s=>s.hits[id]);
  const host=s=>/^(?:add-(?:.+\/v1|section)|section-\d+-add-.+\/v1)$/.test(id)?s.bounds['field-menu']:/^template-(?!search$|close$)/.test(id)?s.bounds['template-viewport']:/^(first-problem$|wifi-|totp-|location-|value-|field-(name|handle)-|record-title$|copy-\d+-|reveal-\d+-|large-\d+-)/.test(id)?s.bounds['record-viewport']:null;
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
  if(activate)for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});await delay(150);
 };
 const text=async(id,text)=>{await click(id);for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});if(text)await rpc('Input.insertText',{text});else for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'Backspace',code:'Backspace',windowsVirtualKeyCode:8});await delay(100);};
 const capture=async name=>{const r=await rpc('Page.captureScreenshot',{format:'png'});await writeFile(`${shots}/${viewport[0]}-${name}.png`,Buffer.from(r.data,'base64'));};

 await evaluate(`const oldPost=Worker.prototype.postMessage;window.__validation={saves:0};Worker.prototype.postMessage=function(data,...args){try{let message;if(data[0]===123)message=JSON.parse(new TextDecoder().decode(data));else{const end=4+new DataView(data.buffer,data.byteOffset,4).getUint32(0,true);message=JSON.parse(new TextDecoder().decode(data.subarray(4,end)));}const save=message.command?.Save??message.command?.SaveRevision;if(save){__validation.saves++;__validation.draft=save.draft;}}catch{}return oldPost.call(this,data,...args);};`);
 await rpc('Browser.grantPermissions',{origin:url,permissions:['clipboardReadWrite','clipboardSanitizedWrite']});
 const key=async(name,code,number)=>{for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:name,code,windowsVirtualKeyCode:number});await delay(150);};
 const find=async re=>{const s=await until(s=>Object.keys(s.hits).some(key=>re.test(key)));return Object.keys(s.hits).find(key=>re.test(key));};
 await until(s=>s.screen==='catalog'&&!s.busy);await click('create');await until(s=>s.screen==='create');if((await snapshot()).hits['create-sync'])await click('create-sync');await text('name','Personal');await text('password','public-client-fixture');await text('repeat','public-client-fixture');await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
 await click('new-record');await click('template-wifi');await until(s=>s.editing);await text('record-title','Public validation fixture');
 assert(!(await snapshot()).bounds['record-validation'],'empty starter must remain optional');await click('save');await until(s=>s.hits.edit&&!s.busy);assert.equal((await snapshot()).error,null);
 await click('edit');await text('value-0-text','Public network');await text('value-1-password','short');await until(s=>s.bounds['record-validation']&&!s.hits.save);const before=await evaluate('__validation.saves');assert.equal(before,1);
 for(let i=0;i<6;i++){await click('add-field');await click('add-text/v1');}
 for(let i=0;i<6;i++){await click(`field-handle-${2+i}`);await key('ArrowDown','ArrowDown',40);}
 await until(s=>s.bounds['field-8']);await click('first-problem',false);await capture('summary');await click('first-problem');await delay(500);
 let state=await snapshot();const point=state.hits['field-name-8'],r=state.bounds['record-viewport'];assert(point[1]>=r[1]&&point[1]<=r[3],JSON.stringify({point,r}));await capture('first-problem');
 await text('value-1-password','public-password');await until(s=>s.hits.save&&!s.bounds['record-validation']);
 await click('add-field');await click('add-totp/v1');let secret=await find(/^totp-\d+-secret$/);await text(secret,'bad!');await until(s=>s.bounds['record-validation']&&!s.hits.save);
 await click('first-problem');await capture('totp-problem');await text(secret,'JBSWY3DPEHPK3PXP');await until(s=>s.hits.save&&!s.bounds['record-validation']);
 await click('add-field');await click('add-location/v1');const lat=await find(/^location-\d+-latitude$/),lon=await find(/^location-\d+-longitude$/);await text(lat,'91');await text(lon,'20');await until(s=>s.bounds['record-validation']&&!s.hits.save);
 await click('first-problem');await capture('location-problem');await text(lat,'90');await until(s=>s.hits.save&&!s.bounds['record-validation']);
 assert.equal(await evaluate('__validation.saves'),before,'no invalid draft may reach Save');await click('save');await until(s=>s.hits.edit&&!s.busy);assert.equal((await snapshot()).error,null);const saved=await evaluate('__validation.draft');assert.equal(saved.fields.length,11);assert.equal(saved.fields[0].values.text,'Public network');assert.equal(saved.fields[1].values.password,'public-password');assert.equal(saved.fields[8].type_name,'wifi-qr/v1');assert.equal(saved.fields[8].values.ssid,'0');assert.equal(saved.fields[8].values.password,'1');assert.equal(saved.fields[9].type_name,'totp/v1');assert.equal(saved.fields[10].values.latitude,'90');await capture('saved');
 await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);await click('vault-0');await until(s=>s.screen==='unlock'&&!s.busy);await text('password','public-client-fixture');await click('submit');await until(s=>s.screen==='open'&&!s.busy);await click('record-0');await until(s=>s.hits.edit);await click('copy-0-text');await delay(200);assert.equal(await evaluate('navigator.clipboard.readText()'),'Public network');await click('copy-1-password');await delay(200);assert.equal(await evaluate('navigator.clipboard.readText()'),'public-password');assert(Object.keys((await snapshot()).bounds).some(id=>/^wifi-\d+-code$/.test(id)));
 return {viewport,emptyStarter:true,wifiSaveGuard:true,firstProblemNavigation:true,totpSaveGuard:true,locationSaveGuard:true,correctedDraftSavedAndReopened:true};
},{viewport,windowSize:viewport}));
console.log(JSON.stringify(results,null,2));
