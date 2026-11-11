import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,directory,shots]=process.argv.slice(2);assert(chrome&&directory&&shots);await mkdir(shots,{recursive:true});const results=[];
for(const language of ['en-US','ru-RU'])for(const viewport of [[1180,1000],[390,1000]])results.push(await runBrowser(chrome,await assets(directory),async({command,evaluate,url})=>{
 const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
 const snapshot=()=>evaluate('window.confidex?.snapshot()');
 const until=async p=>{const deadline=Date.now()+25000;for(;;){const s=await snapshot();if(s&&p(s))return s;assert(Date.now()<deadline,JSON.stringify(s));await delay(50);}};
 const location=(s,id)=>s.hits[id]??(s.bounds[id]&&[(s.bounds[id][0]+s.bounds[id][2])/2,(s.bounds[id][1]+s.bounds[id][3])/2]);
 const click=async(id,activate=true)=>{
  let state=await until(s=>location(s,id));
  const host=s=>/^(?:add-(?:.+\/v1|section)|section-\d+-add-.+\/v1)$/.test(id)?s.bounds['field-menu']:/^template-(?!search$|close$|empty$)/.test(id)?s.bounds['template-viewport']:/^(section-\d+-(?:name|handle|remove|add)$|remove-\d+$|tag-(?!error$)|value-|field-(name|handle)-|record-title$|large-\d+-|copy-\d+-|reveal-\d+-|protected-\d+)/.test(id)?s.bounds['record-viewport']:null;
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
 const key=async(name,code,number)=>{for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:name,code,windowsVirtualKeyCode:number});await delay(150);};
 const geometry=async button=>{await delay(250);const s=await snapshot(),r=s.bounds['field-menu'],[x,y]=s.hits[button];assert(r,'menu is closed');assert(r[0]>=0&&r[1]>=0&&r[2]<=viewport[0]&&r[3]<=viewport[1]);assert(Math.abs((r[0]+r[2])/2-x)<=16,JSON.stringify({r,button:[x,y]}));assert(r[3]-r[1]<=220);assert(r[3]<y||r[1]>y);return r;};
 await rpc('Page.enable');await rpc('Page.addScriptToEvaluateOnNewDocument',{source:`Object.defineProperty(navigator,'languages',{get:()=>['${language}']});`});await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);
 await click('create');await until(s=>s.screen==='create');if((await snapshot()).hits['create-sync'])await click('create-sync');await text('name','Public field menu');await text('password','public-menu-fixture');await text('repeat','public-menu-fixture');await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
 await click('new-record');await click('template-empty');await text('record-title','Public field menu');
 await click('add-field');await geometry('add-field');await capture('footer-menu');await key('Escape','Escape',27);assert(!(await snapshot()).bounds['field-menu']);
 await click('add-field');await click('add-section');await text('section-0-name','Section');await click('section-0-add');await geometry('section-0-add');await capture('section-menu');
 await click('section-0-add-note/v1');await text('value-0-text','Public note fixture');assert(!(await snapshot()).bounds['field-menu']);
 await click('add-field');await geometry('add-field');await click('add-ssh/v1');await until(s=>s.bounds['field-1']);assert(!(await snapshot()).bounds['field-menu']);
 await click('remove-1');await click('section-0-add');await geometry('section-0-add');await capture('section-note-menu');
 // A click outside the menu keeps the draft and closes the menu.
 await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x:viewport[0]-8,y:120});for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x:viewport[0]-8,y:120,button:'left',clickCount:1});await until(s=>!s.bounds['field-menu']);
 await click('section-0-add');await geometry('section-0-add');
 const smaller=[viewport[0]===1180?1040:360,780];await rpc('Emulation.setDeviceMetricsOverride',{width:smaller[0],height:smaller[1],deviceScaleFactor:1,mobile:false});await delay(350);
 let resized=await snapshot();assert(resized.bounds['field-menu']);assert(resized.bounds['field-menu'][2]<=smaller[0]&&resized.bounds['field-menu'][3]<=smaller[1]);await capture('resized-menu');
 await rpc('Emulation.setDeviceMetricsOverride',{width:viewport[0],height:viewport[1],deviceScaleFactor:1,mobile:false});await delay(350);await geometry('section-0-add');await click('section-0-add-ssh/v1');await until(s=>s.bounds['field-1']);assert(!(await snapshot()).bounds['field-menu']);await capture('selected');
 await click('remove-1');
 for(let i=1;i<=3;i++){await click('section-0-add');await click('section-0-add-note/v1');}
 await click('section-0-add');await geometry('section-0-add');await capture('scrolled-section-menu');
 const oldY=(await snapshot()).hits['section-0-add'][1],r=(await snapshot()).bounds['record-viewport'];
 await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x:r[0]+1,y:r[1]+20});await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',x:r[0]+1,y:r[1]+20,deltaX:0,deltaY:100});await delay(350);await geometry('section-0-add');assert((await snapshot()).hits['section-0-add'][1]<oldY-5,'form did not scroll under the open menu');
 await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',x:r[0]+1,y:r[1]+20,deltaX:0,deltaY:-5000});await delay(400);await until(s=>!s.bounds['field-menu']);
 assert((await snapshot()).editing,'scrolling away changed the draft');
 for(const i of [3,2,1])await click('remove-'+i);
 await click('save');await until(s=>s.hits.edit&&!s.busy);await capture('saved');
 return {language,viewport,buttonAnchors:true,boundedMenus:true,lastTypeReachable:true,resizeAndFormScroll:true,hiddenAnchorCloses:true,escapeAndOutside:true,sectionAndFooterInsert:true,saved:true};
},{viewport,windowSize:viewport}));
await writeFile(`${shots}/results.json`,JSON.stringify(results,null,2));console.log(JSON.stringify(results,null,2));
