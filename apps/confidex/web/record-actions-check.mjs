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
  const host=s=>/^(?:add-(?:.+\/v1|section)|section-\d+-add-.+\/v1)$/.test(id)?s.bounds['field-menu']:/^template-(?!search$|close$|empty$)/.test(id)?s.bounds['template-viewport']:/^(location-|section-\d+-(?:name|handle|remove|add)$|remove-\d+$|tag-(?!error$)|value-|field-(name|handle)-|record-title$|large-\d+-|copy-\d+-|reveal-\d+-|protected-\d+)/.test(id)?s.bounds['record-viewport']:null;
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
 const observe=async()=>evaluate(`window.__saves=[];const post=Worker.prototype.postMessage;Worker.prototype.postMessage=function(data,...args){try{const end=data[0]===123?0:4+new DataView(data.buffer,data.byteOffset,4).getUint32(0,true);const request=JSON.parse(new TextDecoder().decode(end?data.subarray(4,end):data));const save=request.command?.Save??request.command?.SaveRevision;if(save)__saves.push(structuredClone(save.draft));}catch{}return post.call(this,data,...args);};`);
 const footer=async()=>{const s=await snapshot(),r=s.bounds['record-footer'];for(const id of ['add-field','add-website','add-location','save','cancel-edit']){const point=s.hits[id]??(s.bounds[id]&&[(s.bounds[id][0]+s.bounds[id][2])/2,(s.bounds[id][1]+s.bounds[id][3])/2]);assert(point&&point[0]>=r[0]&&point[0]<=r[2]&&point[1]>=r[1]&&point[1]<=r[3],id);}assert(r[0]>=0&&r[1]>=0&&r[2]<=viewport[0]&&r[3]<=viewport[1]);};
 const visible=(s,id)=>{const point=location(s,id),r=s.bounds['record-viewport'];return point&&r&&point[1]>=r[1]+3&&point[1]<=r[3]-3;};
 const find=async pattern=>{const s=await until(s=>Object.keys(s.hits).some(id=>pattern.test(id)));return Object.keys(s.hits).find(id=>pattern.test(id));};
 await rpc('Browser.grantPermissions',{origin:url,permissions:['clipboardReadWrite','clipboardSanitizedWrite']});await rpc('Page.enable');await rpc('Page.addScriptToEvaluateOnNewDocument',{source:`Object.defineProperty(navigator,'languages',{get:()=>['${language}']});`});await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);await observe();
 await click('create');await until(s=>s.screen==='create');if((await snapshot()).hits['create-sync'])await click('create-sync');await text('name','Public action fixture');await text('password','public-action-fixture');await text('repeat','public-action-fixture');await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
 await click('new-record');await click('template-login');await text('record-title','Public actions');await text('value-0-username','public@example.test');await text('value-1-password','public-password-fixture');await text('value-2-url','https://example.test');await text('value-3-text','Public original note');await text('tag-input','Public baseline');await key('Enter','Enter',13);await click('save');await until(s=>s.hits.edit&&!s.busy);
 assert.equal(await evaluate('confidex.has_unsaved_changes()'),false);
 await click('edit');await click('save');await until(s=>s.hits.edit&&!s.busy);const baseline=await evaluate('__saves.at(-1)');assert(baseline.fields.every(f=>f.source!==null));await click('edit');await footer();await capture('actions');
 assert.equal(await evaluate('confidex.has_unsaved_changes()'),false);await text('tag-input','Public pending');assert.equal(await evaluate('confidex.has_unsaved_changes()'),true);
 await click('lock');await until(s=>s.hits['exit-confirm']);await capture('unsaved-lock');await click('exit-cancel');await until(s=>s.editing&&!s.hits['exit-confirm']);assert.equal(await evaluate('confidex.has_unsaved_changes()'),true);
 const reload=rpc('Page.reload');await delay(350);await rpc('Page.handleJavaScriptDialog',{accept:false});await reload;await until(s=>s.editing&&!s.busy);assert.equal(await evaluate('confidex.has_unsaved_changes()'),true);
 await text('tag-input','');assert.equal(await evaluate('confidex.has_unsaved_changes()'),false);
 const savedCount=await evaluate('__saves.length');await click('add-website');await until(s=>visible(s,'value-4-url'));await rpc('Input.insertText',{text:'https://second.example.test'});await delay(150);assert.equal(await evaluate('__saves.length'),savedCount);await capture('website-focused');
 await click('add-website');await until(s=>visible(s,'value-5-url'));await rpc('Input.insertText',{text:'https://third.example.test'});await delay(150);
 await click('add-location');const name=await find(/^location-\d+-name$/);await until(s=>visible(s,name));await rpc('Input.insertText',{text:'Public office'});await text(await find(/^location-\d+-latitude$/),'52.1');await text(await find(/^location-\d+-longitude$/),'4.3');await footer();await capture('location-focused');
 await text('tag-input','Public baseline');await until(s=>s.bounds['tag-error']&&!s.hits.save);await footer();const invalid=await snapshot();assert(invalid.bounds['tag-error'][1]>Math.max(...['add-field','add-website','add-location','cancel-edit'].map(id=>invalid.hits[id][1])));await capture('error-below-actions');await text('tag-input','');await until(s=>s.hits.save);
 await click('save');await until(s=>s.hits.edit&&!s.busy);const saved=await evaluate('__saves.at(-1)');assert.equal(saved.fields.length,7);assert.deepEqual(saved.fields.slice(0,4),baseline.fields);assert.deepEqual(saved.sections,baseline.sections);assert.deepEqual(saved.tags,['Login','Public baseline']);assert.deepEqual(saved.fields.slice(4).map(f=>f.type_name),['url/v1','url/v1','location/v1']);assert.equal(saved.fields[4].values.url,'https://second.example.test');assert.equal(saved.fields[5].values.url,'https://third.example.test');assert.deepEqual(saved.fields[6].values,{name:'Public office',latitude:'52.1',longitude:'4.3'});
 assert.equal(await evaluate('confidex.has_unsaved_changes()'),false);
 await click('edit');const committed=await evaluate('__saves.length');await click('add-website');await until(s=>visible(s,'value-7-url'));await rpc('Input.insertText',{text:'https://discard.example.test'});await click('cancel-edit');await until(s=>s.hits.edit&&!s.busy);assert.equal(await evaluate('__saves.length'),committed);assert(!(await snapshot()).bounds['field-7']);await capture('cancelled');
 await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);await click('vault-0');await until(s=>s.screen==='unlock'&&!s.busy);await text('password','public-action-fixture');await click('submit');await until(s=>s.screen==='open'&&!s.busy);await click('record-0');await until(s=>s.hits.edit&&!s.busy);assert(!(await snapshot()).bounds['field-7']);
 const copy=async(id,value)=>{const before=(await snapshot()).copied;await click(id);await until(s=>s.copied>before);assert.equal(await evaluate('navigator.clipboard.readText()'),value);};await copy('copy-4-url','https://second.example.test');await copy('copy-5-url','https://third.example.test');await copy('copy-6-name','Public office');await copy('copy-3-text','Public original note');await capture('reloaded');
 await click('edit');assert.equal(await evaluate('confidex.has_unsaved_changes()'),false);await text('record-title','Public unsaved change');await click('lock');await until(s=>s.hits['exit-confirm']);await click('exit-confirm');await until(s=>s.screen!=='open'&&!s.busy);assert.equal(await evaluate('confidex.has_unsaved_changes()'),false);
 return {language,viewport,repeatedWebsites:true,location:true,automaticFocusAndScroll:true,noImplicitSave:true,sourceAndSectionsKept:true,errorAfterActions:true,cancel:true,encryptedSaveReload:true,unsavedLockCancelAndConfirm:true,pendingTagProtected:true,browserUnloadCancel:true,unchangedDraftIsClean:true};
},{viewport,windowSize:viewport}));
await writeFile(`${shots}/results.json`,JSON.stringify(results,null,2));console.log(JSON.stringify(results,null,2));
