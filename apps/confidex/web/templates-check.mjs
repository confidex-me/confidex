import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,directory,shots]=process.argv.slice(2);assert(chrome&&directory&&shots,'provide Chrome, WASM bundle and screenshots paths');await mkdir(shots,{recursive:true});
const contract=JSON.parse(await readFile(new URL('../../../crates/confidex-app/tests/fixtures/starter-catalog.json',import.meta.url),'utf8'));
const templates=contract.map(template=>({...template,fields:template.fields.map(([name,type,section])=>({name,type,section}))}));assert.equal(templates.length,22);
const slug=name=>name.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean).join('-');
const sample=(type,index)=>{
 const key={'text/v1':'text','note/v1':'text','secure-note/v1':'text','username/v1':'username','password/v1':'password','secret/v1':'secret','url/v1':'url','date/v1':'date','month-year/v1':'date'}[type];
 if(!key)return null;
 return {key,value:type==='date/v1'?'29/02/2024':type==='month-year/v1'?'02/2024':type==='url/v1'?`https://example.test/${index}`:type==='password/v1'?`Public-${index}-fixture`:`Public ${index} café`};
};
const runs=['en-US','ru'].flatMap(language=>[[1180,1000],[390,1000]].map(viewport=>({language,viewport})));
const settled=await Promise.allSettled(runs.map(async({language,viewport})=>runBrowser(chrome,await assets(directory),async({command,evaluate,url})=>{
 const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
 const snapshot=()=>evaluate('window.confidex?.snapshot()');
 const until=async p=>{const deadline=Date.now()+25000;for(;;){const s=await snapshot();if(s&&await p(s))return s;assert(Date.now()<deadline,JSON.stringify(s));await delay(50);}};
 const location=(s,id)=>s.hits[id]??(s.bounds[id]&&[(s.bounds[id][0]+s.bounds[id][2])/2,(s.bounds[id][1]+s.bounds[id][3])/2]);
 const click=async(id,activate=true)=>{
  let state=await until(s=>location(s,id));
  const host=s=>/^template-(?!search$|close$|empty$)/.test(id)?s.bounds['template-viewport']:/^(date-|value-|field-(name|handle)-|record-title$|large-\d+-|copy-\d+-|reveal-\d+-|protected-\d+)/.test(id)?s.bounds['record-viewport']:null;
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
 const source=await readFile(new URL(`../../../crates/confidex-ui/locales/${language}.ftl`,import.meta.url),'utf8');const messages=new Map([...source.matchAll(/^([\w-]+) = (.+)$/gm)].map(([,key,value])=>[key,value]));
 const label=key=>{assert(messages.has(key),key);const value=messages.get(key),ref=value.match(/^\{ ([\w-]+) \}$/);return ref?label(ref[1]):value;};
 await evaluate(`window.__catalogue={saves:0};const post=Worker.prototype.postMessage;Worker.prototype.postMessage=function(data,...args){try{let message;if(data[0]===123)message=JSON.parse(new TextDecoder().decode(data));else{const end=4+new DataView(data.buffer,data.byteOffset,4).getUint32(0,true);message=JSON.parse(new TextDecoder().decode(data.subarray(4,end)));}if(message.command?.Search)__catalogue.search=message.command.Search.query;const save=message.command?.Save??message.command?.SaveRevision;if(save){__catalogue.saves++;__catalogue.draft=save.draft;}}catch{}return post.call(this,data,...args);};`);
 await rpc('Browser.grantPermissions',{origin:url,permissions:['clipboardReadWrite','clipboardSanitizedWrite']});
 const key=async(name,code,number)=>{for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:name,code,windowsVirtualKeyCode:number});await delay(100);};
 const newRecord=async()=>{if(!(await snapshot()).hits['new-record'])await click('back');await click('new-record');await until(s=>s.hits['template-login']);};
 await click('create');await until(s=>s.screen==='create');if((await snapshot()).hits['create-sync'])await click('create-sync');await text('name','Public catalogue');await text('password','public-catalogue-fixture');await text('repeat','public-catalogue-fixture');await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
 await newRecord();await capture('catalogue-top');let state=await snapshot();assert(state.bounds['template-caption'][3]<=state.bounds['template-body'][3]+1,'caption clipped');
 const featured=['login','secure-note','credit-card','identity','api-key','document'].map(id=>state.hits[`template-${id}`]);if(viewport[0]>600){assert(Math.abs(featured[0][1]-featured[1][1])<1);assert(Math.abs(featured[1][1]-featured[2][1])<1);assert(featured[3][1]>featured[0][1]);}else assert(featured.every((r,i)=>i===0||r[1]>featured[i-1][1]));
 await click('template-wireless-router',false);const list=(await snapshot()).bounds['template-viewport'];await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',x:list[0]+4,y:(list[1]+list[3])/2,deltaX:0,deltaY:10000});await delay(350);await capture('catalogue-last');await text('template-search','no matching template');await until(s=>!s.hits['template-login']&&s.hits['template-empty']);await capture('no-results');await key('Enter','Enter',13);assert(!(await snapshot()).editing);await click('template-close');
 await newRecord();await text('template-search','API');await key('Enter','Enter',13);await until(s=>s.editing&&s.hits['value-0-username']&&s.hits['value-1-secret']);await click('cancel-edit');assert.equal((await snapshot()).rows,0);
 const checkDraft=(draft,template)=>{
  assert.deepEqual(draft.tags,[template.name],template.id+' tag');
  assert.equal(draft.fields.length,template.fields.length,template.id);
  for(let i=0;i<template.fields.length;i++){const expected=template.fields[i],field=draft.fields[i];assert.equal(field.type_name,expected.type,`${template.id} ${i}`);assert.equal(field.name,label(`starter-${slug(expected.name)}`),`${language} ${template.id} ${i}`);const value=sample(expected.type,i);if(value)assert.equal(field.values[value.key],value.value,`${template.id} ${i} value`);if(['secret/v1','secure-note/v1','photo/v1','file/v1','ssh/v1'].includes(expected.type))assert(field.protected,`${template.id} ${i} protected`);}
  const sections=[];for(let i=0;i<template.fields.length;i++){const name=template.fields[i].section;if(!name)continue;const last=sections.at(-1);if(last&&last.name===label(`starter-${slug(name)}`)&&last.start+last.count===i)last.count++;else sections.push({name:label(`starter-${slug(name)}`),start:i,count:1});}
  assert.deepEqual(draft.sections.map(({name,start,count})=>({name,start,count})),sections,template.id);
  if(template.id==='wireless-router'){assert.equal(draft.fields[5].values.ssid,'4');assert.equal(draft.fields[5].values.password,'6');}
 };
 const saved=[];
 for(const [index,template] of templates.entries()){
  await newRecord();await text('template-search',template.id.replaceAll('-',' '));await click(`template-${template.id}`);await until(s=>s.editing&&s.bounds.save&&s.bounds['title-error']);let initial=await snapshot();assert(!initial.hits.save,template.id+' requires title');assert(initial.bounds['title-error'][1]>=initial.bounds['cancel-edit'][3]);
  if(index===0){await text('record-title',' \u2003\u3000 ');await click('save');assert.equal(await evaluate('__catalogue.saves'),0);assert((await snapshot()).bounds['title-error']);await capture('required-title');}
  const marker=`catalogue${String.fromCharCode(97+index)}proof`;await text('record-title',marker);await until(s=>s.hits.save&&!s.bounds['title-error']);
  await capture(`editor-${template.id}`);
  for(const [i,field]of template.fields.entries()){
   const value=sample(field.type,i);if(!value)continue;
   if(['secure-note/v1','secret/v1'].includes(field.type)&&(await snapshot()).hits[`reveal-${i}-${value.key}`])await click(`reveal-${i}-${value.key}`);
   let input=`value-${i}-${value.key}`;
   if(value.key==='date'){
    const s=await snapshot(),r=s.bounds[`field-${i}`];assert(r,`${template.id} ${i} bounds`);
    input=Object.keys(s.hits).find(id=>/^date-\d+-input$/.test(id)&&s.hits[id][1]>=r[1]&&s.hits[id][1]<=r[3]);assert(input,`${template.id} ${i} date input`);
   }
   await text(input,value.value);
  }
  const footer=(await snapshot()).bounds['record-footer'];assert(footer&&footer[0]>=0&&footer[2]<=viewport[0]&&footer[3]<=viewport[1],template.id+' footer');
  await click('save');await until(s=>s.hits.edit&&!s.busy);assert.equal((await snapshot()).error,null,template.id);const draft=await evaluate('__catalogue.draft');
  try{assert.equal(draft.title,marker);checkDraft(draft,template);}catch(error){await capture(`failed-${template.id}`);await writeFile(`${shots}/${language}-${viewport[0]}-failed-${template.id}.json`,JSON.stringify({draft,state:await snapshot()},null,2));throw error;}
  saved.push({template,marker});
 }
 assert.equal(await evaluate('__catalogue.saves'),22);
 await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);await click('vault-0');await until(s=>s.screen==='unlock'&&!s.busy);await text('password','public-catalogue-fixture');await click('submit');await until(s=>s.screen==='open'&&!s.busy);
 await evaluate(`window.__catalogue={saves:0};const post=Worker.prototype.postMessage;Worker.prototype.postMessage=function(data,...args){try{let message;if(data[0]===123)message=JSON.parse(new TextDecoder().decode(data));else{const end=4+new DataView(data.buffer,data.byteOffset,4).getUint32(0,true);message=JSON.parse(new TextDecoder().decode(data.subarray(4,end)));}if(message.command?.Search)__catalogue.search=message.command.Search.query;const save=message.command?.Save??message.command?.SaveRevision;if(save){__catalogue.saves++;__catalogue.draft=save.draft;}}catch{}return post.call(this,data,...args);};`);
 for(const [index,{template,marker}] of saved.entries()){
  if(!(await snapshot()).hits.search)await click('back');await text('search',marker);await until(async s=>s.rows===1&&!s.busy&&await evaluate('__catalogue.search')===marker);await click('record-0');await until(s=>s.hits.edit&&!s.busy);await click('edit');await until(s=>s.editing&&s.hits.save);await click('save');await until(async s=>s.hits.edit&&!s.busy&&await evaluate('__catalogue.saves')===index+1);const draft=await evaluate('__catalogue.draft');assert.equal(draft.title,marker);checkDraft(draft,template);assert(draft.fields.every(field=>field.source!==null));
 }
 await click('edit');await text('record-title','');await until(s=>s.bounds['title-error']&&!s.hits.save);await click('save');assert.equal(await evaluate('__catalogue.saves'),22);await click('cancel-edit');await until(s=>s.hits.edit&&!s.busy);
 return {language,viewport,templates:templates.length,created:22,reopenedAndSaved:await evaluate('__catalogue.saves'),englishTemplateTags:true,titleRequired:true,localizedFieldsAndSections:true,searchKeyboardCancel:true};
},{viewport,windowSize:viewport})));
const failures=settled.flatMap((result,index)=>result.status==='rejected'?[{...runs[index],message:result.reason.message,stack:result.reason.stack}]:[]);if(failures.length){await writeFile(`${shots}/failures.json`,JSON.stringify(failures,null,2));throw new AggregateError(failures.map(f=>Error(`${f.language} ${f.viewport}: ${f.message}`)),'template checks failed');}const results=settled.map(result=>result.value);
await writeFile(`${shots}/results.json`,JSON.stringify(results,null,2));
console.log(JSON.stringify(results,null,2));
