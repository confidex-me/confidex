import assert from 'node:assert/strict';
import {mkdir,writeFile,open} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {resolve} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,directory,shots,image]=process.argv.slice(2);assert(chrome&&directory&&shots&&image);await mkdir(shots,{recursive:true});const results=[];
const license=resolve(shots,'public-license.txt'),noise=resolve(shots,'public-noise.bin'),large=resolve(shots,'public-large.bin'),largeSsh=resolve(shots,'public-large-ssh.bin');
await writeFile(license,'Public license fixture licensebodyproof');await writeFile(noise,randomBytes(4100000));await writeFile(largeSsh,Buffer.alloc(65537,42));const sparse=await open(large,'w');await sparse.truncate(65*1024*1024);await sparse.close();
const cancelled=resolve(shots,'public-cancelled-license.txt');await writeFile(cancelled,'Cancelled public replacement');
const sshFile=new URL('../../../crates/confidex-ui/tests/fixtures/public-ssh-key.pem',import.meta.url).pathname;

for(const language of ['en-US','ru-RU'])for(const viewport of [[1180,1000],[390,1000]])results.push(await runBrowser(chrome,await assets(directory),async({command,evaluate,url})=>{
 const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
 const snapshot=()=>evaluate('window.confidex?.snapshot()');
 const until=async p=>{const deadline=Date.now()+25000;for(;;){const s=await snapshot();if(s&&p(s))return s;assert(Date.now()<deadline,JSON.stringify(s));await delay(50);}};
 const location=(s,id)=>s.hits[id]??(s.bounds[id]&&[(s.bounds[id][0]+s.bounds[id][2])/2,(s.bounds[id][1]+s.bounds[id][3])/2]);
 const click=async(id,activate=true)=>{
  let state=await until(s=>location(s,id));
  const host=s=>/^(?:add-(?:.+\/v1|section)|section-\d+-add-.+\/v1)$/.test(id)?s.bounds['field-menu']:/^template-(?!search$|close$|empty$)/.test(id)?s.bounds['template-viewport']:/^(file-drop-|file-\d+-|photo-\d+-|ssh-|field-\d+$|section-\d+-(?:name|handle|remove|add)$|remove-\d+$|tag-(?!error$)|value-|field-(name|handle)-|record-title$|large-\d+-|copy-\d+-|reveal-\d+-|protected-\d+)/.test(id)?s.bounds['record-viewport']:null;
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
 const find=async pattern=>{const s=await until(s=>Object.keys(s.hits).some(id=>pattern.test(id)));return Object.keys(s.hits).find(id=>pattern.test(id));};
 const key=async(name,code,number)=>{for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:name,code,windowsVirtualKeyCode:number});await delay(150);};
 await rpc('Browser.setDownloadBehavior',{behavior:'deny'});await rpc('Browser.grantPermissions',{origin:url,permissions:['clipboardReadWrite','clipboardSanitizedWrite']});
 await rpc('Page.enable');await rpc('Page.addScriptToEvaluateOnNewDocument',{source:`Object.defineProperty(navigator,'languages',{get:()=>['${language}']});`});await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);
 await click('create');await until(s=>s.screen==='create');if((await snapshot()).hits['create-sync'])await click('create-sync');await text('name','Public drop fixture');await text('password','public-drop-fixture');await text('repeat','public-drop-fixture');await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
 await evaluate(`window.__dropProof={reads:0,checks:0,errors:[],downloads:[]};const read=File.prototype.arrayBuffer;File.prototype.arrayBuffer=function(){__dropProof.reads++;return read.call(this);};const create=URL.createObjectURL;URL.createObjectURL=function(blob){if(blob instanceof Blob)blob.arrayBuffer().then(bytes=>__dropProof.downloads.push(new TextDecoder().decode(bytes)));return create.call(this,blob);};const post=Worker.prototype.postMessage,seen=new WeakSet();Worker.prototype.postMessage=function(data,...args){try{if(!seen.has(this)){seen.add(this);const receive=this.onmessage;this.onmessage=function(event){try{const data=event.data,start=data[0]===123?0:4+new DataView(data.buffer,data.byteOffset,4).getUint32(0,true);const reply=JSON.parse(new TextDecoder().decode(start?data.subarray(4,start):data));if(reply.result?.Err)__dropProof.errors.push(reply.result.Err);}catch{}receive?.call(this,event);};}const offset=data[0]===123?0:4+new DataView(data.buffer,data.byteOffset,4).getUint32(0,true);const m=JSON.parse(new TextDecoder().decode(offset?data.subarray(4,offset):data));if(m.command?.CheckDraft)__dropProof.checks++;}catch{}return post.call(this,data,...args);};`);
 const proof=()=>evaluate('__dropProof');
 const waitProof=async predicate=>{const deadline=Date.now()+25000;for(;;){const value=await proof();if(predicate(value))return value;assert(Date.now()<deadline,JSON.stringify(value));await delay(50);}};
 const position=async index=>{await click('field-'+index,false);const s=await until(s=>s.bounds['file-drop-'+index]);const r=s.bounds['file-drop-'+index];return {x:(r[0]+r[2])/2,y:(r[1]+r[3])/2};};
 const drop=async(files,point,shot)=>{const data={items:[],files:files.map(file=>resolve(file)),dragOperationsMask:1};await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x:2,y:2});for(const type of ['dragEnter','dragOver'])await rpc('Input.dispatchDragEvent',{type,...point,data});await delay(200);if(shot)await capture(shot);await rpc('Input.dispatchDragEvent',{type:'drop',...point,data});await delay(250);};
 await click('new-record');await click('template-document');await text('record-title','Public drop fixture');await text('value-1-text','Public document note');await capture('empty-document');
 await drop([license],{x:viewport[0]-2,y:2});assert.equal((await proof()).reads,0);
 await drop([license,noise],await position(0));assert.equal((await proof()).reads,0);await capture('multiple-rejected');
 await drop([large],await position(0));assert.equal((await proof()).reads,0);assert.equal((await proof()).checks,0);await capture('source-limit');
 await drop([license],await position(0),'file-hover');await waitProof(p=>p.checks>0);await find(/^file-\d+-save$/);await capture('file-added');
 await drop([noise],await position(0));await waitProof(p=>p.errors.some(e=>JSON.stringify(e).includes('RecordLimit')));await capture('record-limit');
 const savedFile=await find(/^file-\d+-save$/);const count=(await proof()).downloads.length;await click(savedFile);await waitProof(p=>p.downloads.length>count);assert.equal((await proof()).downloads.at(-1),'Public license fixture licensebodyproof');
 await click('add-field');await click('add-photo/v1');await drop([image],await position(2),'photo-hover');await until(s=>s.hits['photo-apply']);await capture('photo-import');await click('photo-cancel');await until(s=>s.hits.save);assert(!Object.keys((await snapshot()).hits).some(id=>/^photo-\d+-reveal$/.test(id)));
 await drop([image],await position(2));await until(s=>s.hits['photo-apply']);await click('photo-apply');await find(/^photo-\d+-reveal$/);await until(s=>s.hits.save&&!s.busy);await capture('photo-added');
 await click('add-field');await click('add-ssh/v1');const reads=(await proof()).reads;await drop([largeSsh],await position(3));const notice=await until(s=>Object.keys(s.bounds).some(id=>/^ssh-\d+-notice$/.test(id)));assert.equal((await proof()).reads,reads);let prefix=Object.keys(notice.bounds).find(id=>/^ssh-\d+-notice$/.test(id)).replace(/-notice$/,'');await capture('ssh-limit');await click(prefix+'-action-2');await until(s=>s.hits.save);
 await drop([sshFile],await position(3),'ssh-hover');const password=await find(/^ssh-\d+-password$/);prefix=password.replace(/-password$/,'');await text(password,'wrong');await click(prefix+'-action-1');await until(s=>s.hits[prefix+'-action-1']);await text(password,'public-fixture-passphrase');await click(prefix+'-action-1');await until(s=>s.hits.save&&!s.busy&&s.hits['value-3-fingerprint']);await capture('ssh-added');
 await click('save');await until(s=>s.hits.edit&&!s.busy);await capture('saved');const ignoredReads=(await proof()).reads;await drop([license],{x:viewport[0]-80,y:250});assert.equal((await proof()).reads,ignoredReads);assert(!(await snapshot()).editing);
 await click('edit');await evaluate(`const original=File.prototype.arrayBuffer;window.__readBeforeCancel=original;File.prototype.arrayBuffer=function(){if(this.name!=='public-cancelled-license.txt')return original.call(this);return new Promise((resolve,reject)=>{window.__resumeDrop=()=>original.call(this).then(resolve,reject);});};`);
 await drop([cancelled],await position(0));assert(await evaluate('typeof __resumeDrop==="function"'));await click('cancel-edit');await until(s=>s.hits.edit&&!s.busy);await evaluate('__resumeDrop();File.prototype.arrayBuffer=__readBeforeCancel');await delay(400);assert(!(await snapshot()).editing);const downloads=(await proof()).downloads.length;await click(await find(/^file-\d+-save$/));await waitProof(p=>p.downloads.length>downloads);assert.equal((await proof()).downloads.at(-1),'Public license fixture licensebodyproof');await capture('late-drop-cancelled');
 await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);await click('vault-0');await until(s=>s.screen==='unlock'&&!s.busy);await text('password','public-drop-fixture');await click('submit');await until(s=>s.screen==='open'&&!s.busy);await click('record-0');await until(s=>s.hits.edit);await capture('reloaded');assert(Object.keys((await snapshot()).hits).some(id=>/^file-\d+-save$/.test(id)));assert(Object.keys((await snapshot()).hits).some(id=>/^photo-\d+-reveal$/.test(id)));assert((await snapshot()).hits['value-3-fingerprint']);
 await evaluate(`window.__reloadedFile=[];const create=URL.createObjectURL;URL.createObjectURL=function(blob){if(blob instanceof Blob)blob.arrayBuffer().then(bytes=>__reloadedFile.push(new TextDecoder().decode(bytes)));return create.call(this,blob);};`);await click(await find(/^file-\d+-save$/));for(let n=0;!(await evaluate('__reloadedFile.length'));n++){assert(n<100);await delay(50);}assert.equal(await evaluate('__reloadedFile.at(-1)'),'Public license fixture licensebodyproof');
 const copied=(await snapshot()).copied;await click('copy-1-text');await until(s=>s.copied>copied);assert.equal(await evaluate('navigator.clipboard.readText()'),'Public document note');
 await click(await find(/^photo-\d+-reveal$/));await until(s=>s.bounds['photo-viewer']);await delay(600);await capture('reloaded-photo-viewer');await click('photo-viewer-close');await until(s=>!s.bounds['photo-viewer']);
 const before=(await snapshot()).copied;await click('copy-3-fingerprint');await until(s=>s.copied>before);assert.equal(await evaluate('navigator.clipboard.readText()'),'SHA256:2qK+2sSbXCzJHgO05gCz4xAdNqqtzCiM7ZiwlTuMTQ8');
 return {language,viewport,externalPositionBridge:true,outsideAndReadonlyIgnored:true,multipleRejectedWithoutRead:true,sourceLimitsBeforeRead:true,wholeRecordLimitPreservesFile:true,photoCancelAndApply:true,encryptedSshPassphrase:true,lateDropCancel:true,noteAndFileBytesPreserved:true,photoViewerAfterReload:true,sshFingerprintAfterReload:true,saveReload:true};
},{viewport,windowSize:viewport}));
await writeFile(`${shots}/results.json`,JSON.stringify(results,null,2));console.log(JSON.stringify(results,null,2));
