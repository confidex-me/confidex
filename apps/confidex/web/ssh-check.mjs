import assert from 'node:assert/strict';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,directory,shots]=process.argv.slice(2);assert(chrome&&directory&&shots,'provide Chrome, WASM bundle and screenshots paths');await mkdir(shots,{recursive:true});const results=[];const oversized=resolve(shots,'oversized-ssh.bin');await writeFile(oversized,Buffer.alloc(65537,42));const keyFile=new URL('../../../crates/confidex-ui/tests/fixtures/public-ssh-key.pem',import.meta.url).pathname;const source=await readFile(new URL('../../../crates/confidex-ui/tests/fixtures/public-ssh-key.pem',import.meta.url),'utf8');
for(const viewport of [[1180,1000],[390,1000]])results.push(await runBrowser(chrome,await assets(directory),async({command,evaluate,url})=>{
 const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
 const snapshot=()=>evaluate('window.confidex?.snapshot()');
 const until=async p=>{const deadline=Date.now()+25000;for(;;){const s=await snapshot();if(s&&p(s))return s;assert(Date.now()<deadline,JSON.stringify(s));await delay(50);}};
 const click=async id=>{
  let state=await until(s=>s.hits[id]);
  const host=s=>/^(?:add-(?:.+\/v1|section)|section-\d+-add-.+\/v1)$/.test(id)?s.bounds['field-menu']:/^template-(?!search$|close$)/.test(id)?s.bounds['template-viewport']:/^(ssh-|value-|field-(name|handle)-|record-title$|copy-\d+-|reveal-\d+-|large-\d+-)/.test(id)?s.bounds['record-viewport']:null;
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

 await evaluate("window.__sshProof={requests:[]};const oldPost=Worker.prototype.postMessage;Worker.prototype.postMessage=function(data,...args){try{const off=4+new DataView(data.buffer,data.byteOffset,4).getUint32(0,true);const value=JSON.parse(new TextDecoder().decode(data.subarray(4,off)));if(value.command?.ImportSsh){const bytes=data.subarray(off);__sshProof.requests.push({length:bytes.length,lines:bytes.filter(x=>x===10).length});}}catch{}return oldPost.call(this,data,...args);};");
 await rpc('Browser.grantPermissions',{origin:url,permissions:['clipboardReadWrite','clipboardSanitizedWrite']});
 await until(s=>s.screen==='catalog'&&!s.busy);await delay(250);await click('create');await until(s=>s.screen==='create');if((await snapshot()).hits['create-sync'])await click('create-sync');await text('name','Personal');await text('password','public-client-fixture');await text('repeat','public-client-fixture');await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
 const key=async(name,code,number)=>{for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:name,code,windowsVirtualKeyCode:number});await delay(150);};

 await click('new-record');await click('template-empty');await until(s=>s.editing);
 await text('record-title','Public SSH fixture');await click('add-field');await click('add-ssh/v1');
 const find=async re=>{const s=await until(s=>Object.keys(s.hits).some(key=>re.test(key)));return Object.keys(s.hits).find(key=>re.test(key));};
 const importId=await find(/^ssh-\d+-import$/);let prefix=importId.slice(0,-7);
 await click(importId);assert(!(await snapshot()).hits.save);
 await click(`${prefix}-source`);await evaluate(`(() => {const data=new DataTransfer();data.setData('text/plain',${JSON.stringify(source)});document.activeElement.dispatchEvent(new ClipboardEvent('paste',{clipboardData:data,bubbles:true,cancelable:true}));})()`);await delay(200);await click(`${prefix}-action-1`);await delay(500);const posted=await evaluate('window.__sshProof.requests.at(-1)');assert.equal(posted.length,Buffer.byteLength(source));assert.equal(posted.lines,source.split('\n').length-1);
 await find(/^ssh-\d+-password$/);await text(`${prefix}-password`,'wrong');await click(`${prefix}-action-1`);
 await until(s=>s.hits[`${prefix}-action-1`]);assert(!(await snapshot()).hits.save);
 await text(`${prefix}-password`,'public-fixture-passphrase');await click(`${prefix}-action-1`);
 await until(s=>s.hits.save&&!s.busy&&s.hits['value-0-fingerprint']);
 const copy=async name=>{const before=(await snapshot()).copied;await click(`copy-0-${name}`);await until(s=>s.copied===before+1);return evaluate('navigator.clipboard.readText()');};
 const fingerprint=await copy('fingerprint');assert.equal(fingerprint,'SHA256:2qK+2sSbXCzJHgO05gCz4xAdNqqtzCiM7ZiwlTuMTQ8');
 assert((await copy('public_key')).startsWith('ssh-ed25519 '));
 const privatePem=await copy('private_key');assert(privatePem.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----'));
 await capture('ssh-edit');await click('save');await until(s=>s.hits.edit&&!s.busy);
 assert.equal(await copy('fingerprint'),fingerprint);
 await click('reveal-0-private_key');await click('large-0-private_key');await until(s=>s.hits['large-close']);await capture('ssh-large');await click('large-close');
 await click('edit');const nextImport=await find(/^ssh-\d+-import$/);prefix=nextImport.slice(0,-7);await click(nextImport);await text(`${prefix}-source`,'not a key');await click(`${prefix}-action-1`);await delay(500);assert(!(await snapshot()).hits.save);
 await click(`${prefix}-action-2`);await until(s=>s.hits.save);await click('cancel-edit');await until(s=>s.hits.edit&&!s.busy);assert.equal(await copy('fingerprint'),fingerprint);
 await rpc('Page.reload');await until(s=>s.screen==='catalog'&&!s.busy);await click('vault-0');await until(s=>s.screen==='unlock'&&!s.busy);await text('password','public-client-fixture');await click('submit');await until(s=>s.screen==='open'&&!s.busy);await click('record-0');await until(s=>s.hits.edit);assert.equal(await copy('fingerprint'),fingerprint);assert.equal(await copy('private_key'),privatePem);await capture('ssh-reopened');

 await click('edit');const fileImport=await find(/^ssh-\d+-import$/);prefix=fileImport.slice(0,-7);await click(fileImport);
 await evaluate(`window.__fileReads=0;const oldRead=File.prototype.arrayBuffer;File.prototype.arrayBuffer=function(){__fileReads++;return oldRead.call(this);};HTMLInputElement.prototype.click=function(){if(this.type==='file')this.dataset.fixture='ssh-pick';};`);
 const pick=async path=>{await click(`${prefix}-action-0`);const {root}=await rpc('DOM.getDocument');const {nodeId}=await rpc('DOM.querySelector',{nodeId:root.nodeId,selector:'input[data-fixture="ssh-pick"]'});assert(nodeId);await rpc('DOM.setFileInputFiles',{nodeId,files:[path]});};
 await pick(oversized);await until(s=>s.bounds[`${prefix}-notice`]);assert.equal(await evaluate('window.__fileReads'),0);assert(!(await snapshot()).hits.save);await capture('ssh-file-limit');
 await pick(keyFile);await find(/^ssh-\d+-password$/);assert.equal(await evaluate('window.__fileReads'),1);await text(`${prefix}-password`,'public-fixture-passphrase');await click(`${prefix}-action-1`);await until(s=>s.hits.save&&!s.busy);assert.equal(await copy('fingerprint'),fingerprint);
 await click('save');await until(s=>s.hits.edit&&!s.busy);
 return {viewport,encryptedPaste:true,boundedFilePicker:true,wrongPassphrase:true,derivedMetadata:true,privateCopyAndLarge:true,cancel:true,encryptedSaveReload:true};
},{viewport,windowSize:viewport}));
console.log(JSON.stringify(results,null,2));
