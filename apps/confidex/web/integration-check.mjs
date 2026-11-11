import assert from 'node:assert/strict';
import {mkdir, writeFile, readFile} from 'node:fs/promises';
import {randomBytes, createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {resolve} from 'node:path';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';

const [chrome, bundle, output, image] = process.argv.slice(2);
assert(chrome && bundle && output && image, 'Usage: integration-check.mjs CHROME BUNDLE OUTPUT PUBLIC_IMAGE');
await mkdir(output, {recursive:true});
const license = Buffer.from('PUBLIC SOFTWARE LICENSE\nProduct: Screenshot demo\nKey: TEST-ONLY-2026\n');
const noise = randomBytes(2_100_000);
await writeFile(`${output}/license.txt`, license);
await writeFile(`${output}/noise.bin`, noise);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const results = [];
for (const viewport of [[1180,1100], [390,1100]]) {
  results.push(await runBrowser(chrome, await assets(bundle), async ({command, evaluate, url}) => {
 const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
 const snapshot=()=>evaluate('window.confidex?.snapshot()');
 const until=async p=>{const deadline=Date.now()+25000;for(;;){const s=await snapshot();if(s&&p(s))return s;assert(Date.now()<deadline,JSON.stringify(s));await delay(50);}};
 const click=async id=>{
  let state=await until(s=>s.hits[id]);
  const host = s => {
    if (/^(?:add-(?:.+\/v1|section)|section-\d+-add-.+\/v1)$/.test(id)) return s.bounds['field-menu'];
    const record = s.bounds['record-viewport'];
    if (/^history-view-/.test(id)) {
      const history = s.bounds['history-viewport'];
      if (history && history[1] >= record[1] && history[3] <= record[3]) return history;
    }
    return /^(value-|field-(name|handle)-|record-title$|large-\d+-|copy-\d+-|reveal-\d+-|protected-\d+|photo-\d+-|file-\d+-|wifi-\d+-|card-\d+-|totp-\d+-|password-\d+-|history-(toggle$|view-\d+$|more$))/.test(id) ? record : null;
  };
  for(let n=0;;n++){
   const r=host(state),top=Math.max(r?.[1]??15,15),bottom=Math.min(r?.[3]??viewport[1]-15,viewport[1]-15),y=state.hits[id][1];
   if(y>=top+2&&y<=bottom-2)break;
   if(n===24) { await capture('unreachable'); console.log(JSON.stringify({id,point:state.hits[id],record:state.bounds['record-viewport'],history:state.bounds['history-viewport']})); }
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
 const capture=async name=>{const r=await rpc('Page.captureScreenshot',{format:'png'});await writeFile(`${output}/${viewport[0]}-${name}.png`,Buffer.from(r.data,'base64'));};
  const hit = async pattern => {
    const state = await until(s => Object.keys(s.hits).some(id => pattern.test(id)));
    return Object.keys(state.hits).find(id => pattern.test(id));
  };
  const pick = async (id, file) => {
    await evaluate(`HTMLInputElement.prototype.click = function() { if(this.type === 'file') this.dataset.fixture = 'pick'; };`);
    await click(id);
    const {root} = await rpc('DOM.getDocument');
    const {nodeId} = await rpc('DOM.querySelector', {nodeId:root.nodeId, selector:'input[data-fixture="pick"]'});
    assert(nodeId, 'file picker was not installed');
    await rpc('DOM.setFileInputFiles', {nodeId, files:[resolve(file)]});
  };
  const response = async predicate => {
    for (let count=0; count<600; count++) {
      if (await evaluate(`(${predicate})`)) return;
      await delay(50);
    }
    throw Error('engine response timeout');
  };
  const save = async () => {
    await click('save');
    await until(s => !s.busy && !s.editing && s.hits.edit);
    assert.equal((await snapshot()).error, null);
  };
  const template = async (search, id) => {
    if (!(await snapshot()).hits['new-record']) await click('back');
    await click('new-record'); await text('template-search', search); await click(`template-${id}`);
  };
  await rpc('Page.enable');
  await rpc('Page.addScriptToEvaluateOnNewDocument', {source:`
    window.__proof = {checks:0};
    function decode(bytes) {
      let offset = 0, value;
      try { value = JSON.parse(new TextDecoder().decode(bytes)); }
      catch {
        offset = 4 + new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0,true);
        value = JSON.parse(new TextDecoder().decode(bytes.subarray(4,offset)));
      }
      for (const draft of [value.result?.Ok?.Draft, value.result?.Ok?.Historical?.draft]) {
        if (!draft) continue;
        for (const field of draft.fields) if (field.data) {
          const length = new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0,true);
          offset += 4;
          field.data = Array.from(bytes.subarray(offset,offset+length));
          offset += length;
        }
      }
      return value;
    }
    window.Worker = class extends Worker {
      constructor(...args) {
        super(...args);
        if(String(args[0]).endsWith('/worker.js')) this.addEventListener('message', ({data}) => {
          try {
            const result = decode(data).result;
            if(result.Ok?.Draft) __proof.draft = result.Ok.Draft;
            if(result.Ok?.Historical) __proof.historical = result.Ok.Historical;
            if(result.Ok?.Checked) { __proof.checks++; __proof.size = result.Ok.Checked.compressed; }
            if(result.Err) __proof.error = result.Err;
          } catch(error) { __proof.decodeError = String(error); }
        });
      }
    };
    const create = URL.createObjectURL;
    URL.createObjectURL = function(blob) {
      if(blob instanceof Blob) blob.arrayBuffer().then(bytes => {
        window.__downloads ??= [];
        __downloads.push(Array.from(new Uint8Array(bytes)));
      });
      return create.call(this,blob);
    };
  `});
  await rpc('Page.reload');
  await rpc('Browser.grantPermissions', {origin:url, permissions:['clipboardReadWrite','clipboardSanitizedWrite']});
  await until(s => s.screen === 'catalog' && !s.busy);
  await delay(300);
  await click('create');
  await until(s => s.screen === 'create');
  await click('create-sync');
  await text('name', 'Public integration fixture');
  await text('password', 'Public-Integration-2026!');
  await text('repeat', 'Public-Integration-2026!');
  await click('submit');
  await until(s => s.screen === 'key' && !s.busy);
  await click('key-saved'); await click('continue');
  await until(s => s.screen === 'open' && !s.busy);

  await template('Identity', 'identity');
  await text('record-title', 'Public identity');
  await text('value-0-text', 'Foma Kinaev');
  await pick(await hit(/^photo-\d+-choose$/), image);
  await until(s => s.hits['photo-apply']);
  await delay(1200);
  await click('photo-cancel');
  await until(s => !s.bounds['photo-preparation']);
  assert(!Object.keys((await snapshot()).hits).some(id => /^photo-\d+-reveal$/.test(id)));
  await pick(await hit(/^photo-\d+-choose$/), image);
  await until(s => s.hits['photo-apply']); await delay(1200);
  await click('photo-apply');
  await response('__proof.checks === 1');
  await until(s => !s.busy && !s.bounds['photo-preparation']);
  await click(await hit(/^photo-\d+-reveal$/));
  await until(s => s.bounds['photo-viewer']);
  await capture('photo-reveal');
  await click('photo-viewer-export');
  await click('photo-viewer-viewer-original');
  await response('__downloads?.length === 1');
  assert.equal(digest(Buffer.from(await evaluate('__downloads[0]'))), digest(await readFile(image)));
  for (const [format, count, signature] of [
    ['png', 2, [137,80,78,71,13,10,26,10]],
    ['jpeg', 3, [255,216,255]],
  ]) {
    await click('photo-viewer-export'); await click(`photo-viewer-${format}`);
    await response(`__downloads?.length === ${count}`);
    assert.deepEqual(await evaluate(`__downloads[${count-1}].slice(0,${signature.length})`), signature);
  }
  await click('photo-viewer-close');

  await click('add-field'); await click('add-file/v1');
  await pick(await hit(/^file-\d+-choose$/), `${output}/license.txt`);
  await response('__proof.checks === 2');
  await click(await hit(/^file-\d+-save$/));
  await response('__downloads?.length === 4');
  assert.deepEqual(Buffer.from(await evaluate('__downloads[3]')), license);
  await click('add-field'); await click('add-totp/v1');
  await text(await hit(/^totp-\d+-secret$/), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  const copied = (await snapshot()).copied;
  await click(await hit(/^totp-\d+-copy$/));
  await until(s => s.copied > copied);
  assert.match(await evaluate('navigator.clipboard.readText()'), /^\d{6}$/);
  await click('add-field'); await click('add-card/v1');
  await text(await hit(/^card-\d+-number$/), '4111111111111112');
  await text(await hit(/^card-\d+-holder$/), 'PUBLIC CARD');
  await capture('mixed-editor');
  await save();
  const restored = await evaluate('__proof.draft');
  assert.equal(restored.fields[0].name, 'Full name');
  assert.equal(restored.fields[0].values.text, 'Foma Kinaev');
  assert.equal(restored.fields[5].type_name, 'photo/v1');
  assert.equal(restored.fields[5].protected, true);
  assert.deepEqual(Buffer.from(restored.fields[6].data), license);
  assert.equal(Buffer.from(restored.fields[7].data).toString(), '12345678901234567890');
  assert.equal(restored.fields[8].values.number, '4111111111111112');
  assert.equal(restored.fields[8].type_name, 'card/v1');
  await capture('mixed-saved');

  await click('edit');
  await click('add-field'); await click('add-file/v1');
  await pick(Object.keys((await snapshot()).hits).filter(id => /^file-\d+-choose$/.test(id)).at(-1), `${output}/noise.bin`);
  await response('__proof.checks === 3');
  await save();
  const head = await evaluate('__proof.draft.revision');
  await click('edit');
  await click('add-field'); await click('add-file/v1');
  // The last picker belongs to the newly added field.
  const choose = Object.keys((await snapshot()).hits).filter(id => /^file-\d+-choose$/.test(id)).at(-1);
  await evaluate('__proof.error = null');
  await pick(choose, `${output}/noise.bin`);
  await response('__proof.error === "RecordLimit"');
  await capture('whole-record-limit');
  assert.deepEqual(await evaluate('__proof.draft.revision'), head);
  await click('cancel-edit');
  await until(s => !s.editing && !s.busy && s.hits.edit);
  assert.equal((await evaluate('__proof.draft.fields')).length, 10);
  await click('history-toggle');
  await click('history-view-1');
  await until(s => s.bounds['history-window']);
  await response('__proof.historical?.draft?.fields?.length === 9');
  await capture('historical-attachments');
  await click('history-close');

  await template('Wi', 'wifi');
  await text('record-title', 'Public Wi-Fi');
  await text('value-0-text', 'Screenshot Wi-Fi'); await text('value-1-password','Public-Wifi-2026!');
  await click('password-1-generate');
  await until(s => s.hits['password-1-generator-use']);
  await capture('password-generator');
  await click('password-1-generator-use');
  await save();
  await until(s => Object.keys(s.bounds).some(id => /^wifi-\d+-code$/.test(id)));
  const wifi = await evaluate('__proof.draft.fields');
  assert(wifi[1].values.password.length > 0);
  assert.equal(wifi[2].values.ssid, '0'); assert.equal(wifi[2].values.password, '1');
  await template('Credit', 'credit-card');
  await text('record-title', 'Public card template'); await text('value-0-secret','4111111111111111');
  await save();
  const card = await evaluate('__proof.draft.fields');
  assert.equal(card.length,6); assert.equal(card[0].name,'Card number'); assert.match(card[3].name,/CVV/);
  assert(card[0].protected && card[3].protected && card[4].protected);
  await rpc('Page.reload');
  await until(s => s.screen === 'catalog' && !s.busy);
  await click('vault-0'); await until(s => s.screen === 'unlock' && !s.busy);
  await text('password','Public-Integration-2026!'); await click('submit');
  await until(s => s.screen === 'open' && !s.busy && s.rows === 3);
  await click('record-0'); await until(s => s.hits.edit);
  await capture('reloaded');
  if (!(await snapshot()).hits.lock) await click('back');
  await click('lock'); await until(s => s.screen === 'unlock' && !s.busy);
  assert(!Object.keys((await snapshot()).hits).some(id => /^photo-|^totp-|^card-/.test(id)));
  return {viewport, photo:true, fileExactBytes:true, totp:true, cardChecksumAdvisory:true,
    wholeRecordLimit:true, history:true, generator:true, templates:true, reload:true, lock:true};
  }, {viewport, windowSize:viewport}));
}
console.log(JSON.stringify(results,null,2));
