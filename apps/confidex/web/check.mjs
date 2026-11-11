import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { runBrowser } from '../../../tools/browser-run.mjs';
import { assets } from './assets.mjs';

const [chrome, directory, screenshotDirectory, ...flags] = process.argv.slice(2);
const quotaCheck = !flags.includes('--ui-only');
const automaticOffline = flags.includes('--auto-sync-offline');
const remoteUrl = flags.find(flag => flag.startsWith('--url='))?.slice(6);
if (remoteUrl) assert.equal(new URL(remoteUrl).protocol, 'https:');
if (screenshotDirectory) await mkdir(screenshotDirectory, {recursive: true});
const files = await assets(directory);
if (!remoteUrl) files['/worker.js'] = Buffer.concat([Buffer.from(`
const originalAdd = IDBObjectStore.prototype.add;
let failFirstCreate = true;
IDBObjectStore.prototype.add = function (...args) {
  if (failFirstCreate && this.name === 'vaults') {
    failFirstCreate = false;
    throw new DOMException('Public form retry fixture', 'QuotaExceededError');
  }
  return originalAdd.apply(this, args);
};
`), files['/worker.js']]);
const results = [];
for (const viewport of [[1920, 1100], [1180, 1000], [390, 1100]]) {
  results.push(await runBrowser(chrome, files, async ({ command, evaluate, url }) => {
    const rpc = async (method, params = {}) => {
      const reply = await command(method, params);
      assert(!reply.error, JSON.stringify(reply));
      return reply.result;
    };
    const snapshot = () => evaluate('window.confidex?.snapshot()');
    const capture = async name => {
      if (!screenshotDirectory) return;
      await delay(150);
      const image = await rpc('Page.captureScreenshot', {format: 'png'});
      await writeFile(join(screenshotDirectory, `${viewport[0]}-${name}.png`), Buffer.from(image.data, 'base64'));
    };
    const until = async predicate => {
      const deadline = Date.now() + 30000;
      for (;;) {
        let state;
        try { state = await snapshot(); } catch { /* A page reload replaces the JS context. */ }
        if (state && predicate(state)) return state;
        assert(Date.now() < deadline, `UI timed out: ${JSON.stringify(state)}`);
        await delay(30);
      }
    };
    const click = async id => {
      const settingsSection = /^(theme|language|scale)$/.test(id) ? 0
        : /^(sync-server|sync-now|sync-enabled|export-key)$/.test(id) ? 1 : null;
      if (settingsSection !== null) {
        if (!(await snapshot()).bounds['preferences-window']) await click('settings');
        const marker = settingsSection === 0 ? 'theme' : 'export-key';
        if (!(await snapshot()).hits[marker]) {
          if ((await snapshot()).hits['preferences-sections']) await click('preferences-sections');
          await click(`preferences-section-${settingsSection}`);
        }
      }
      if (/^add-.*\//.test(id) && !(await snapshot()).hits[id]) await click('add-field');
      let state = await until(s => s.hits[id]);
      const host = s => /^(?:add-(?:.+\/v1|section)|section-\d+-add-.+\/v1)$/.test(id)?s.bounds['field-menu']:/^(theme|language|scale|sync-server|sync-now|sync-enabled|export-key)$/.test(id) ? s.bounds['preferences-viewport'] : /^(value-|field-|protected-|record-title|copy-|reveal-)/.test(id)
        ? s.bounds['record-viewport'] : /^record-\d+$/.test(id) ? s.bounds['list-viewport'] : null;
      for (let attempt = 0;; attempt++) {
        const r=host(state), [x,y]=state.hits[id];
        const top=r?.[1]??15, bottom=r?.[3]??viewport[1]-24;
        if (y>=top+2 && y<=bottom-2) break;
        assert(attempt<20, `could not scroll to ${id}: ${JSON.stringify(state)}`);
        await rpc('Input.dispatchMouseEvent', {type:'mouseMoved',x:r?.[0]+4||Math.min(x,viewport[0]-24),y:r?(r[1]+r[3])/2:viewport[1]-120});
        await delay(40);
        await rpc('Input.dispatchMouseEvent', {type:'mouseWheel',x:r?.[0]+4||Math.min(x,viewport[0]-24),y:r?(r[1]+r[3])/2:viewport[1]-120,deltaX:0,deltaY:y<top?-180:180});
        await delay(150); state=await until(s=>s.hits[id]);
      }
      const [x,y]=state.hits[id];
      assert(x>=0&&x<=viewport[0],`outside viewport ${id}`);
      await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});
      await delay(40);
      for(const type of ['mousePressed','mouseReleased']) await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});
      await delay(100);
    };
    const escape = async () => {
      for(const type of ['keyDown','keyUp']) await rpc('Input.dispatchKeyEvent',{type,key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
      await delay(100);
    };
    const chooseLanguage = async index => {
      await click('language');
      const [x,y] = (await until(s=>s.hits['language-menu'])).hits['language-menu'];
      await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});
      await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',x,y,deltaX:0,deltaY:-5000});
      await delay(200);
      for(let attempt=0;!(await snapshot()).hits[`language-${index}`];attempt++) {
        assert(attempt<12,'language option did not become visible');
        await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',x,y,deltaX:0,deltaY:160});
        await delay(200);
      }
      await click(`language-${index}`);
      await escape();
    };
    const text = async (id, value) => {
      await click(id);
      await rpc('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'a', code: 'KeyA', windowsVirtualKeyCode: 65, modifiers: 4 });
      await rpc('Input.dispatchKeyEvent', { type: 'keyUp', key: 'a', code: 'KeyA', windowsVirtualKeyCode: 65, modifiers: 4 });
      await rpc('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Meta', code: 'MetaLeft', modifiers: 0 });
      if(value) await rpc('Input.insertText', { text: value });
      else for(const type of ['keyDown','keyUp']) await rpc('Input.dispatchKeyEvent',{type,key:'Backspace',code:'Backspace',windowsVirtualKeyCode:8});
      await delay(50);
    };
    const shortForm = async (name, lastId) => {
      if (viewport[0] >= 600) return;
      await rpc('Emulation.setDeviceMetricsOverride',{width:viewport[0],height:440,deviceScaleFactor:1,mobile:false});
      await delay(200);
      for(let attempt=0;;attempt++) {
        const s=await snapshot(),y=s.hits[lastId]?.[1];
        if(y>=70&&y<=420)break;
        assert(attempt<20,`${name} actions cannot be reached in a short window`);
        const point={x:viewport[0]-20,y:220};
        await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});await delay(40);
        await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:y<70?-160:160});await delay(150);
      }
      await capture(`${name}-short`);
      await rpc('Emulation.setDeviceMetricsOverride',{width:viewport[0],height:viewport[1],deviceScaleFactor:1,mobile:false});await delay(200);
    };
    const enter = async () => {
      for (const type of ['keyDown','keyUp']) await rpc('Input.dispatchKeyEvent', {
        type, key:'Enter', code:'Enter', windowsVirtualKeyCode:13,
      });
      await delay(100);
    };
    await rpc('Browser.grantPermissions',{origin:url,permissions:['clipboardReadWrite','clipboardSanitizedWrite']});
    await until(s => s.screen === 'catalog' && !s.busy);
    await capture('catalog-empty');
    await click('settings');await capture('appearance');await escape();
    assert.equal((await snapshot()).defaultSyncServer, 'https://sync.confidex.me/', 'wrong sync default');
    await evaluate('navigator.serviceWorker.ready.then(() => true)');
    let quota;
    if (quotaCheck) {
    const storageModule = Object.keys(files).find(path => path.endsWith('/web/storage.js'));
    assert(storageModule);
    await evaluate(`(async () => {
      window.storageFixture = (await import(${JSON.stringify(storageModule)})).dbCall;
      window.fixtureBytes = () => {
        const bytes = new Uint8Array(2 * 1024 * 1024);
        for (let offset = 0; offset < bytes.length; offset += 65536) crypto.getRandomValues(bytes.subarray(offset, offset + 65536));
        return bytes;
      };
      const vault = { info: { id: Array(16).fill(254), name: 'Storage fixture' }, lock: [1] };
      await storageFixture('create', [vault]);
      await storageFixture('append', ['fe'.repeat(16), 'fd'.repeat(16), '01'.repeat(32), null, fixtureBytes(), []]);
      return (await storageFixture('object', ['fe'.repeat(16), '01'.repeat(32)])).length;
    })()`).then(length => assert.equal(length, 2 * 1024 * 1024));
    const origin = new URL(url).origin;
    const usage = await rpc('Storage.getUsageAndQuota', { origin });
    await rpc('Storage.overrideQuotaForOrigin', { origin, quotaSize: 1 });
    const overridden = await rpc('Storage.getUsageAndQuota', {origin});
    assert(overridden.overrideActive && overridden.quota === 1, JSON.stringify(overridden));
    // Let Chromium's IndexedDB free-space cache expire after reducing the quota.
    await delay(35000);
    try {
      quota = await evaluate(`(async () => {
        try {
          await storageFixture('append', ['fe'.repeat(16), 'fd'.repeat(16), '02'.repeat(32), '01'.repeat(32), fixtureBytes(), []]);
          return 'unexpected success';
        } catch (error) { return String(error); }
      })()`);
    } finally { await rpc('Storage.overrideQuotaForOrigin', { origin }); }
    assert.equal(quota, 'Quota', JSON.stringify({usage, after: await rpc('Storage.getUsageAndQuota', {origin})}));
    await evaluate(`(async () => {
      const head = await storageFixture('head', ['fe'.repeat(16), 'fd'.repeat(16)]);
      if (!head.revision.every(byte => byte === 1)) throw new Error('quota failure changed the head');
      const db = await new Promise(resolve => { const request = indexedDB.open('confidex'); request.onsuccess = () => resolve(request.result); });
      await new Promise((resolve, reject) => {
        const tx = db.transaction(['vaults', 'heads', 'objects'], 'readwrite');
        tx.objectStore('vaults').delete('fe'.repeat(16));
        tx.objectStore('heads').delete(['fe'.repeat(16), 'fd'.repeat(16)]);
        tx.objectStore('objects').delete(['fe'.repeat(16), '01'.repeat(32)]);
        tx.oncomplete = resolve; tx.onabort = reject;
      }); db.close(); delete window.storageFixture; delete window.fixtureBytes;
    })()`);
    }
    await evaluate('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve(true))))');
    await click('create');
    await until(s=>s.screen==='create');
    await click('create-sync');
    await capture('create');
    await enter();
    await until(s=>!s.busy&&s.error==='vault-error-input');
    await capture('create-validation-empty');
    await text('name', 'Personal');
    await text('password', 'public-browser-fixture-password');
    await text('repeat', 'mismatched-public-password');
    await enter();
    await until(s=>!s.busy&&s.error==='vault-error-input');
    await capture('create-validation-repeat');
    await text('repeat', 'public-browser-fixture-password');
    await shortForm('create','submit');
    await enter();
    if (!remoteUrl) {
      await until(s=>!s.busy&&s.error==='vault-error-quota');
      await capture('create-storage-error');
      await enter();
    }
    await until(s => s.screen === 'key' && !s.busy);
    const keyState=await snapshot();
    const groups=Array.from({length:11},(_,i)=>keyState.bounds[`key-group-${i}`]);
    assert(groups.every(Boolean),'missing secret-key group');
    for(let i=1;i<groups.length;i++) {
      const [a,b]=[groups[i-1],groups[i]];
      assert(Math.abs(a[1]-b[1])<1?b[0]>=a[2]:b[1]>=a[3],'key groups overlap or change reading order');
    }
    await capture('secret-key');
    await enter();
    assert.equal((await snapshot()).screen,'key','Enter bypassed key confirmation');
    await shortForm('secret-key','key-saved');
    await click('key-saved');
    await enter();
    await until(s => s.screen === 'open' && !s.busy);
    await capture('records-empty');
    const extras = ['PyPI', 'Work account', 'Home network', 'Email', 'Cloud service', 'Recovery codes', 'Private notes'];
    let expectedRows = 0;
    for (const title of extras) {
      await click('new-record'); await click('template-empty'); await text('record-title', title);
      await click('add-note/v1'); await text('value-0-text', 'Public visual fixture.');
      await click('save'); expectedRows++;
      await until(s => !s.busy && s.rows === expectedRows && s.hits.edit);
      if (viewport[0] < 960) await click('back');
    }
    await click('new-record'); await click('template-login');
    await click('add-field');await escape();
    assert((await snapshot()).editing,'Escape from Add field cancelled the record');
    await capture('new-empty-record');
    const emptyEditor = await until(s => s.bounds['field-0']);
    const column = emptyEditor.bounds['record-column'];
    const field = emptyEditor.bounds['field-2'];
    const footer = emptyEditor.bounds['record-footer'];
    assert(column[2]-column[0]<=721,'record editor stretches across the window');
    assert(footer[1]-field[3]>=12&&footer[1]-field[3]<48,'Add field is detached from the short record');
    assert(field[3]<=emptyEditor.bounds['record-viewport'][3]+1,'an empty login is clipped in a tall window');
    assert(emptyEditor.hits['record-title'][1]<emptyEditor.bounds['field-0'][1],'empty title has no visible place above the fields');
    await capture('new-login-empty');
    await text('record-title', 'GitHub');
    await text('value-0-username', 'mosquito');
    await text('value-1-password', 'public-password-fixture');
    await text('value-2-url', 'https://github.com');
    await click('remove-3');
    await click('add-secure-note/v1');
    await click('reveal-3-text');
    await text('value-3-text', 'Recovery codes are kept in a separate record.');
    await enter();
    assert((await snapshot()).editing,'Enter in a note submitted the editor');
    await text('value-3-text', 'Recovery codes are kept in a separate record.');
    await capture('editor');
    await click('record-title');await enter();
    await until(s => !s.busy && s.rows === extras.length + 1 && s.hits.edit);
    const viewed = await snapshot();
    await click('edit');
    const edited = await snapshot();
    for (const id of ['copy-0-username','copy-1-password','reveal-1-password','copy-2-url','copy-3-text','reveal-3-text']) {
      assert(edited.hits[id].every((v,i)=>Math.abs(v-viewed.hits[id][i])<1), `${id} moves between view and edit`);
    }
    await capture('record-actions-edit');
    await click('reveal-3-text');
    await text('value-3-text', 'Recovery codes are kept in a separate record.');
    await click('save');
    await until(s => !s.busy && s.rows === extras.length + 1 && s.hits.edit);
    assert((await snapshot()).hits['reveal-3-text'],'protected note lost its reveal control after saving');
    await capture('record-dark');
    await click('copy-0-username');await until(s=>s.copied===1);
    assert.equal(await evaluate('navigator.clipboard.readText()'),'mosquito');
    await evaluate('navigator.clipboard.writeText=()=>Promise.reject(new DOMException("fixture denied","NotAllowedError"));true');
    await click('copy-3-text');await until(s=>s.copyFailed===1);
    assert.equal((await snapshot()).copied,1,'failed copy looked successful');
    await evaluate('delete navigator.clipboard.writeText;true');
    await click('copy-3-text');await until(s=>s.copied===2);
    assert.equal(await evaluate('navigator.clipboard.readText()'),'Recovery codes are kept in a separate record.');
    await click('large-1-password');await until(s=>s.hits['large-close']);
    const large=(await snapshot()).bounds['large-dialog'];
    assert(large[0]>=-1&&large[1]>=-1&&large[2]<=viewport[0]+1&&large[3]<=viewport[1]+1,'large type leaves viewport');
    await capture('large-type');
    await click('large-copy');await until(s=>s.copied===3);
    assert.equal(await evaluate('navigator.clipboard.readText()'),'public-password-fixture');
    await click('large-close');await until(s=>!s.hits['large-close']);
    await click('large-1-password');await until(s=>s.hits['large-close']);
    await enter();await until(s=>!s.hits['large-close']);
    assert(!(await snapshot()).editing,'closing large type changed record mode');
    const beforeSetup = await snapshot();
    assert(beforeSetup.hits.sync, 'quick sync is missing beside settings');
    const [sx, sy] = beforeSetup.hits.sync, [px, py] = beforeSetup.hits.settings;
    assert(viewport[0] >= 960 ? Math.abs(sx-px)<2 && Math.abs(sy-py)<60
      : Math.abs(sy-py)<2 && Math.abs(sx-px)<60, 'sync and settings are not adjacent');
    await click('sync');
    await until(s=>s.bounds['preferences-window'] && s.hits['export-key'] && !s.busy);
    await capture('vault-settings-window');
    await text('sync-server', 'https://unsaved.example.test/');
    await escape();
    await click('sync');
    await until(s=>s.bounds['preferences-window'] && !s.busy);
    await capture('vault-settings-reopened');
    await escape();
    await click('theme');await click('theme-1');await escape();
    await capture('record-light');
    await click('theme');await click('theme-0');await escape();
    await chooseLanguage(1);await until(s=>s.locale==='ru');await capture('record-ru');
    await chooseLanguage(0);await until(s=>s.locale==='en-US');
    await click('scale');await click('scale-150');await until(s=>s.zoom===1.5);await escape();
    await capture('record-scale-150');
    await click('scale');await click('scale-100');await until(s=>s.zoom===1);await escape();
    await click('large-1-password');await until(s=>s.hits['large-close']);
    await rpc('Input.dispatchKeyEvent',{type:'keyDown',key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:10});
    await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:0});
    await until(s => s.screen === 'unlock' && !s.busy && s.rows === 0);
    await capture('unlock');
    await shortForm('unlock','submit');
    await text('password', 'wrong');
    await enter();
    await until(s => !s.busy && s.error === 'vault-error-auth');
    await capture('unlock-error');
    await text('password', 'public-browser-fixture-password');
    await enter();
    await until(s => s.screen === 'open' && !s.busy && s.rows === extras.length + 1);
    await evaluate('navigator.serviceWorker.ready.then(() => true)');
    const deadline = Date.now() + 30000;
    while (!await evaluate('Boolean(navigator.serviceWorker.controller)')) {
      assert(Date.now() < deadline, 'offline shell did not activate'); await delay(50);
    }
    if (automaticOffline) {
      const modulePath = Object.keys(files).find(path => path.endsWith('/web/storage.js'));
      await evaluate(`(async () => {
        const {dbCall} = await import(${JSON.stringify(modulePath)});
        const vault = (await dbCall('vaults', []))[0];
        const id = vault.id.map(b => b.toString(16).padStart(2, '0')).join('');
        const previous = await dbCall('sync-state', [id]);
        const current = Array.from(new TextEncoder().encode(JSON.stringify({server:'https://127.0.0.1:1/',enabled:true,cursor:0,heads:[]})));
        await dbCall('sync-commit', [id, {previous,current,objects:[],heads:[]}]);
      })()`);
    }
    await evaluate('window.__beforeOfflineReload = true');
    await rpc('Network.enable');
    await rpc('Network.emulateNetworkConditions', { offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0 });
    await rpc('Page.reload', { ignoreCache: true });
    while (true) {
      let ready = false;
      try { ready = await evaluate(`location.href === ${JSON.stringify(url)} && !window.__beforeOfflineReload && document.readyState === 'complete'`); } catch { /* Navigation. */ }
      if (ready) break;
      assert(Date.now() < deadline, 'offline navigation timed out'); await delay(50);
    }
    await until(s => s.screen === 'catalog' && !s.busy && s.vaults === 1);
    await capture('catalog');
    assert.equal(await evaluate('navigator.onLine'), false);
    await click('vault-0');
    await until(s => s.screen === 'unlock' && !s.busy);
    await text('password', 'public-browser-fixture-password');
    await click('submit');
    await until(s => s.screen === 'open' && !s.busy && s.rows === extras.length + 1);
    if (automaticOffline) assert.equal((await snapshot()).error, null, 'automatic sync showed an offline error');
    await text('search','GitHub');
    const reopened=await until(s=>Object.keys(s.hits).some(id=>/^record-\d+$/.test(id)));
    await click(Object.keys(reopened.hits).find(id=>/^record-\d+$/.test(id)));
    await until(s => !s.busy && s.hits.edit);
    assert((await snapshot()).hits['reveal-3-text'],'protected note was not persisted across offline reload');
    await capture('record-offline');
    if (viewport[0] < 960) await click('back');
    await text('search','No matching public fixture');await capture('records-no-results');
    await text('search','GitHub');
    const filtered = await until(s=>Object.keys(s.hits).some(id=>/^record-\d+$/.test(id)));
    await click(Object.keys(filtered.hits).find(id=>/^record-\d+$/.test(id)));
    await until(s=>!s.busy&&s.hits.delete);
    await click('delete');
    await until(s=>s.hits['confirm-delete']);await capture('delete-dialog');
    await click('confirm-delete');
    await until(s => !s.busy && s.rows === 0);
    await text('search','');
    await until(s => !s.busy && s.rows === extras.length);
    await click('lock');
    await until(s => s.screen === 'unlock' && !s.busy);
    await text('password', 'public-browser-fixture-password');
    await click('submit');
    const final = await until(s => s.screen === 'open' && !s.busy && s.rows === extras.length);
    if (automaticOffline) {
      assert.equal(final.error, null, 'automatic retry showed an offline error');
      await click('sync');
      await until(s => !s.busy && s.error === 'sync-error-network');
      assert(!(await snapshot()).bounds['preferences-window'], 'quick sync opened settings for a connected vault');
    }
    return { viewport, automaticOffline, manualErrorVisible: automaticOffline, largeObjectBytes: quotaCheck ? 2 * 1024 * 1024 : null, quotaRollback: quotaCheck ? quota === 'Quota' : null, offlineReload: true, verifiedDeletionHistory: true, screen: final.screen, error: final.error };
  }, { windowSize: viewport, viewport, remoteUrl }));
}
console.log(JSON.stringify(results, null, 2));
