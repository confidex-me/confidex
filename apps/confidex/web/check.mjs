// Check persistence and offline reopening through the actual browser UI.
import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import {releaseAssets} from './assets.mjs';
import {runBrowser} from '../../../tools/browser-run.mjs';

const [chrome, web] = process.argv.slice(2);
assert(chrome && web, 'Usage: check.mjs CHROMIUM WEB_DIRECTORY');
const files = await releaseAssets(web);
files['/worker.js'] = Buffer.concat([Buffer.from(`
const originalAdd = IDBObjectStore.prototype.add;
let failFirstCreate = true;
IDBObjectStore.prototype.add = function (...args) {
  if (failFirstCreate && this.name === 'vaults') {
    failFirstCreate = false;
    throw new DOMException('Public create retry fixture', 'QuotaExceededError');
  }
  return originalAdd.apply(this, args);
};
`), files['/worker.js']]);
const results = [];
for (const width of [1180, 390]) {
  results.push(await runBrowser(chrome, files, async ({command, evaluate, url}) => {
    const rpc = async (method, params = {}) => {
      const result = await command(method, params);
      assert(!result.error, JSON.stringify(result));
      return result.result;
    };
    await rpc('Page.enable');
    await rpc('Page.addScriptToEvaluateOnNewDocument', {source: 'window.confirm = () => false;'});
    await evaluate('window.confirm = () => false; true');
    const snapshot = () => evaluate('window.confidex?.snapshot()');
    const until = async predicate => {
      const deadline = Date.now() + 45_000;
      let state, failure;
      while (Date.now() < deadline) {
        try { state = await snapshot(); } catch (error) { failure = error.message; }
        if (state && predicate(state)) return state;
        await delay(50);
      }
      assert.fail(`UI timed out: ${JSON.stringify(state)}; ${failure ?? "no snapshot error"}`);
    };
    const click = async id => {
      const state = await until(state => state.hits[id]);
      const [x, y] = state.hits[id];
      await rpc('Input.dispatchMouseEvent', {type: 'mouseMoved', x, y});
      for (const type of ['mousePressed', 'mouseReleased']) {
        await rpc('Input.dispatchMouseEvent', {type, x, y, button: 'left', clickCount: 1});
      }
      await delay(150);
    };
    const text = async (id, value) => {
      await click(id);
      await rpc('Input.insertText', {text: value});
      await delay(100);
    };
    await rpc('Browser.grantPermissions', {origin: url, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite']});
    await until(state => state.screen === 'catalog' && !state.busy);
    const version = await evaluate('window.confidex.version()');
    assert.equal(version, JSON.parse(files['/BUILD.json']).version);
    await click('create');
    await until(state => state.screen === 'create');
    await click('create-sync');
    await text('name', 'Public persistence fixture');
    await text('password', 'public-smoke-password');
    await text('repeat', 'public-smoke-password');
    await click('submit');
    await until(state => state.screen === 'create' && state.error === 'vault-error-quota' && !state.busy);
    await click('submit');
    await until(state => state.screen === 'key' && !state.busy);
    await click('copy-key');
    const key = await evaluate('navigator.clipboard.readText()');
    assert.match(key, /^[A-Z2-7-]+$/);
    assert.equal(key.replaceAll('-', '').length, 77);
    await click('key-saved');
    await click('continue');
    await until(state => state.screen === 'open' && !state.busy);
    await click('new-record');
    await click('template-empty');
    await text('record-title', 'Public offline record');
    await click('add-field');
    await click('add-note/v1');
    await text('value-0-text', 'Public persistence marker');
    await click('save');
    await until(state => !state.busy && state.rows === 1 && state.hits.edit);
    const beforeCopy = await snapshot();
    await click('copy-0-text');
    await until(state => state.copied === beforeCopy.copied + 1);
    assert.equal(await evaluate('navigator.clipboard.readText()'), 'Public persistence marker');
    await evaluate('navigator.clipboard.writeText = () => Promise.reject(new DOMException("Fixture denied", "NotAllowedError")); true');
    await click('copy-0-text');
    const denied = await until(state => state.copyFailed === beforeCopy.copyFailed + 1);
    assert.equal(denied.copied, beforeCopy.copied + 1);
    await evaluate('delete navigator.clipboard.writeText; true');
    await evaluate('navigator.serviceWorker.ready.then(() => true)');
    for (let attempt = 0; !await evaluate('Boolean(navigator.serviceWorker.controller)'); attempt++) {
      assert(attempt < 200, 'Service Worker did not activate');
      await delay(50);
    }
    await rpc('Network.enable');
    await rpc('Network.emulateNetworkConditions', {offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0});
    await rpc('Page.reload', {ignoreCache: true});
    await until(state => state.screen === 'catalog' && state.vaults === 1 && !state.busy);
    assert.equal(await evaluate('navigator.onLine'), false);
    await click('vault-0');
    await until(state => state.screen === 'unlock' && !state.busy);
    const unlock = await snapshot();
    if (unlock.hits['secret-key']) await text('secret-key', key);
    await text('password', 'public-smoke-password');
    await click('submit');
    const reopened = await until(state => state.screen === 'open' && state.rows === 1 && !state.busy);
    const record = Object.keys(reopened.hits).find(id => /^record-\d+$/.test(id));
    if (record) await click(record);
    const view = await until(state => state.hits.edit && !state.busy);
    await click('copy-0-text');
    await until(state => state.copied === view.copied + 1);
    assert.equal(await evaluate('navigator.clipboard.readText()'), 'Public persistence marker');
    await click('lock');
    await until(state => state.screen === 'unlock' && !state.busy);
    return {width, createRetry: true, offlineReload: true, persistedRecords: 1, locked: true};
  }, {windowSize: [width, 1100], viewport: [width, 1100]}));
}
console.log(JSON.stringify(results));
