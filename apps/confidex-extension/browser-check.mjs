import assert from 'node:assert/strict';
import {execFileSync, spawn} from 'node:child_process';
import {createHash, X509Certificate} from 'node:crypto';
import {cp, mkdtemp, mkdir, readFile, readdir, rm, writeFile} from 'node:fs/promises';
import {request as httpRequest} from 'node:http';
import {createServer} from 'node:https';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import {setTimeout as delay} from 'node:timers/promises';
import {releaseAssets} from '../confidex/web/assets.mjs';

const [chromePath, extensionPath, webPath, daemonPath, option] = process.argv.slice(2);
assert(daemonPath, 'Usage: node browser-check.mjs CHROME EXTENSION WEB SYNC_DAEMON [--vault-only]');
assert(option == null || option === '--vault-only', 'Unknown check option');
const directory = await mkdtemp(join(tmpdir(), 'confidex-extension-'));
let chrome, daemon, server;
const password = 'public-extension-master-fixture';
const loginPassword = 'public-extension-login-fixture';

try {
  const certFile = join(directory, 'cert.pem');
  const keyFile = join(directory, 'key.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-keyout', keyFile, '-out', certFile,
  ], {stdio: 'ignore'});
  const cert = await readFile(certFile);
  const key = await readFile(keyFile);
  const publicKey = new X509Certificate(cert).publicKey.export({type: 'spki', format: 'der'});
  const fingerprint = createHash('sha256').update(publicKey).digest('base64');

  const blobPath = join(directory, 'objects');
  await mkdir(blobPath);
  const config = join(directory, 'server.toml');
  await writeFile(config, `
[listen]
address = "127.0.0.1"
port = 0
[index]
url = ${JSON.stringify(join(directory, 'index.sqlite'))}
[[backend.posix]]
path = ${JSON.stringify(blobPath)}
`);
  daemon = spawn(resolve(daemonPath), [config], {stdio: ['ignore', 'ignore', 'pipe']});
  let port;
  for await (const line of createInterface({input: daemon.stderr})) {
    port = line.match(/^confidexsyncd listening on 127\.0\.0\.1:(\d+)$/)?.[1];
    if (port) break;
    if (line.startsWith('Error:')) throw new Error(line);
  }
  assert(port, 'Fixture sync server failed to start');

  const assets = await releaseAssets(webPath);
  server = createServer({cert, key}, (req, res) => {
    if (req.url.startsWith('/v1/')) {
      const proxy = httpRequest({hostname: '127.0.0.1', port, path: req.url,
        method: req.method, headers: req.headers}, incoming => {
        res.writeHead(incoming.statusCode, incoming.headers);
        incoming.pipe(res);
      });
      proxy.on('error', () => res.writeHead(502).end());
      req.pipe(proxy);
      return;
    }
    if (req.url === '/strict' || req.url === '/ordinary') {
      res.setHeader('Content-Type', 'text/html');
      if (req.url === '/strict') {
        res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'none'; object-src 'none'");
      }
      res.end('<!doctype html><title>CSP fixture</title><input type="password">');
      return;
    }
    if (req.url === '/seed') {
      res.writeHead(200, {'Content-Type': 'text/html'}).end('<!doctype html><title>Sync fixture</title>');
      return;
    }
    const asset = assets[req.url];
    if (!asset) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, {'Content-Type': req.url.endsWith('.wasm') ? 'application/wasm' : 'text/javascript'});
    res.end(asset);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `https://127.0.0.1:${server.address().port}`;

  // PR 1 has no permission UI. Give only the local fixture host permission in
  // a disposable copy and run the same content bootstrap and WASM binaries.
  const cspExtension = join(directory, 'csp-extension');
  await cp(extensionPath, cspExtension, {recursive: true});
  const manifestPath = join(cspExtension, 'manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath));
  assert.equal(manifest.host_permissions, undefined);
  manifest.host_permissions = ['https://127.0.0.1/*'];
  await writeFile(manifestPath, JSON.stringify(manifest));

  chrome = spawn(chromePath, [
    '--headless=new', '--remote-debugging-pipe', '--enable-unsafe-extension-debugging',
    '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
    '--disable-component-update', '--disable-sync', '--enable-unsafe-swiftshader',
    `--ignore-certificate-errors-spki-list=${fingerprint}`,
    `--user-data-dir=${join(directory, 'profile')}`,
  ], {stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe']});
  const command = devTools(chrome);
  const browser = await command('Browser.getVersion');
  const {id} = await command('Extensions.loadUnpacked', {path: resolve(extensionPath)});
  const {id: cspId} = await command('Extensions.loadUnpacked', {path: cspExtension});
  const tabTargets = () => command('Target.getTargets', {filter: [{type: 'tab'}]}).then(response => response.targetInfos);
  const previousTargets = new Set((await tabTargets()).map(target => target.targetId));
  const seed = await newTab(command, origin + '/seed');
  const credentials = await seed.evaluate(`(async () => {
    const worker = new Worker('/worker.js', {type: 'module'});
    await new Promise((resolve, reject) => {
      worker.onmessage = ({data}) => { if (data === 'ready') resolve(); };
      worker.onerror = reject;
    });
    const call = command => new Promise((resolve, reject) => {
      worker.onerror = reject;
      worker.onmessage = ({data}) => {
        try {
          const result = JSON.parse(new TextDecoder().decode(data)).result;
          if ('Err' in result) reject(new Error('Web fixture command failed'));
          else resolve(result.Ok);
        } catch (error) { reject(error); }
        finally { data.fill(0); }
      };
      const input = new TextEncoder().encode(JSON.stringify({generation: 1, command}));
      worker.postMessage(input, [input.buffer]);
    });
    const password = ${JSON.stringify(password)};
    const server = ${JSON.stringify(origin + '/')};
    const {Created} = await call({Create: {name: 'Synthetic web vault', password, remember: false}});
    const fields = [
      ['username/v1', 'username', 'chromium-fixture@example.test'],
      ['password/v1', 'password', ${JSON.stringify(loginPassword)}],
      ['url/v1', 'url', 'https://example.test'],
    ].map(([type_name, key, value]) => ({source: null, name: '', type_name, values: {[key]: value}, opaque: 0, protected: false}));
    await call({Save: {epoch: 1, draft: {
      record: Array(16).fill(1), revision: null, title: 'Synthetic login', fields, tags: [],
    }}});
    await call({SyncConfig: {server}});
    for (let step = 0; step < 16; step++) {
      const {Synced} = await call({Sync: {server}});
      if (!Synced.more && !Synced.conflicts.length) {
        worker.terminate();
        return {password, key: Created.key};
      }
    }
    throw new Error('Web fixture did not sync');
  })()`);

  const extensionUrl = `chrome-extension://${id}/session.html`;
  const seedTab = (await tabTargets()).find(target => !previousTargets.has(target.targetId));
  assert(seedTab, 'No top-level tab target for the toolbar action');
  await command('Extensions.triggerAction', {id, targetId: seedTab.targetId});
  const tab = await until(async () => {
    const {targetInfos} = await command('Target.getTargets');
    return targetInfos.find(target => target.type === 'page' && target.url === extensionUrl);
  }, 'action opens the session tab');
  const session = await attach(command, tab.targetId);
  await waitForUi(session);
  await until(() => session.evaluate("navigator.locks.query().then(s => s.held.some(lock => lock.name === 'confidex-session'))"), 'session ownership');
  await command('Extensions.triggerAction', {id, targetId: seedTab.targetId});
  assert.equal((await command('Target.getTargets')).targetInfos
    .filter(target => target.type === 'page' && target.url === extensionUrl).length, 1);

  const host = (await readdir(join(extensionPath, 'ui', 'snippets'), {recursive: true}))
    .find(name => name.endsWith('/web/session-host.js'));
  assert(host, 'Packaged session host is missing');
  const action = (page, action) => page.evaluate(`(async () => {
    const {exchange} = await import(${JSON.stringify('./ui/snippets/' + host)});
    const packet = new TextEncoder().encode(JSON.stringify({version: 1, action: ${JSON.stringify(action)}}));
    const response = await exchange(packet);
    try { return JSON.parse(new TextDecoder().decode(response)); }
    finally { response.fill(0); }
  })()`);
  const status = page => until(async () => {
    try {
      return await action(page, 'Status');
    } catch (error) {
      // The egui startup may still be waiting for its own initial status request.
      if (!error.message.includes('Confidex session request already pending')) throw error;
      return false;
    }
  }, 'session status');
  assert.deepEqual(await status(session), {Ok: 'Disconnected'});
  assert.deepEqual(await action(session, {Connect: {
    name: 'Synthetic extension vault', server: origin + '/', credentials: {...credentials, password: 'incorrect'},
  }}), {Err: 'Auth'});
  assert((await action(session, {Connect: {
    name: 'Synthetic extension vault', server: origin + '/', credentials,
  }})).Ok?.Opened?.can_sync, 'Test vault did not connect');
  for (let step = 0; step < 16; step++) {
    const report = (await action(session, 'Sync')).Ok?.Synced;
    assert(report && !report.conflicts, 'Test vault sync failed');
    if (!report.more) break;
  }
  const expected = {Ok: {Logins: {rows: [{title: 'Synthetic login', username: 'chromium-fixture@example.test'}], next: null}}};
  assert.deepEqual(await action(session, {Logins: {after: null}}), expected);
  const plaintextFound = await session.evaluate(`(async () => {
    const forbidden = ${JSON.stringify([password, credentials.key, loginPassword, 'chromium-fixture@example.test'])};
    const database = await new Promise((resolve, reject) => {
      const open = indexedDB.open('confidex');
      open.onsuccess = () => resolve(open.result);
      open.onerror = reject;
    });
    try {
      if (forbidden.some(secret => JSON.stringify(localStorage).includes(secret))) return true;
      for (const name of database.objectStoreNames) {
        const rows = await new Promise((resolve, reject) => {
          const query = database.transaction(name).objectStore(name).getAll();
          query.onsuccess = () => resolve(query.result);
          query.onerror = reject;
        });
        const text = JSON.stringify(rows, (_, value) => ArrayBuffer.isView(value)
          ? new TextDecoder().decode(value) : value);
        if (forbidden.some(secret => text.includes(secret))) return true;
      }
      return false;
    } finally { database.close(); }
  })()`);
  assert.equal(plaintextFound, false, 'Plaintext appeared in extension storage');

  await command('Target.closeTarget', {targetId: session.targetId});
  const reopened = await newTab(command, extensionUrl);
  await waitForUi(reopened);
  assert.equal((await status(reopened)).Ok?.Locked?.name, 'Synthetic extension vault');
  assert.deepEqual(await action(reopened, {Logins: {after: null}}), {Err: 'Locked'});
  await new Promise(resolve => {
    server.close(resolve);
    server.closeAllConnections();
  });
  assert((await action(reopened, {Unlock: credentials})).Ok?.Opened, 'Offline unlock failed');
  assert.deepEqual(await action(reopened, {Logins: {after: null}}), expected);
  console.log(JSON.stringify({browser: browser.product, syncFromWeb: true, offlineUnlock: true,
    plaintextInBrowserStorage: false}));

  if (option !== '--vault-only') {
    server.listen(Number(new URL(origin).port), '127.0.0.1');
    await once(server, 'listening');
    const cspPage = await newTab(command, `chrome-extension://${cspId}/session.html`);
    await cspPage.evaluate(`chrome.scripting.registerContentScripts([{
      id: 'content-smoke', matches: ['https://127.0.0.1/*'], world: 'ISOLATED',
      js: ['content-bootstrap.js'], runAt: 'document_start',
    }])`);
    const inspect = async path => {
      const url = origin + path;
      const site = await newTab(command, url);
      assert.equal(await site.evaluate("typeof globalThis.confidexContent"), 'undefined');
      return cspPage.evaluate(`(async () => {
        const [tab] = await chrome.tabs.query({url: ${JSON.stringify(url)}});
        const [result] = await chrome.scripting.executeScript({
          target: {tabId: tab.id}, world: 'ISOLATED',
          func: async () => {
            try {
              return {detected: (await globalThis.confidexContent).has_password_field(document)};
            } catch (error) {
              return {detected: false, error: String(error)};
            }
          },
        });
        return result.result;
      })()`);
    };
    const ordinary = await inspect('/ordinary');
    const strict = await inspect('/strict');
    console.log(JSON.stringify({ordinary, strict}));
    assert.equal(ordinary?.detected, true, 'Content WASM did not work on the control page');
    assert.equal(strict?.detected, true, 'Content WASM did not work under strict site CSP');
  }
} finally {
  server?.closeAllConnections();
  server?.close();
  await Promise.all([chrome, daemon].map(async child => {
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    child.kill('SIGKILL');
    await once(child, 'exit');
  }));
  await rm(directory, {recursive: true, force: true});
}

function devTools(child) {
  const pending = new Map();
  let sequence = 0;
  let buffer = '';
  child.stdio[4].setEncoding('utf8');
  child.stdio[4].on('data', chunk => {
    const frames = (buffer + chunk).split('\0');
    buffer = frames.pop();
    for (const frame of frames) {
      const response = JSON.parse(frame);
      const finish = pending.get(response.id);
      if (!finish) continue;
      pending.delete(response.id);
      finish(response);
    }
  });
  return (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`DevTools timed out: ${method}`));
    }, 45_000);
    pending.set(id, response => {
      clearTimeout(timer);
      if (response.error) reject(new Error(`DevTools ${method}: ${response.error.message}`));
      else resolve(response.result);
    });
    child.stdio[3].write(JSON.stringify({id, method, params, sessionId}) + '\0');
  });
}

async function until(check, description) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const result = await check();
    if (result) return result;
    await delay(100);
  }
  throw new Error(`Browser did not reach ${description}`);
}

async function attach(command, targetId) {
  const {sessionId} = await command('Target.attachToTarget', {targetId, flatten: true});
  return {targetId, async evaluate(expression) {
    const result = await command('Runtime.evaluate', {
      expression, awaitPromise: true, returnByValue: true,
    }, sessionId);
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description ?? 'Browser evaluation failed');
    }
    return result.result.value;
  }};
}

async function waitForUi(tab) {
  await until(() => tab.evaluate("document.querySelector('#session-text-input') !== null"), 'egui startup');
}

async function newTab(command, url) {
  const {targetId} = await command('Target.createTarget', {url});
  const page = await attach(command, targetId);
  await until(() => page.evaluate(`location.href === ${JSON.stringify(url)} && document.readyState === 'complete'`), 'page load');
  return page;
}
