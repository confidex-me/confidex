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

const [chromePath, extensionPath, webPath, daemonPath, ...options] = process.argv.slice(2);
assert(daemonPath, 'Usage: node browser-check.mjs CHROME EXTENSION WEB SYNC_DAEMON [--vault-only] [--interactive-permission]');
assert(options.every(option => ['--vault-only', '--interactive-permission'].includes(option)), 'Unknown check option');
const interactive = options.includes('--interactive-permission');
const directory = await mkdtemp(join(tmpdir(), 'confidex-extension-'));
let chrome, daemon, server;
const password = 'public-extension-master-fixture';
const loginPassword = 'public-extension-login-fixture';
const sessionProtocol = 2;

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
      const frame = req.url === '/ordinary' ? '<iframe src="/seed"></iframe>' : '';
      res.end('<!doctype html><title>CSP fixture</title><input type="password">' + frame);
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
  assert.equal(manifest.externally_connectable, undefined);
  manifest.host_permissions = ['https://127.0.0.1/*'];
  await writeFile(manifestPath, JSON.stringify(manifest));

  chrome = spawn(chromePath, [
    ...(interactive ? [] : ['--headless=new']),
    '--remote-debugging-pipe', '--enable-unsafe-extension-debugging',
    '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
    '--disable-component-update', '--disable-sync', '--enable-unsafe-swiftshader',
    `--ignore-certificate-errors-spki-list=${fingerprint}`,
    `--user-data-dir=${join(directory, 'profile')}`,
  ], {stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe']});
  const command = devTools(chrome);
  const browser = await command('Browser.getVersion');
  await command('Target.setDiscoverTargets', {discover: true});
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
    const packet = new TextEncoder().encode(JSON.stringify({version: ${sessionProtocol}, action: ${JSON.stringify(action)}}));
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

  const hostPermission = "{origins: ['https://*/*']}";
  const permission = () => session.evaluate(`chrome.permissions.contains(${hostPermission})`);
  const registered = () => session.evaluate(`chrome.scripting.getRegisteredContentScripts({
    ids: ['confidex-site-channel'],
  }).then(scripts => scripts.length === 1)`);
  assert.equal(await permission(), false);
  assert.equal(await registered(), false);
  await until(() => session.evaluate("!document.querySelector('#site-permissions').hidden"), 'permission control');
  await session.evaluate("document.querySelector('#site-permissions-toggle').click()");
  assert.equal(await permission(), false, 'A synthetic click requested site access');
  if (interactive) {
    console.log('Accept the HTTPS host permission prompt in the temporary Chromium window.');
  } else {
    // Record prior consent through Chromium's own settings in the disposable
    // profile, so the real optional-permission API can run without a native dialog.
    const settings = await newTab(command, 'chrome://extensions/',
      ['chrome://extensions/', 'edge://extensions/', 'brave://extensions/']);
    await settings.evaluate(`chrome.developerPrivate.addHostPermission(${JSON.stringify(id)}, 'https://*/*')`);
    await command('Target.closeTarget', {targetId: settings.targetId});
    assert.equal(await permission(), false, 'Prior consent activated host access before the click');
  }
  await click(session, '#site-permissions-toggle');
  await until(permission, 'HTTPS site permission', interactive ? 600 : 100);
  await until(registered, 'content channel registration');

  const ordinaryUrl = origin + '/ordinary';
  const strictUrl = origin + '/strict';
  const ordinaryTab = await newTab(command, ordinaryUrl);
  const strictTab = await newTab(command, strictUrl);
  assert.equal(await ordinaryTab.evaluate('globalThis.chrome?.runtime?.id === undefined'), true);
  // A trusted extension page drives test injections even when the session is closed.
  const siteDriver = await newTab(command, `chrome-extension://${id}/session-messages.json`);
  const report = {kind: 'FormPresence', version: 1, hasPassword: true};
  const fromSite = (url, message, allFrames = false) => siteDriver.evaluate(`(async () => {
    const [tab] = await chrome.tabs.query({url: ${JSON.stringify(url)}});
    const results = await chrome.scripting.executeScript({
      target: {tabId: tab.id, allFrames: ${allFrames}}, world: 'ISOLATED',
      args: [${JSON.stringify(message)}],
      func: request => chrome.runtime.sendMessage(request).then(value => value ?? null, () => null),
    });
    return results.map(({frameId, result}) => ({frameId, result}));
  })()`);
  const reportFrom = async url => (await fromSite(url, report))[0].result;
  await until(() => reportFrom(ordinaryUrl), 'validated top-frame report');
  assert.equal(await reportFrom(strictUrl), true, 'Strict CSP blocked the routing channel');
  const frames = await fromSite(ordinaryUrl, report, true);
  assert.equal(frames.find(frame => frame.frameId === 0)?.result, true);
  assert.equal(frames.find(frame => frame.frameId > 0)?.result, false);
  for (const malformed of [
    {...report, version: 2},
    {...report, hasPassword: 'true'},
    {...report, origin: 'https://forged.test', frameId: 0, tabId: 123, documentId: 'abc'},
    {...report, extra: 'x'.repeat(4096)},
    {version: 2, action: 'Lock'},
    {version: 2, action: {Logins: {after: null}}},
    {version: 1, kind: 'ConfidexRoutedForm', context: {}, report},
  ]) {
    const [response] = await fromSite(ordinaryUrl, malformed);
    assert([false, null].includes(response.result), 'An invalid content request was accepted');
  }
  assert.deepEqual(await action(session, {Logins: {after: null}}), expected);
  assert.equal(await session.evaluate(`chrome.runtime.sendMessage(${JSON.stringify(report)})`), false);

  const backgroundUrl = `chrome-extension://${id}/background.js`;
  const targetsAt = (type, url) => command('Target.getTargets')
    .then(({targetInfos}) => targetInfos.filter(target => target.type === type && target.url === url));
  const [background] = await targetsAt('service_worker', backgroundUrl);
  assert(background, 'No MV3 service worker target');
  await session.call('ServiceWorker.enable');
  await session.call('ServiceWorker.stopAllWorkers');
  await until(async () => !(await targetsAt('service_worker', backgroundUrl)).length, 'background stopped');
  assert.equal(await reportFrom(ordinaryUrl), true, 'Restarted background did not route to the live worker');
  const [restarted] = await targetsAt('service_worker', backgroundUrl);
  assert.notEqual(restarted?.targetId, background.targetId);
  assert.deepEqual(await action(session, {Logins: {after: null}}), expected);

  const {frameTree: {frame}} = await ordinaryTab.call('Page.getFrameTree');
  let siteWorld;
  command.on('Runtime.executionContextCreated', ({context}) => {
    if (context.auxData?.frameId === frame.id && context.auxData.type === 'isolated'
        && context.origin === `chrome-extension://${id}`) siteWorld = context.uniqueId;
  });
  await ordinaryTab.call('Runtime.enable');
  const worldId = await until(() => siteWorld, 'existing content script world');
  // CDP targets the existing isolated world. A new scripting injection would
  // fail at the permissions API and never exercise routing after revocation.
  const reportFromExistingDocument = () => ordinaryTab.evaluate(
    `chrome.runtime.sendMessage(${JSON.stringify(report)})`, {uniqueContextId: worldId},
  );
  assert.equal(await reportFromExistingDocument(), true);
  await click(session, '#site-permissions-toggle');
  await until(async () => !await permission() && !await registered(), 'site permission and registration removed');
  assert.equal(await reportFromExistingDocument(), false, 'Revoked access still allowed reports from an open document');
  assert.deepEqual(await action(session, {Logins: {after: null}}), expected);
  await click(session, '#site-permissions-toggle');
  await until(permission, 'site permission restored');
  await until(registered, 'content channel re-registered');

  const duplicateId = await session.evaluate(`(async () => {
    const current = await chrome.tabs.getCurrent();
    const duplicate = await chrome.tabs.duplicate(current.id);
    return duplicate.id;
  })()`);
  assert(Number.isInteger(duplicateId), 'Chrome did not duplicate the Confidex tab');
  await until(() => session.evaluate(`chrome.tabs.get(${duplicateId}).then(() => false, () => true)`),
    'duplicate Confidex tab closes');
  const rivalWorkerRejected = await session.evaluate(`(async () => {
    const worker = new Worker(chrome.runtime.getURL('session-worker.js'), {type: 'module'});
    try {
      const response = await new Promise((resolve, reject) => {
        worker.onmessage = ({data}) => resolve(data);
        worker.onerror = reject;
        const packet = new TextEncoder().encode(JSON.stringify({version: ${sessionProtocol}, action: 'Status'}));
        worker.postMessage(packet, [packet.buffer]);
      });
      return response === null;
    } finally {
      worker.terminate();
    }
  })()`);
  assert.equal(rivalWorkerRejected, true, 'A second worker started a vault session');
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

  const workers = new Map();
  const workerUrl = `chrome-extension://${id}/session-worker.js`;
  command.on('Target.attachedToTarget', ({sessionId, targetInfo}) => {
    if (targetInfo.url === workerUrl) workers.set(sessionId, targetInfo.targetId);
  });
  command.on('Target.detachedFromTarget', ({sessionId}) => workers.delete(sessionId));
  await session.call('Target.setAutoAttach', {
    autoAttach: true, waitForDebuggerOnStart: false, flatten: true, filter: [{type: 'worker'}],
  });
  const currentWorker = () => until(() => {
    for (const [sessionId] of workers) return debuggerSession(command, sessionId);
    return false;
  }, 'session worker attached');
  const shiftWorkerClock = async (worker, shift) => {
    await worker.evaluate(`globalThis.realTime ??= Date.now; Date.now = () => realTime() + ${shift}; true`);
  };
  const idleMs = 15 * 60 * 1000;
  const expiring = await currentWorker();
  await shiftWorkerClock(expiring, idleMs - 15_000);
  assert.equal(await reportFrom(ordinaryUrl), true);
  await click(session, '#session');
  await shiftWorkerClock(expiring, idleMs + 5_000);
  assert.equal(await reportFrom(ordinaryUrl), true, 'A trusted interaction failed to renew the lease');
  assert.deepEqual(await action(session, {Logins: {after: null}}), expected);
  await session.evaluate("window.dispatchEvent(new KeyboardEvent('keydown', {key: 'x'}))");
  await shiftWorkerClock(expiring, 2 * idleMs);
  assert.equal(await reportFrom(ordinaryUrl), false, 'Background or synthetic input renewed the session');
  await until(() => !workers.size, 'expired worker terminates');
  assert.deepEqual(await action(session, {Logins: {after: null}}), {Err: 'Locked'});

  const slowWorker = await currentWorker();
  await slowWorker.call('Runtime.addBinding', {name: 'confidexTestDeriving'});
  let deriving = false;
  command.on('Runtime.bindingCalled', ({name}) => {
    if (name === 'confidexTestDeriving') deriving = true;
  });
  await slowWorker.evaluate(`(() => {
    const handle = self.onmessage;
    self.onmessage = event => {
      if (event.data instanceof Uint8Array) {
        self.onmessage = handle;
        self.confidexTestDeriving('');
        // Model synchronous WASM work across a heartbeat and probe deadline.
        const end = performance.now() + 9000;
        while (performance.now() < end) {}
      }
      return handle(event);
    };
    return true;
  })()`);
  await session.call('Page.bringToFront');
  const [unlock, reportDuringUnlock] = await Promise.all([
    action(session, {Unlock: credentials}),
    until(() => deriving, 'slow unlock started').then(() => reportFrom(ordinaryUrl)),
  ]);
  assert(unlock.Ok?.Opened, 'A slow unlock was interrupted');
  assert.equal(reportDuringUnlock, false, 'Routing accepted a report while the worker was blocked');
  assert.equal(await reportFrom(ordinaryUrl), true, 'Routing did not resume after unlock');

  const stopped = await currentWorker();
  await stopped.evaluate('setTimeout(() => self.close(), 0); true');
  assert.equal(await reportFrom(ordinaryUrl), false, 'A stopped worker allowed routing');
  await until(async () => (await status(session)).Ok?.Locked, 'worker loss locks the vault');
  assert((await action(session, {Unlock: credentials})).Ok?.Opened, 'Unlock after worker loss failed');

  assert.equal((await action(session, 'Lock')).Ok?.Locked?.name, 'Synthetic extension vault');
  assert.deepEqual(await action(session, {Logins: {after: null}}), {Err: 'Locked'});
  assert.equal(await reportFrom(ordinaryUrl), false, 'A locked session allowed routing');
  assert((await action(session, {Unlock: credentials})).Ok?.Opened, 'Could not unlock the original session');
  const timeOrigin = await session.evaluate('performance.timeOrigin');
  await session.call('Page.reload');
  await until(() => session.evaluate(`performance.timeOrigin !== ${timeOrigin}`), 'session reload');
  await waitForUi(session);
  assert.equal((await status(session)).Ok?.Locked?.name, 'Synthetic extension vault');
  assert.equal(await reportFrom(ordinaryUrl), false, 'Reload restored the open session');
  assert((await action(session, {Unlock: credentials})).Ok?.Opened, 'Could not unlock the reloaded session');
  await command('Target.closeTarget', {targetId: session.targetId});
  assert.equal(await reportFrom(ordinaryUrl), false, 'A closed session allowed routing');
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
    duplicateTabClosed: true, rivalWorkerRejected, plaintextInBrowserStorage: false,
    optionalSitePermission: true, senderValidation: true, strictCspRouting: true,
    backgroundRestart: true, idleExpiry: true, workerLoss: true,
    slowUnlock: true, openDocumentAfterRevocation: true}));

  if (!options.includes('--vault-only')) {
    for (const page of [ordinaryTab, strictTab]) {
      await command('Target.closeTarget', {targetId: page.targetId});
    }
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
  const listeners = new Map();
  let sequence = 0;
  let buffer = '';
  child.stdio[4].setEncoding('utf8');
  child.stdio[4].on('data', chunk => {
    const frames = (buffer + chunk).split('\0');
    buffer = frames.pop();
    for (const frame of frames) {
      const response = JSON.parse(frame);
      listeners.get(response.method)?.(response.params);
      const finish = pending.get(response.id);
      if (!finish) continue;
      pending.delete(response.id);
      finish(response);
    }
  });
  const request = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
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
  request.on = (method, handle) => listeners.set(method, handle);
  return request;
}

async function until(check, description, attempts = 100) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    const result = await check();
    if (result) return result;
    await delay(100);
  }
  throw new Error(`Browser did not reach ${description}`);
}

async function click(page, selector) {
  await page.call('Page.bringToFront');
  const {x, y} = await page.evaluate(`(() => {
    const rect = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();
    return {x: rect.x + rect.width / 2, y: rect.y + rect.height / 2};
  })()`);
  for (const type of ['mousePressed', 'mouseReleased']) {
    await page.call('Input.dispatchMouseEvent', {type, x, y, button: 'left', clickCount: 1});
  }
}

async function attach(command, targetId) {
  const {sessionId} = await command('Target.attachToTarget', {targetId, flatten: true});
  return {targetId, ...debuggerSession(command, sessionId)};
}

function debuggerSession(command, sessionId) {
  const call = (method, params) => command(method, params, sessionId);
  return {call, async evaluate(expression, options = {}) {
    const result = await call('Runtime.evaluate', {
      expression, awaitPromise: true, returnByValue: true, ...options,
    });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description ?? 'Browser evaluation failed');
    }
    return result.result.value;
  }};
}

async function waitForUi(tab) {
  await until(() => tab.evaluate("document.querySelector('#session-text-input') !== null"), 'egui startup');
}

async function newTab(command, url, expectedUrls = [url]) {
  const {targetId} = await command('Target.createTarget', {url});
  const page = await attach(command, targetId);
  await until(() => page.evaluate(`${JSON.stringify(expectedUrls)}.includes(location.href) && document.readyState === 'complete'`),
    `page load for ${url}`);
  return page;
}
