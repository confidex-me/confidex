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
let networkBlocked = false;
const password = 'public-extension-master-fixture';
const loginPassword = 'public-extension-login-fixture';
const sessionProtocol = 3;
const offlinePassword = 'public-extension-offline-fixture';
const updatedPassword = 'public-extension-updated-fixture';

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
      if (networkBlocked) {
        req.socket.destroy();
        return;
      }
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

  const launch = () => {
    chrome = spawn(chromePath, [
      ...(interactive ? [] : ['--headless=new']),
      '--remote-debugging-pipe', '--enable-unsafe-extension-debugging',
      '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
      '--disable-component-update', '--disable-sync', '--enable-unsafe-swiftshader',
      `--ignore-certificate-errors-spki-list=${fingerprint}`,
      `--user-data-dir=${join(directory, 'profile')}`,
    ], {stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe']});
    return devTools(chrome);
  };
  const command = launch();
  const browser = await command('Browser.getVersion');
  await command('Target.setDiscoverTargets', {discover: true});
  const {id} = await command('Extensions.loadUnpacked', {path: resolve(extensionPath)});
  const tabTargets = () => command('Target.getTargets', {filter: [{type: 'tab'}]}).then(response => response.targetInfos);
  const previousTargets = new Set((await tabTargets()).map(target => target.targetId));
  const seed = await newTab(command, origin + '/seed');
  await startWebWorker(seed);
  const initialWeb = value => webCommand(seed, value);
  const {Created} = (await initialWeb({Create: {
    name: 'Synthetic web vault', password, remember: false,
  }})).Ok;
  const credentials = {password, key: Created.key};
  const webRecord = Array(16).fill(1);
  const fields = [
    ['username/v1', 'username', 'chromium-fixture@example.test'],
    ['password/v1', 'password', loginPassword],
    ['url/v1', 'url', 'https://example.test'],
  ].map(([type_name, key, value]) => ({
    source: null, name: '', type_name, values: {[key]: value}, opaque: 0, protected: false,
  }));
  assert((await initialWeb({Save: {epoch: 1, draft: {
    record: webRecord, revision: null, title: 'Synthetic login', fields, tags: [],
  }}})).Ok?.Saved, 'Test web login was not saved');
  assert((await initialWeb({SyncConfig: {server: origin + '/'}})).Ok?.Synced);
  await syncWeb(initialWeb, origin);

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
      // Wait for the egui startup request or for the host to retire a stopped worker.
      if (!/Confidex session (request already pending|closed)/.test(error.message)) throw error;
      return false;
    }
  }, 'session status');
  assert.deepEqual(await status(session), {Ok: 'Disconnected'});
  assert.deepEqual(await action(session, {Connect: {
    name: 'Synthetic extension vault', server: origin + '/', credentials: {...credentials, password: 'incorrect'},
  }}), {Err: 'Auth'});
  assert((await action(session, {Connect: {
    name: 'Synthetic extension vault', server: origin + '/', credentials,
  }})).Ok?.Opened, 'Test vault did not connect');
  const list = page => action(page, {Logins: {after: null}}).then(reply => {
    assert(reply.Ok?.Logins, 'Expected login previews');
    return reply.Ok.Logins.page;
  });
  const current = page => until(async () => (await status(page)).Ok?.Opened?.sync === 'Current',
    'automatic synchronization');
  await current(session);
  const expectWebLogin = async page => {
    const {rows, next, issues} = await list(page);
    assert.equal(rows.length, 1);
    assert.deepEqual(rows[0].target.head.record, webRecord);
    assert.equal(rows[0].title, 'Synthetic login');
    assert.equal(rows[0].username, 'chromium-fixture@example.test');
    assert.equal(next, null);
    assert.deepEqual(issues, {ambiguous: false, conflicts: false});
  };
  await expectWebLogin(session);

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
  await newTab(command, strictUrl);
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
    {version: sessionProtocol, action: 'Lock'},
    {version: sessionProtocol, action: {Logins: {after: null}}},
    {version: sessionProtocol, action: {CreateLogin: {record: Array(16).fill(99), login: {
      title: 'Site request', url: ordinaryUrl, username: 'fixture', password: loginPassword,
    }}}},
    {version: 1, kind: 'ConfidexRoutedForm', context: {}, report},
  ]) {
    const [response] = await fromSite(ordinaryUrl, malformed);
    assert([false, null].includes(response.result), 'An invalid content request was accepted');
  }
  await expectWebLogin(session);
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
  await expectWebLogin(session);

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
  await expectWebLogin(session);
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
  await expectWebLogin(session);

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
  await expectWebLogin(session);
  await session.evaluate("window.dispatchEvent(new KeyboardEvent('keydown', {key: 'x'}))");
  await shiftWorkerClock(expiring, 2 * idleMs);
  assert.equal(await reportFrom(ordinaryUrl), false, 'Background or synthetic input renewed the session');
  await until(() => !workers.size, 'expired worker terminates');
  assert.deepEqual(await action(session, {Logins: {after: null}}), {Err: 'Locked'});

  const exiting = await currentWorker();
  await exiting.evaluate(`(() => {
    const handle = self.onmessage;
    self.onmessage = event => {
      if (event.data instanceof Uint8Array) {
        event.data.fill(0);
        self.close();
        return;
      }
      return handle(event);
    };
    return true;
  })()`);
  const beforeExit = await session.evaluate('performance.timeOrigin');
  await assert.rejects(action(session, {Unlock: credentials}), /Confidex session closed/);
  assert.equal(await session.evaluate('performance.timeOrigin'), beforeExit, 'Worker loss reloaded the session');
  assert.equal((await status(session)).Ok?.Locked?.name, 'Synthetic extension vault');

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
  await reopened.call('Emulation.setDeviceMetricsOverride', {
    width: 1000, height: 850, deviceScaleFactor: 1, mobile: false,
  });
  await waitForUi(reopened);
  assert.equal((await status(reopened)).Ok?.Locked?.name, 'Synthetic extension vault');
  assert.deepEqual(await action(reopened, {Logins: {after: null}}), {Err: 'Locked'});
  networkBlocked = true;
  await reopened.call('Page.bringToFront');
  await reopened.evaluate("document.querySelector('#session').focus()");
  await tabAndType(reopened, credentials.key, 'secret key');
  await tabAndType(reopened, credentials.password, 'vault password');
  await press(reopened, 'Enter', 13);
  await until(async () => (await status(reopened)).Ok?.Opened?.sync === 'Offline', 'offline UI unlock');

  // Keyboard order in the session toolbar is Lock, Sync now, New login.
  await reopened.evaluate("document.querySelector('#session').focus()");
  for (let button = 0; button < 3; button++) await press(reopened, 'Tab', 9);
  await press(reopened, 'Enter', 13);
  const login = {
    title: 'Offline login', url: 'https://example.test/account?private=1#login',
    username: 'offline-fixture@example.test', password: offlinePassword,
  };
  // Focus can return to the toolbar when the New login button is disabled by the editor.
  await tabAndType(reopened, login.title, 'new login title', 4);
  await tabAndType(reopened, login.url, 'new login URL');
  await tabAndType(reopened, login.username, 'new login username');
  await tabAndType(reopened, login.password, 'new login password');
  await press(reopened, 'Enter', 13);

  const offline = await until(async () => {
    try {
      return (await list(reopened)).rows.find(row => row.title === login.title);
    } catch (error) {
      if (!error.message.includes('Confidex session request already pending')) throw error;
      return false;
    }
  }, 'login saved through the offline session UI');
  const {record} = offline.target.head;
  const create = {CreateLogin: {record, login}};
  assert.deepEqual(await action(reopened, create), {Err: {Storage: 'Conflict'}});
  const change = {username: null, password: updatedPassword};
  const updated = (await action(reopened, {UpdateLogin: {target: offline.target, change}})).Ok?.Saved;
  assert(updated, 'Offline update did not finish');
  assert.deepEqual(await action(reopened, {UpdateLogin: {target: offline.target, change}}), {Err: {Storage: 'Conflict'}});
  await checkStorage(reopened, [password, credentials.key, loginPassword, offlinePassword,
    updatedPassword, 'chromium-fixture@example.test', 'offline-fixture@example.test']);

  // Shut down Chromium while the server is still unreachable. Reuse only the
  // temporary profile, just as a user would after a browser restart.
  const exited = once(chrome, 'exit');
  await Promise.race([command('Browser.close'), exited]);
  await exited;
  const browserAfterRestart = launch();
  assert.equal((await browserAfterRestart('Extensions.loadUnpacked', {path: resolve(extensionPath)})).id, id);
  const recovered = await newTab(browserAfterRestart, extensionUrl);
  await waitForUi(recovered);
  assert((await status(recovered)).Ok?.Locked, 'Browser restart restored an unlocked session');
  assert.deepEqual(await action(recovered, create), {Err: 'Locked'});
  assert((await action(recovered, {Unlock: credentials})).Ok?.Opened, 'Restarted offline unlock failed');
  assert.deepEqual((await list(recovered)).rows.find(row => row.title === 'Offline login')?.target.head, updated);

  networkBlocked = false;
  await current(recovered);
  const main = await newTab(browserAfterRestart, origin + '/seed');
  await startWebWorker(main);
  const web = value => webCommand(main, value);
  const {Catalog} = (await web('Catalog')).Ok;
  assert((await web({Unlock: {vault: Catalog[0].id, ...credentials, remember: false}})).Ok?.Opened);
  await syncWeb(web, origin);
  const read = () => web({Open: {record}});
  const {Draft: draft} = (await read()).Ok;
  assert.equal(draft.title, 'Offline login');
  assert.deepEqual(draft.fields.map(field => field.type_name), ['username/v1', 'password/v1', 'url/v1', 'note/v1']);
  assert(draft.fields[1].values.password === updatedPassword, 'Web cache did not receive the offline update');
  assert.equal(draft.fields[2].values.url, 'https://example.test');
  assert.deepEqual(draft.revision, updated.revision);

  draft.fields[0].values.username = 'edited-in-web@example.test';
  draft.fields[3].values.text = 'Note edited in the main app';
  const fromWeb = (await web({Save: {draft, epoch: Date.now()}})).Ok?.Saved;
  assert(fromWeb, 'Web update did not finish');
  await syncWeb(web, origin);
  await syncExtension(recovered, action);
  assert.deepEqual(await action(recovered, {UpdateLogin: {target: {head: updated, field: 1}, change}}), {Err: {Storage: 'Conflict'}});
  const common = (await list(recovered)).rows.find(row => row.title === 'Offline login');
  assert.equal(common.username, 'edited-in-web@example.test');
  assert.deepEqual(common.target.head, fromWeb);

  networkBlocked = true;
  const localBranch = (await action(recovered, {UpdateLogin: {target: common.target, change: {
    username: 'local-branch@example.test', password: updatedPassword,
  }}})).Ok?.Saved;
  assert(localBranch, 'Extension conflict fixture was not saved');
  const branchDraft = (await read()).Ok.Draft;
  branchDraft.fields[0].values.username = 'remote-branch@example.test';
  const remoteBranch = (await web({Save: {draft: branchDraft, epoch: Date.now()}})).Ok?.Saved;
  assert(remoteBranch, 'Web conflict fixture was not saved');
  networkBlocked = false;
  await syncWeb(web, origin);
  await syncExtension(recovered, action);
  const conflicted = await list(recovered);
  assert(conflicted.issues.conflicts, 'Conflict was not reported');
  assert(!conflicted.rows.some(row => row.title === 'Offline login'), 'Conflicted login remained selectable');
  assert.deepEqual(await action(recovered, {UpdateLogin: {target: {head: localBranch, field: 1}, change}}), {Err: {Storage: 'Conflict'}});
  const conflict = (await syncWeb(web, origin)).conflicts.find(entry => entry.record.every((byte, i) => byte === record[i]));
  assert(conflict, 'The main client did not offer conflict resolution');
  const revisionKey = revision => revision.join(',');
  assert.deepEqual([conflict.local.revision, conflict.remote.revision].map(revisionKey).sort(),
    [localBranch.revision, remoteBranch.revision].map(revisionKey).sort());
  assert((await web({CheckSync: {server: origin + '/'}})).Ok?.Synced?.conflicts.length,
    'An unchanged checkpoint hid an unresolved conflict');
  assert.deepEqual(await read(), {Err: {Storage: 'Conflict'}});
  assert((await web({Resolve: {record, local: conflict.local.revision, remote: conflict.remote.revision,
    keep_local: revisionKey(conflict.local.revision) === revisionKey(remoteBranch.revision), epoch: Date.now()}})).Ok?.Synced);
  await syncWeb(web, origin);
  await syncExtension(recovered, action);
  const resolved = await list(recovered);
  assert(!resolved.issues.conflicts, 'Resolved login still showed a conflict');
  const resolvedLogin = resolved.rows.find(row => row.title === 'Offline login');
  assert.equal(resolvedLogin?.username, 'remote-branch@example.test');

  const onlineWrite = (await action(recovered, {UpdateLogin: {target: resolvedLogin.target, change: {
    username: 'synchronized-after-save@example.test', password: updatedPassword,
  }}})).Ok?.Saved;
  assert(onlineWrite, 'Online write did not finish');
  await current(recovered);
  await syncWeb(web, origin);
  const finalDraft = (await read()).Ok.Draft;
  assert.deepEqual(finalDraft.revision, onlineWrite.revision);
  assert.equal(finalDraft.fields[3].values.text, 'Note edited in the main app');

  console.log(JSON.stringify({browser: browser.product, syncFromWeb: true, syncToWeb: true,
    offlineUnlock: true, newLoginThroughUi: true, offlineWritesSurviveBrowserRestart: true, automaticSync: true,
    duplicateCreateRejected: true, staleUpdateRejected: true, conflictPreservedAndResolved: true,
    duplicateTabClosed: true, rivalWorkerRejected, plaintextInBrowserStorage: false,
    optionalSitePermission: true, senderValidation: true, strictCspRouting: true,
    backgroundRestart: true, idleExpiry: true, workerLoss: true,
    slowUnlock: true, workerLossDuringUnlock: true, openDocumentAfterRevocation: true}));

  if (!options.includes('--vault-only')) {
    const {id: probeId} = await browserAfterRestart('Extensions.loadUnpacked', {path: cspExtension});
    const cspPage = await newTab(browserAfterRestart, `chrome-extension://${probeId}/session.html`);
    await cspPage.evaluate(`chrome.scripting.registerContentScripts([{
      id: 'content-smoke', matches: ['https://127.0.0.1/*'], world: 'ISOLATED',
      js: ['content-bootstrap.js'], runAt: 'document_start',
    }])`);
    const inspect = async path => {
      const url = origin + path;
      const site = await newTab(browserAfterRestart, url);
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

async function startWebWorker(page) {
  return page.evaluate(`(async () => {
    const worker = new Worker('/worker.js', {type: 'module'});
    await new Promise((resolve, reject) => {
      worker.onmessage = ({data}) => { if (data === 'ready') resolve(); };
      worker.onerror = reject;
    });
    globalThis.fixtureCall = command => new Promise((resolve, reject) => {
      worker.onerror = reject;
      worker.onmessage = ({data}) => {
        try { resolve(JSON.parse(new TextDecoder().decode(data)).result); }
        catch (error) { reject(error); }
        finally { data.fill(0); }
      };
      const input = new TextEncoder().encode(JSON.stringify({generation: 1, command}));
      worker.postMessage(input, [input.buffer]);
    });
  })()`);
}

function webCommand(page, command) {
  return page.evaluate(`fixtureCall(${JSON.stringify(command)})`);
}

async function syncWeb(web, origin) {
  for (let step = 0; step < 16; step++) {
    const report = (await web({Sync: {server: origin + '/'}})).Ok?.Synced;
    assert(report, 'Web synchronization failed');
    if (!report.more) return report;
  }
  throw new Error('Web synchronization did not finish');
}

async function syncExtension(page, action) {
  for (let step = 0; step < 16; step++) {
    const report = (await action(page, 'Sync')).Ok?.Synced;
    assert(report?.sync === 'Current' || report?.sync === 'Pending', 'Extension synchronization failed');
    if (!report.more) return;
  }
  throw new Error('Extension synchronization did not finish');
}

async function checkStorage(page, forbidden) {
  const plaintextFound = await page.evaluate(`(async () => {
    const forbidden = ${JSON.stringify(forbidden)};
    const database = await new Promise((resolve, reject) => {
      const open = indexedDB.open('confidex');
      open.onsuccess = () => resolve(open.result);
      open.onerror = reject;
    });
    try {
      const settings = [JSON.stringify(localStorage)];
      if (chrome.storage?.local) settings.push(JSON.stringify(await chrome.storage.local.get()));
      if (forbidden.some(secret => settings.some(value => value.includes(secret)))) return true;
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

async function press(page, key, windowsVirtualKeyCode) {
  for (const type of ['rawKeyDown', 'keyUp']) {
    await page.call('Input.dispatchKeyEvent', {type, key, code: key, windowsVirtualKeyCode});
  }
  await page.evaluate('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
}

async function tabAndType(page, text, field, tabStops = 1) {
  for (let step = 0; step < tabStops; step++) {
    await press(page, 'Tab', 9);
    if (await page.evaluate("document.activeElement.id === 'session-text-input'")) {
      await page.call('Input.insertText', {text});
      return;
    }
  }
  throw new Error(`Browser did not focus ${field}`);
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
