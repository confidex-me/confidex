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
let scenario = 'start HTTPS fixtures';
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
    if (req.url === '/save-submit') {
      req.resume();
      res.writeHead(303, {Location: '/fill'}).end();
      return;
    }
    if (req.url.startsWith('/fill') || req.url === '/strict' || req.url === '/ordinary') {
      res.setHeader('Content-Type', 'text/html');
      if (req.url === '/strict' || req.url === '/fill-save') {
        res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'none'; object-src 'none'");
      }
      const frame = req.url === '/ordinary' ? '<iframe src="/seed"></iframe>' : '';
      const login = '<form id="login" method="post"><label>User <input id="user" autocomplete="username"></label>'
        + '<input id="password" name="password" type="password" autocomplete="current-password"><button>Sign in</button></form>';
      const pages = {
        '/fill': login,
        '/fill-first': '<form id="first"><input id="user" autocomplete="username"><button>Next</button></form>',
        '/fill-second': '<form id="second" method="post"><input id="password" type="password" autocomplete="current-password"></form>',
        '/fill-card': '<form method="post"><label>Card security code <input name="cvc" type="password" autocomplete="cc-csc"></label>'
          + '<button>Pay</button></form>',
        '/fill-empty': '<main></main>',
        '/fill-iframe': '<iframe src="/fill"></iframe>',
        '/fill-save': '<form method="post" action="/save-submit"><input id="user" autocomplete="username">'
          + '<input id="password" type="password" autocomplete="current-password"><button>Submit</button></form>',
        '/fill-register': '<form method="post" action="/save-submit"><input id="user" autocomplete="username">'
          + '<input id="password" type="password" autocomplete="new-password">'
          + '<input id="confirmation" type="password" autocomplete="new-password"><button>Register</button></form>',
        '/fill-save-first': '<form action="/fill-save-second"><input id="user" autocomplete="username">'
          + '<button>Next</button></form>',
        '/fill-save-second': '<form method="post" action="/save-submit">'
          + '<input id="password" type="password" autocomplete="current-password"><button>Submit</button></form>',
      };
      const path = req.url.split('?')[0];
      res.end('<!doctype html><title>Form fixture</title>' + (pages[path] ?? '<input type="password">') + frame);
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
  manifest.web_accessible_resources = [{
    resources: ['content/content.js', 'content/content_bg.wasm'], matches: ['https://127.0.0.1/*'],
  }];
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
    ['url/v1', 'url', origin + '/account?path=ignored#login'],
  ].map(([type_name, key, value]) => ({
    source: null, name: '', type_name, values: {[key]: value}, opaque: 0, protected: false,
  }));
  assert((await initialWeb({Save: {epoch: 1, draft: {
    record: webRecord, revision: null, title: 'Synthetic login', fields, tags: [],
  }}})).Ok?.Saved, 'Test web login was not saved');
  assert((await initialWeb({SyncConfig: {server: origin + '/'}})).Ok?.Synced);
  await syncWeb(initialWeb, origin);

  scenario = 'toolbar popup and session';
  const extensionUrl = `chrome-extension://${id}/session.html`;
  const seedTab = (await tabTargets()).find(target => !previousTargets.has(target.targetId));
  assert(seedTab, 'No top-level tab target for the toolbar action');
  const popupUrl = `chrome-extension://${id}/popup.html`;
  await command('Extensions.triggerAction', {id, targetId: seedTab.targetId});
  const popup = await until(async () => {
    const {targetInfos} = await command('Target.getTargets');
    const target = targetInfos.find(target => target.url === popupUrl);
    if (target) return attach(command, target.targetId);
    return false;
  }, 'toolbar opens popup');
  const popupCall = (page, action) => page.evaluate(`chrome.runtime.sendMessage(
    ${JSON.stringify({kind: 'ConfidexPopup', version: 1, action})})`);
  await until(() => popup.evaluate("!document.getElementById('startup')"), 'egui popup startup');
  assert.equal(await popupCall(popup, {Discover: {after: null}}), 'Locked');
  await until(() => popup.evaluate("document.activeElement?.id === 'popup'"), 'keyboard focus in popup');
  await press(popup, 'Tab', 9);
  // Opening the session closes the toolbar popup while Chrome dispatches the key.
  await popup.call('Input.dispatchKeyEvent', {type: 'rawKeyDown', key: 'Enter', code: 'Enter',
    windowsVirtualKeyCode: 13});
  const tab = await until(async () => {
    const {targetInfos} = await command('Target.getTargets');
    return targetInfos.find(target => target.type === 'page' && target.url === extensionUrl);
  }, 'popup opens the session tab');
  const session = await attach(command, tab.targetId);
  await waitForUi(session);
  await until(() => session.evaluate("navigator.locks.query().then(s => s.held.some(lock => lock.name === 'confidex-session'))"), 'session ownership');
  // Use a trusted extension page to keep the same popup entry point open when
  // DevTools changes tabs to simulate a document replacement.
  const popupDriver = await newTab(command, popupUrl);
  assert.equal(await popupCall(popupDriver, 'OpenSession'), 'Live');
  assert.equal((await command('Target.getTargets')).targetInfos
    .filter(target => target.type === 'page' && target.url === extensionUrl).length, 1);

  scenario = 'connect and synchronize fixtures';
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
    assert.equal(rows[0].fields, 3);
    assert.equal(next, null);
    assert.deepEqual(issues, {ambiguous: false, conflicts: false});
  };
  await expectWebLogin(session);

  scenario = 'grant access and validate content senders';
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

  scenario = 'autofill on ordinary HTTPS and strict CSP';
  const discover = async page => {
    await page.call('Page.bringToFront');
    return until(async () => {
      const result = await popupCall(popupDriver, {Discover: {after: null}});
      return result !== 'Busy' && result;
    }, 'autofill discovery');
  };
  const choice = async page => {
    const result = await discover(page);
    assert(result.Site, `Expected a supported site, got ${JSON.stringify(result)}`);
    return result.Site;
  };
  const fillPacket = (site, form = 0, account = 0) => ({
    Fill: {operation: site.operation, form: site.forms[form].target.form, target: site.matches.rows[account].target},
  });
  const runFill = packet => popupCall(popupDriver, packet);
  const expectEmpty = page => page.evaluate("Array.from(document.querySelectorAll('input')).every(input => input.value === '')");
  const isFilled = (page, user = true, pass = true) => page.evaluate(`(() => {
    const root = document.querySelector('#shadow')?.shadowRoot ?? document;
    return (root.querySelector('#user')?.value === 'chromium-fixture@example.test') === ${user}
      && (root.querySelector('#password, input[type=password]')?.value === ${JSON.stringify(loginPassword)}) === ${pass};
  })()`);

  const normal = await newTab(command, origin + '/fill');
  await normal.evaluate(`(() => {
    window.filledEvents = [];
    const form = document.querySelector('form');
    for (const type of ['input', 'change', 'submit']) {
      form.addEventListener(type, event => window.filledEvents.push(type + ':' + event.target.id));
    }
  })()`);
  const normalSite = await choice(normal);
  assert.equal(normalSite.origin, origin);
  assert.equal(normalSite.matches.rows.length, 1);
  assert(!JSON.stringify(normalSite).includes(loginPassword), 'Popup received the password');
  const normalPacket = fillPacket(normalSite);
  assert.equal((await fromSite(origin + '/fill', {
    kind: 'ConfidexPopup', version: 1, action: normalPacket,
  }))[0].result, 'Error');
  assert(await expectEmpty(normal));
  assert.equal(await runFill(normalPacket), 'Filled');
  assert(await isFilled(normal));
  assert.deepEqual(await normal.evaluate('window.filledEvents'),
    ['input:user', 'change:user', 'input:password', 'change:password']);
  assert.equal(await runFill(normalPacket), 'Changed', 'A fill operation could be replayed');

  const strict = await newTab(command, strictUrl);
  assert.equal(await runFill(fillPacket(await choice(strict))), 'Filled');
  assert(await isFilled(strict, false), 'Autofill failed under strict CSP');

  scenario = 'masked non-login fields and GET form submissions';
  const card = await newTab(command, origin + '/fill-card');
  assert.equal((await choice(card)).forms.length, 0, 'A masked CVC was treated as a login');
  await card.evaluate("document.querySelector('input').autocomplete = 'cc-csc' + ' '.repeat(80) + 'webauthn'");
  assert.equal((await choice(card)).forms.length, 0, 'Truncating autocomplete turned an explicit role into a password');
  assert(await expectEmpty(card));

  const methods = await newTab(command, origin + '/fill');
  const beforeMethodChange = fillPacket(await choice(methods));
  await methods.evaluate(`document.querySelector('form').setAttribute('method', 'get')`);
  assert.equal(await runFill(beforeMethodChange), 'Changed', 'Changing the form to GET kept the fill operation valid');
  assert.equal((await choice(methods)).forms.length, 0, 'An explicit GET form accepted the login');
  assert(await expectEmpty(methods));
  await methods.evaluate(`document.querySelector('form').removeAttribute('method')`);
  assert.equal((await choice(methods)).forms.length, 0, 'The default GET form accepted the login');
  await methods.evaluate(`document.querySelector('form').setAttribute('method', 'invalid')`);
  assert.equal((await choice(methods)).forms.length, 0, 'An invalid method defaulted to GET but accepted the login');
  await methods.evaluate(`document.querySelector('form').setAttribute('method', 'post')`);

  const beforeOverride = fillPacket(await choice(methods));
  await methods.evaluate(`document.querySelector('button').setAttribute('formmethod', 'get')`);
  assert.equal(await runFill(beforeOverride), 'Changed', 'Changing a submitter to GET kept the fill operation valid');
  assert.equal((await choice(methods)).forms.length, 0, 'A GET submitter overrode POST and accepted the login');
  assert(await expectEmpty(methods));
  await methods.evaluate(`document.querySelector('button').disabled = true`);
  assert.equal((await choice(methods)).forms.length, 1, 'A disabled GET submitter blocked a POST form');
  await methods.evaluate(`document.body.insertAdjacentHTML('beforeend',
    '<input type="image" form="login" formmethod="invalid">')`);
  assert.equal((await choice(methods)).forms.length, 0, 'An external image submitter defaulted to GET and accepted the login');
  await command('Target.closeTarget', {targetId: methods.targetId});

  scenario = 'SPA, Shadow DOM and stale form selections';
  const spa = await newTab(command, origin + '/fill-empty');
  assert.equal((await choice(spa)).forms.length, 0);
  await spa.evaluate(`document.querySelector('main').innerHTML =
    '<div id="shadow"></div>'`);
  await spa.evaluate(`document.querySelector('#shadow').attachShadow({mode:'open'}).innerHTML =
    '<form method="post" aria-label="Sign in"><input hidden autocomplete="username"><input readonly autocomplete="username">'
    + '<input disabled autocomplete="username"><input id="user" autocomplete="username">'
    + '<input id="password" type="password" autocomplete="current-password"></form>'`);
  const shadow = await choice(spa);
  assert.equal(shadow.forms[0].label, 'Sign in');
  assert.equal(await runFill(fillPacket(shadow)), 'Filled');
  assert(await isFilled(spa));
  assert(await spa.evaluate(`Array.from(document.querySelector('#shadow').shadowRoot
    .querySelectorAll('[hidden], [readonly], [disabled]')).every(input => input.value === '')`));

  const replacement = await newTab(command, origin + '/fill');
  const selection = fillPacket(await choice(replacement));
  await replacement.evaluate(`document.querySelector('form').replaceWith(document.querySelector('form').cloneNode(true))`);
  assert.equal(await runFill(selection), 'Changed');
  assert(await expectEmpty(replacement));
  const changedDestination = fillPacket(await choice(replacement));
  await replacement.evaluate("document.querySelector('button').formAction = 'https://localhost/other'");
  assert.equal(await runFill(changedDestination), 'Changed');
  assert(await expectEmpty(replacement));
  assert.equal((await choice(replacement)).forms.length, 0);
  await replacement.evaluate("document.querySelector('button').removeAttribute('formaction')");
  await replacement.evaluate(`(() => {
    const form = document.querySelector('form');
    form.setAttribute('action', 'http://127.0.0.1/downgrade');
    form.insertAdjacentHTML('beforeend', '<input type="hidden" name="action">');
  })()`);
  assert.equal((await choice(replacement)).forms.length, 0, 'A named control hid the unsafe action');
  await replacement.evaluate("document.querySelector('form').removeAttribute('action')");
  await replacement.evaluate("document.querySelector('#password').autocomplete = 'section-login new-password'");
  assert.equal((await choice(replacement)).forms.length, 0);
  await replacement.evaluate("document.querySelector('#password').autocomplete = 'current-password'");
  const spaNavigation = fillPacket(await choice(replacement));
  await replacement.evaluate("history.pushState({}, '', '/fill?step=second')");
  assert.equal(await runFill(spaNavigation), 'Changed');
  const replacedDocument = fillPacket(await choice(replacement));
  await replacement.call('Page.navigate', {url: origin + '/fill'});
  await until(() => replacement.evaluate('document.readyState === "complete" && location.search === ""'), 'replacement document ready');
  assert.equal(await runFill(replacedDocument), 'Changed');
  assert(await expectEmpty(replacement));

  scenario = 'two-step sign-ins, frames and origin isolation';
  const first = await newTab(command, origin + '/fill-first');
  assert.equal(await runFill(fillPacket(await choice(first))), 'Filled');
  assert(await isFilled(first, true, false));
  await first.call('Page.navigate', {url: origin + '/fill-second'});
  await until(() => first.evaluate('location.pathname === "/fill-second" && document.readyState === "complete"'), 'second login step');
  const second = await choice(first);
  assert.deepEqual(second.preferred, second.matches.rows[0].target);
  assert.equal(await runFill(fillPacket(second)), 'Filled');
  assert(await isFilled(first, false));

  const iframe = await newTab(command, origin + '/fill-iframe');
  assert.equal((await choice(iframe)).forms.length, 0);
  const closed = await newTab(command, origin + '/fill-empty');
  await closed.evaluate(`(document.querySelector('main').attachShadow({mode:'closed'})).innerHTML =
    '<input autocomplete="username"><input type="password">' `);
  assert.equal((await choice(closed)).forms.length, 0);
  const foreign = await newTab(command, origin.replace('127.0.0.1', 'localhost') + '/fill');
  assert.equal((await choice(foreign)).matches.rows.length, 0);
  await first.call('Page.navigate', {url: origin.replace('127.0.0.1', 'localhost') + '/fill-first'});
  await until(() => first.evaluate('location.hostname === "localhost"'), 'origin transition');
  await first.call('Page.navigate', {url: origin + '/fill-second'});
  await until(() => first.evaluate('location.pathname === "/fill-second" && document.readyState === "complete"'), 'return to first origin');
  assert.equal((await choice(first)).preferred, null);

  scenario = 'session, permissions, online and offline write regressions';
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
  const revokedChoice = fillPacket(await choice(replacement));
  await click(session, '#site-permissions-toggle');
  await until(async () => !await permission() && !await registered(), 'site permission and registration removed');
  assert.equal(await reportFromExistingDocument(), false, 'Revoked access still allowed reports from an open document');
  await replacement.call('Page.bringToFront');
  assert.equal(await runFill(revokedChoice), 'Changed');
  assert(await expectEmpty(replacement));
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
    width: 1000, height: 1050, deviceScaleFactor: 1, mobile: false,
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
  const noteLines = ['Offline note from the extension', 'Second line'];
  const tags = ['admin', 'work'];
  const editedTags = ['admin', 'project'];
  const login = {
    title: 'Offline login', username: 'offline-fixture@example.test', password: offlinePassword,
    url: 'https://example.test/account?private=1#login', notes: noteLines.join('\n'), tags,
  };
  await until(() => reopened.evaluate("document.activeElement.id === 'session-text-input'"), 'record title focus');
  await reopened.call('Input.insertText', {text: login.title});
  await tabAndType(reopened, login.username, 'new login username');
  await tabAndType(reopened, login.password, 'new login password');
  await tabAndType(reopened, login.url, 'new login website');
  await tabAndType(reopened, noteLines[0], 'new login notes');
  await press(reopened, 'Enter', 13);
  await reopened.call('Input.insertText', {text: noteLines[1]});
  await tabAndType(reopened, ` ${tags[0]} `, 'new login tag');
  await press(reopened, 'Enter', 13);
  await reopened.call('Input.insertText', {text: tags[1]});
  await press(reopened, 'Enter', 13);
  await press(reopened, 'Tab', 9);
  await press(reopened, 'Enter', 13);

  const waitForLogin = title => until(async () => {
    try {
      return (await list(reopened)).rows.find(row => row.title === title);
    } catch (error) {
      if (!error.message.includes('Confidex session request already pending')) throw error;
      return false;
    }
  }, `saved login ${title}`);
  const offline = await waitForLogin(login.title);
  assert.equal(offline.fields, 4);
  const {record} = offline.target.head;
  const create = {CreateLogin: {record, login}};
  assert.deepEqual(await action(reopened, create), {Err: {Storage: 'Conflict'}});
  const openEditor = (page, target) => action(page, {LoginEditor: {target}});
  const {fields: savedFields} = (await openEditor(reopened, offline.target)).Ok.LoginEditor;
  assert.deepEqual(savedFields, {
    title: login.title, username: login.username, url: 'https://example.test', notes: login.notes, tags,
  });

  // The session toolbar contributes three tab stops before the login actions.
  const editRow = async title => {
    const rowIndex = (await list(reopened)).rows.findIndex(row => row.title === title);
    assert(rowIndex >= 0);
    await activateFromMargin(reopened, rowIndex + 4);
    await until(() => reopened.evaluate("document.activeElement.id === 'session-text-input'"), 'edit title focus');
  };
  await editRow(login.title);
  const edited = {
    title: 'Edited offline login',
    url: 'https://edited.example.test/path',
    origin: 'https://edited.example.test',
    notes: 'Edited notes from Chromium',
  };
  await replaceFocusedText(reopened, edited.title);
  for (const field of ['username', 'password', 'website']) {
    await press(reopened, 'Tab', 9);
    assert(await reopened.evaluate("document.activeElement.id === 'session-text-input'"),
      `Browser did not focus edit ${field}`);
  }
  await replaceFocusedText(reopened, edited.url);
  await press(reopened, 'Tab', 9);
  await replaceFocusedText(reopened, edited.notes);
  for (let stop = 0; stop < tags.length + 2; stop++) await press(reopened, 'Tab', 9);
  await press(reopened, 'Enter', 13);

  const editedLogin = await waitForLogin(edited.title);
  assert.deepEqual((await openEditor(reopened, editedLogin.target)).Ok?.LoginEditor?.fields, {
    ...savedFields, title: edited.title, url: edited.origin, notes: edited.notes,
  });
  const change = {username: null, password: updatedPassword};
  assert.deepEqual(await action(reopened, {UpdateLogin: {target: offline.target, change}}), {Err: {Storage: 'Conflict'}});
  assert.deepEqual(await openEditor(reopened, offline.target), {Err: {Storage: 'Conflict'}});
  const updated = (await action(reopened, {UpdateLogin: {
    target: editedLogin.target, change: {username: null, password: null, tags: editedTags},
  }})).Ok?.Saved;
  assert(updated, 'Tag-only write did not finish');
  // A separate write advances the head while the editor still has an unsaved password.
  // Keep this fixture offline so the later restart still exercises the durable queue.
  const draftPassword = 'public-extension-conflict-draft';
  const draftWebsite = 'https://recovered.example.test';
  const currentTitle = 'Changed by another client';
  const currentTags = ['concurrent-tag'];
  const currentNote = 'Changed during revision review';
  await reopened.call('Emulation.setDeviceMetricsOverride', {
    width: 1000, height: 1400, deviceScaleFactor: 1, mobile: false,
  });
  const reviewTarget = (await list(reopened)).rows.find(row => row.title === 'Synthetic login').target;
  await editRow('Synthetic login');
  await press(reopened, 'Tab', 9);
  await tabAndType(reopened, draftPassword, 'password replacement before conflict');
  await press(reopened, 'Tab', 9);
  await replaceFocusedText(reopened, draftWebsite);
  const concurrent = (await action(reopened, {UpdateLogin: {target: reviewTarget, change: {
    title: currentTitle, tags: currentTags,
  }}})).Ok?.Saved;
  assert(concurrent, 'Concurrent write did not advance the head');
  for (let stop = 0; stop < 3; stop++) await press(reopened, 'Tab', 9);
  await press(reopened, 'Enter', 13);
  await status(reopened);
  assert.deepEqual((await waitForLogin(currentTitle)).target.head, concurrent);

  const reapplyDraft = async () => {
    // Lock, Sync now, Compare versions, then Reapply my edits.
    await activateFromMargin(reopened, 3);
    await status(reopened);
    await activateFromMargin(reopened, 4);
    await until(() => reopened.evaluate("document.activeElement.id === 'session-text-input'"), 'rebased draft focus');
  };
  const saveRebasedDraft = async () => {
    for (let stop = 0; stop < 6 + currentTags.length; stop++) await press(reopened, 'Tab', 9);
    await press(reopened, 'Enter', 13);
    await status(reopened);
  };
  await reapplyDraft();
  assert.deepEqual((await waitForLogin(currentTitle)).target.head, concurrent);
  const afterReview = (await action(reopened, {UpdateLogin: {
    target: {...reviewTarget, head: concurrent}, change: {notes: currentNote},
  }})).Ok?.Saved;
  assert(afterReview, 'Second concurrent write did not advance the head');
  await saveRebasedDraft();
  assert.deepEqual((await waitForLogin(currentTitle)).target.head, afterReview);
  await reapplyDraft();
  await saveRebasedDraft();
  const recoveredDraft = await until(async () => {
    const row = await waitForLogin(currentTitle);
    return row.target.head.revision.join(',') !== afterReview.revision.join(',') && row;
  }, 'draft saved after reviewing the newest revision');
  const {fields: recoveredFields} = (await openEditor(reopened, recoveredDraft.target)).Ok.LoginEditor;
  assert.equal(recoveredFields.url, draftWebsite);
  assert.equal(recoveredFields.notes, currentNote);
  assert.deepEqual(recoveredFields.tags, currentTags);

  await checkStorage(reopened, [password, credentials.key, loginPassword, offlinePassword,
    updatedPassword, draftPassword, noteLines[0], edited.notes, 'chromium-fixture@example.test', 'offline-fixture@example.test']);

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
  assert.deepEqual((await list(recovered)).rows.find(row => row.title === edited.title)?.target.head, updated);

  networkBlocked = false;
  await current(recovered);
  const main = await newTab(browserAfterRestart, origin + '/seed');
  await startWebWorker(main);
  const web = value => webCommand(main, value);
  const {Catalog} = (await web('Catalog')).Ok;
  assert((await web({Unlock: {vault: Catalog[0].id, ...credentials, remember: false}})).Ok?.Opened);
  await syncWeb(web, origin);
  const {Draft: reviewed} = (await web({Open: {record: webRecord}})).Ok;
  assert.deepEqual(reviewed.revision, recoveredDraft.target.head.revision);
  assert(reviewed.fields.find(field => field.type_name === 'password/v1')?.values.password === draftPassword,
    'The draft password was lost during revision review');
  const read = () => web({Open: {record}});
  const {Draft: draft} = (await read()).Ok;
  assert.equal(draft.title, edited.title);
  assert.deepEqual(draft.fields.map(field => field.type_name), ['username/v1', 'password/v1', 'url/v1', 'note/v1']);
  assert(draft.fields[1].values.password === offlinePassword, 'Editing with the password blank changed the saved password');
  assert.equal(draft.fields[2].values.url, edited.origin);
  assert.deepEqual(draft.fields.map(field => field.name), ['Username', 'Password', 'Website', 'Notes']);
  assert.equal(draft.fields[3].values.text, edited.notes);
  assert.deepEqual(draft.tags, editedTags);
  assert.deepEqual(draft.revision, updated.revision);

  draft.fields[0].values.username = 'edited-in-web@example.test';
  draft.fields[3].values.text = 'Note edited in the main app';
  draft.tags.push('web');
  const fromWeb = (await web({Save: {draft, epoch: Date.now()}})).Ok?.Saved;
  assert(fromWeb, 'Web update did not finish');
  await syncWeb(web, origin);
  await syncExtension(recovered, action);
  assert.deepEqual(await action(recovered, {UpdateLogin: {target: {head: updated, field: 1}, change}}), {Err: {Storage: 'Conflict'}});
  const common = (await list(recovered)).rows.find(row => row.title === edited.title);
  assert.equal(common.username, 'edited-in-web@example.test');
  assert.deepEqual(common.target.head, fromWeb);
  assert.deepEqual((await openEditor(recovered, common.target)).Ok?.LoginEditor?.fields.tags, [...editedTags, 'web']);

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
  assert(!conflicted.rows.some(row => row.title === edited.title), 'Conflicted login remained selectable');
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
  const resolvedLogin = resolved.rows.find(row => row.title === edited.title);
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
  assert(finalDraft.fields[1].values.password === updatedPassword, 'Password replacement did not synchronize');
  assert.deepEqual(finalDraft.tags, [...editedTags, 'web']);

  scenario = 'multiple accounts, multiple forms and stale credential selections';
  const originalLogin = (await list(recovered)).rows
    .find(row => row.target.head.record.join(',') === webRecord.join(','));
  assert((await action(recovered, {UpdateLogin: {target: originalLogin.target, change: {url: origin}}})).Ok?.Saved);
  const otherRecord = Array(16).fill(78);
  const otherLogin = {
    title: 'Another synthetic login', url: origin, username: 'second-account@example.test', password: updatedPassword,
  };
  assert((await action(recovered, {CreateLogin: {record: otherRecord, login: otherLogin}})).Ok?.Saved);
  const restartedPermission = () => recovered.evaluate(`chrome.permissions.contains(${hostPermission})`);
  if (!await restartedPermission()) {
    // DevTools can reload the unpacked package with optional permissions reset.
    const settings = await newTab(browserAfterRestart, 'chrome://extensions/',
      ['chrome://extensions/', 'edge://extensions/', 'brave://extensions/']);
    await settings.evaluate(`chrome.developerPrivate.addHostPermission(${JSON.stringify(id)}, 'https://*/*')`);
    await browserAfterRestart('Target.closeTarget', {targetId: settings.targetId});
    await click(recovered, '#site-permissions-toggle');
    await until(restartedPermission, 'site permission after unpacked reload');
  }
  const multiple = await newTab(browserAfterRestart, origin + '/fill');
  const postRestartPopup = await newTab(browserAfterRestart, popupUrl);
  await multiple.evaluate(`document.body.insertAdjacentHTML('beforeend',
    '<form id="second" method="post"><input id="backup-user" autocomplete="username">'
    + '<input id="backup-password" type="password" autocomplete="current-password"></form>')`);
  await multiple.call('Page.bringToFront');
  const lookupAfterRestart = () => until(async () => {
    const result = await popupCall(postRestartPopup, {Discover: {after: null}});
    return result !== 'Busy' && result;
  }, 'post-restart autofill discovery');
  const postRestart = await lookupAfterRestart();
  const completeSite = postRestart.Site;
  assert(completeSite, `Autofill did not reconnect after browser restart (${postRestart})`);
  assert.equal(completeSite.forms.length, 2);
  assert.equal(completeSite.matches.rows.length, 2);
  const otherIndex = completeSite.matches.rows.findIndex(row => row.title === otherLogin.title);
  const secondForm = completeSite.forms.findIndex(form => form.label === 'second');
  const otherPacket = fillPacket(completeSite, secondForm, otherIndex);
  assert.equal(await popupCall(postRestartPopup, otherPacket), 'Filled');
  assert(await multiple.evaluate(`document.querySelector('#backup-user').value === ${JSON.stringify(otherLogin.username)}
    && document.querySelector('#backup-password').value === ${JSON.stringify(updatedPassword)}
    && !document.querySelector('#password').value && !document.querySelector('#user').value`));

  const latest = (await lookupAfterRestart()).Site;
  const target = latest.matches.rows.find(row => row.title === otherLogin.title).target;
  assert((await action(recovered, {UpdateLogin: {target, change: {password: offlinePassword}}})).Ok?.Saved);
  assert.equal(await popupCall(postRestartPopup, {Fill: {
    operation: latest.operation, form: latest.forms[0].target.form, target,
  }}), 'Changed');
  assert(await multiple.evaluate("!document.querySelector('#password').value"));

  const saveOrigin = origin.replace('127.0.0.1', 'localhost');
  const newUser = 'autosave@example.test';
  const newPassword = 'public-autosave-fixture';
  const changedPassword = 'public-autosave-replacement-fixture';
  const registrationPassword = 'public-autosave-registration-fixture';
  const saveCall = (action, page = postRestartPopup) => until(async () => {
    const response = await popupCall(page, {Save: action});
    const save = response?.Save ?? response;
    return save !== 'Busy' && save;
  }, 'autosave command');
  const readOffers = async (page) => {
    const reply = await saveCall('List', page);
    assert(reply?.Offers, 'Expected a live autosave offers response');
    return reply.Offers.offers;
  };
  const offer = () => until(async () => (await readOffers())[0], 'autosave offer');
  const navigate = (page, path) => until(() => page.evaluate(
    `location.pathname === ${JSON.stringify(path)} && document.readyState === 'complete'`,
  ).catch(() => false), `submission navigates to ${path}`);
  const populate = (page, values, root = 'document') => page.evaluate(`Object.entries(${JSON.stringify(values)})
    .forEach(([name, value]) => { ${root}.querySelector('#' + name).value = value; })`);
  const submit = async (page, values, path = '/fill') => {
    await page.call('Page.bringToFront');
    await populate(page, values);
    await click(page, 'input');
    await delay(450);
    await click(page, 'button');
    await navigate(page, path);
  };
  const badge = url => recovered.evaluate(`(async () => {
    const [tab] = await chrome.tabs.query({active: true, lastFocusedWindow: true, url: ${JSON.stringify(url)}});
    return tab ? chrome.action.getBadgeText({tabId: tab.id}) : null;
  })()`);
  const policy = (origin, policy) => popupCall(postRestartPopup, {SetPolicy: {origin, policy}});
  const noOffer = async () => {
    await delay(450);
    assert.deepEqual(await readOffers(), []);
  };

  scenario = 'offline autosave after native navigation under strict CSP';
  networkBlocked = true;
  await action(recovered, 'Sync');
  await until(async () => (await status(recovered)).Ok?.Opened?.sync === 'Offline', 'autosave offline status');
  const saveTab = await newTab(browserAfterRestart, saveOrigin + '/fill-save');
  await submit(saveTab, {user: newUser, password: newPassword});
  const pending = await offer();
  assert.equal(pending.origin, saveOrigin);
  assert.deepEqual(pending.kind, {New: {username: newUser}});
  assert(!(await list(recovered)).rows.some(row => row.username === newUser), 'A page submission wrote to the vault');
  assert(!JSON.stringify(pending).includes(newPassword), 'Popup received a captured password');
  assert((await readOffers(recovered)).some(row => row.id === pending.id), 'Session tab did not see the same offer');
  await until(async () => await badge(saveOrigin + '/fill') === '1', 'save badge after navigation');
  const confirm = {Confirm: {id: pending.id, target: null}};
  assert.deepEqual(await saveCall(confirm), {Saved: 'Offline'});
  assert.equal(await saveCall(confirm), 'Changed', 'An already saved operation could be replayed');
  await until(async () => await badge(saveOrigin + '/fill') === '', 'save badge cleared');
  const fromCapture = (await list(recovered)).rows.find(row => row.username === newUser);
  assert(fromCapture, 'The offline capture did not create a login');
  assert((await action(recovered, 'Lock')).Ok?.Locked);
  await status(recovered);
  assert((await action(recovered, {Unlock: credentials})).Ok?.Opened);
  const autofillSaved = () => lookupAfterRestart().then(({Site}) => {
    const account = Site.matches.rows.findIndex(row => row.username === newUser);
    return popupCall(postRestartPopup, fillPacket(Site, 0, account));
  });
  assert.equal(await autofillSaved(), 'Filled');
  assert(await saveTab.evaluate(`document.querySelector('#password').value === ${JSON.stringify(newPassword)}`));
  networkBlocked = false;
  await syncExtension(recovered, action);
  await syncWeb(web, origin);
  const capturedInWeb = (await web({Open: {record: fromCapture.target.head.record}})).Ok.Draft;
  assert.deepEqual(capturedInWeb.fields.map(field => field.type_name), ['username/v1', 'password/v1', 'url/v1', 'note/v1']);
  assert(capturedInWeb.fields[1].values.password === newPassword, 'The captured password did not sync');
  assert.equal(capturedInWeb.fields[2].values.url, saveOrigin);

  scenario = 'autosave suppresses duplicates and validates registration confirmation';
  const duplicate = await newTab(browserAfterRestart, saveOrigin + '/fill-save');
  await submit(duplicate, {user: newUser, password: newPassword});
  await noOffer();
  assert.equal(await badge(saveOrigin + '/fill'), '');
  const register = await newTab(browserAfterRestart, saveOrigin + '/fill-register');
  await submit(register, {user: 'registration@example.test', password: registrationPassword, confirmation: 'different'});
  await noOffer();
  const rootTabs = () => browserAfterRestart('Target.getTargets', {filter: [{type: 'tab'}]}).then(reply => reply.targetInfos);
  const existingTabs = new Set((await rootTabs()).map(tab => tab.targetId));
  const validRegistration = await newTab(browserAfterRestart, saveOrigin + '/fill-register');
  await submit(validRegistration, {user: 'registration@example.test', password: registrationPassword, confirmation: registrationPassword});
  const registration = await offer();
  assert.deepEqual(registration.kind, {New: {username: 'registration@example.test'}});
  const activeRoot = (await rootTabs()).find(tab => !existingTabs.has(tab.targetId))?.targetId;
  assert(activeRoot, 'Could not find the registration browser tab for the toolbar action');
  await browserAfterRestart('Extensions.triggerAction', {id, targetId: activeRoot});
  const savePopup = await until(async () => {
    const {targetInfos} = await browserAfterRestart('Target.getTargets');
    const target = targetInfos.find(target => target.url === popupUrl && target.targetId !== postRestartPopup.targetId);
    return target && attach(browserAfterRestart, target.targetId);
  }, 'autosave toolbar popup');
  await until(() => savePopup.evaluate("!document.getElementById('startup') && document.activeElement?.id === 'popup'"),
    'keyboard focus in autosave popup');
  await delay(1700);
  await press(savePopup, 'Tab', 9);
  await press(savePopup, 'Enter', 13);
  await until(async () => {
    try {
      return (await list(recovered)).rows.some(row => row.username === 'registration@example.test');
    } catch (error) {
      if (!error.message.includes('Confidex session request already pending')) throw error;
      return false;
    }
  }, 'registration saved from the toolbar popup');
  await press(savePopup, 'Escape', 27).catch(() => {});

  scenario = 'autosave in open Shadow DOM SPA with password change and revision revalidation';
  const changePage = await newTab(browserAfterRestart, saveOrigin + '/fill-empty');
  await changePage.evaluate(`(() => {
    const root = document.querySelector('main').attachShadow({mode: 'open'});
    root.innerHTML = '<form method="post"><input type="password" id="old" autocomplete="current-password">'
      + '<input type="password" id="password" autocomplete="new-password">'
      + '<input type="password" id="confirmation" autocomplete="new-password">'
      + '<button type="button">Change password</button></form>';
    root.querySelector('button').onclick = () => { root.innerHTML = ''; history.pushState({}, '', '/fill-empty?changed'); };
  })()`);
  await populate(changePage, {old: newPassword, password: changedPassword, confirmation: changedPassword},
    "document.querySelector('main').shadowRoot");
  await changePage.evaluate("document.querySelector('main').shadowRoot.querySelector('#password').focus()");
  await delay(350);
  const {x, y} = await changePage.evaluate(`(() => {
    const rect = document.querySelector('main').shadowRoot.querySelector('button').getBoundingClientRect();
    return {x: rect.x + rect.width / 2, y: rect.y + rect.height / 2};
  })()`);
  for (const type of ['mousePressed', 'mouseReleased']) {
    await changePage.call('Input.dispatchMouseEvent', {type, x, y, button: 'left', clickCount: 1});
  }
  const update = await offer();
  assert.equal(update.kind.Update.length, 2);
  const previous = update.kind.Update.find(row => row.username === newUser).target;
  assert.deepEqual(previous, fromCapture.target);
  assert.equal(await saveCall({Confirm: {id: update.id, target: null}}), 'Changed', 'A password change could create a login');
  const revised = (await action(recovered, {UpdateLogin: {target: previous, change: {notes: 'Keep this note'}}})).Ok.Saved;
  assert.equal(await saveCall({Confirm: {id: update.id, target: previous}}), 'Changed');
  const updatedOffer = await offer();
  assert.equal(updatedOffer.id, update.id);
  const revisedTarget = updatedOffer.kind.Update.find(row => row.username === newUser).target;
  assert.deepEqual(revisedTarget.head, revised);
  assert((await saveCall({Confirm: {id: updatedOffer.id, target: revisedTarget}})).Saved);
  await saveTab.call('Page.bringToFront');
  assert.equal(await autofillSaved(), 'Filled');
  assert(await saveTab.evaluate(`document.querySelector('#password').value === ${JSON.stringify(changedPassword)}`));

  scenario = 'two-step autosave and exact origin exclusions';
  const autosaveFirst = await newTab(browserAfterRestart, saveOrigin + '/fill-save-first');
  await submit(autosaveFirst, {user: 'two-step@example.test'}, '/fill-save-second');
  await submit(autosaveFirst, {password: newPassword});
  const twoStep = await offer();
  assert.deepEqual(twoStep.kind, {New: {username: 'two-step@example.test'}});
  assert.equal(await policy(saveOrigin, 'NoSave'), 'PolicyChanged');
  await until(async () => (await readOffers()).length === 0, 'site exception clears candidate');
  assert.equal(await saveCall({Confirm: {id: twoStep.id, target: null}}), 'Changed');
  assert.equal(await autofillSaved(), 'Filled', 'Saving exception also disabled filling');
  const excluded = await newTab(browserAfterRestart, saveOrigin + '/fill-save');
  await submit(excluded, {user: 'ignored@example.test', password: newPassword});
  await noOffer();
  assert.equal(await policy(saveOrigin, 'Disabled'), 'PolicyChanged');
  assert.deepEqual(await lookupAfterRestart(), {SiteDisabled: {origin: saveOrigin}});
  await multiple.call('Page.bringToFront');
  assert.equal((await lookupAfterRestart()).Site.origin, origin, 'Exception leaked to a different origin');
  await checkStorage(recovered, [newPassword, changedPassword, registrationPassword]);
  assert.equal(await policy(saveOrigin, 'Allow'), 'PolicyChanged');
  const closing = await newTab(browserAfterRestart, saveOrigin + '/fill-save');
  await submit(closing, {user: 'closed-tab@example.test', password: registrationPassword});
  const closedOffer = await offer();
  await browserAfterRestart('Target.closeTarget', {targetId: closing.targetId});
  await until(async () => !(await readOffers(recovered)).some(row => row.id === closedOffer.id),
    'closed tab clears the captured login');

  console.log(JSON.stringify({browser: browser.product, syncFromWeb: true, syncToWeb: true,
    offlineUnlock: true, newLoginThroughUi: true, editedLoginThroughUi: true, tagsSyncedBothWays: true,
    offlineWritesSurviveBrowserRestart: true, automaticSync: true,
    duplicateCreateRejected: true, staleUpdateRejected: true, draftRecoveredAfterConflict: true,
    conflictPreservedAndResolved: true,
    duplicateTabClosed: true, rivalWorkerRejected, plaintextInBrowserStorage: false,
    optionalSitePermission: true, senderValidation: true, strictCspRouting: true, keyboardPopup: true,
    backgroundRestart: true, idleExpiry: true, workerLoss: true,
    slowUnlock: true, workerLossDuringUnlock: true, openDocumentAfterRevocation: true,
    autofill: true, strictCspAutofill: true, openShadowDom: true, usernameFirst: true,
    formReplacementRejected: true, documentReplacementRejected: true, replayRejected: true,
    multipleFormsAndAccounts: true, staleFillRejected: true,
    maskedCardCodeRejected: true, getSubmissionRejected: true, autosave: true,
    offlineAutosave: true, autosaveAfterNavigation: true, autosaveDeduplication: true,
    registrationConfirmation: true, autosaveThroughUi: true, staleCaptureUpdateRejected: true,
    autosaveExclusions: true, closedTabDropsCapture: true}));

  if (!options.includes('--vault-only')) {
    scenario = 'standalone content WASM CSP reproduction';
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
} catch (error) {
  throw new Error(`Browser check failed during ${scenario}`, {cause: error});
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

async function activateFromMargin(page, tabStops) {
  const x = await page.evaluate('innerWidth - 16');
  for (const type of ['mousePressed', 'mouseReleased']) {
    await page.call('Input.dispatchMouseEvent', {type, x, y: 200, button: 'left', clickCount: 1});
  }
  for (let stop = 0; stop < tabStops; stop++) await press(page, 'Tab', 9);
  await press(page, 'Enter', 13);
}

async function press(page, key, windowsVirtualKeyCode, modifiers = 0) {
  for (const type of ['rawKeyDown', 'keyUp']) {
    await page.call('Input.dispatchKeyEvent', {type, key, code: key, windowsVirtualKeyCode, modifiers});
  }
  await page.evaluate('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
}

async function replaceFocusedText(page, text) {
  assert(await page.evaluate("document.activeElement.id === 'session-text-input'"),
    'Expected a focused text field');
  await press(page, 'a', 65, process.platform === 'darwin' ? 4 : 2);
  await page.call('Input.insertText', {text});
}

async function tabAndType(page, text, field) {
  await press(page, 'Tab', 9);
  assert(await page.evaluate("document.activeElement.id === 'session-text-input'"),
    `Browser did not focus ${field}`);
  await page.call('Input.insertText', {text});
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
