import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

export async function runBrowser(chromePath, assets, expression, { windowSize = [800, 600], viewport, remoteUrl, isolated = false, passkeys = false } = {}) {
  const profile = await mkdtemp(join(tmpdir(), 'confidex-browser-'));
  const server = createServer((req, res) => {
    if (isolated) {
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    }
    const asset = assets[req.url];
    if (req.url === '/') { res.setHeader('Content-Type', 'text/html'); res.end((typeof expression === 'function' && asset) || '<!doctype html><title>Confidex checks</title>'); }
    else if (asset) {
      const type = req.url.endsWith('.html') ? 'text/html'
        : req.url.endsWith('.json') ? 'application/json'
        : req.url.endsWith('.js') ? 'text/javascript'
        : req.url.endsWith('.ttf') ? 'font/ttf'
        : req.url.endsWith('.txt') ? 'text/plain; charset=utf-8'
        : 'application/wasm';
      res.setHeader('Content-Type', type);
      res.end(asset);
    }
    else { res.statusCode = 404; res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const host = passkeys ? 'localhost' : '127.0.0.1';
  const pageUrl = remoteUrl ?? `http://${host}:${server.address().port}/`;
  const chrome = spawn(chromePath, [
    '--headless=new', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
    '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
    '--disable-component-update', '--disable-sync', `--user-data-dir=${profile}`,
    `--window-size=${windowSize.join(',')}`,
    pageUrl,
  ], { stdio: 'ignore' });
  let socket;
  let launchError;
  chrome.on('error', error => { launchError = error; });
  try {
    let port;
    const deadline = Date.now() + 30_000;
    while (!port && Date.now() < deadline) {
      if (launchError) throw launchError;
      assert(chrome.exitCode === null, 'Chrome exited before opening the debug port');
      try {
        port = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0];
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        await delay(100);
      }
    }
    assert(port, 'Chrome startup timed out');
    const tabs = await fetch(`http://127.0.0.1:${port}/json/list`).then(r => r.json());
    socket = new WebSocket(tabs.find(tab => tab.type === 'page').webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', reject, { once: true });
    });
    let requestId = 0;
    function command(method, params) {
      const id = ++requestId;
      return new Promise((resolve, reject) => {
        const receive = event => {
          const message = JSON.parse(event.data);
          if (message.id !== id) return;
          clearTimeout(timer);
          socket.removeEventListener('message', receive);
          resolve(message);
        };
        const timer = setTimeout(() => {
          socket.removeEventListener('message', receive);
          reject(new Error(`browser command timed out: ${method}`));
        }, 120_000);
        socket.addEventListener('message', receive);
        socket.send(JSON.stringify({ id, method, params }));
      });
    }
    const evaluate = expression => command('Runtime.evaluate', {
      expression, awaitPromise: true, returnByValue: true,
    });
    for (;;) {
      const page = await evaluate('[location.href, document.readyState]');
      const [url, state] = page.result?.result?.value ?? [];
      if (url === pageUrl && state === 'complete') break;
      assert(Date.now() < deadline, 'browser page navigation timed out');
      await delay(100);
    }
    if (!passkeys && assets['/app_bg.wasm']) {
      const cancelEnrollment = `if (navigator.credentials) for (const method of ['create', 'get']) navigator.credentials[method] = async () => {
        throw new DOMException('Test enrollment canceled', 'NotAllowedError');
      };`;
      const installed = await command('Page.addScriptToEvaluateOnNewDocument', {source: cancelEnrollment});
      const applied = await evaluate(cancelEnrollment);
      assert(!installed.error && !applied.error && !applied.result.exceptionDetails);
    }
    if (viewport) {
      const resized = await command('Emulation.setDeviceMetricsOverride', {
        width: viewport[0], height: viewport[1], deviceScaleFactor: 1, mobile: false,
      });
      assert(!resized.error, JSON.stringify(resized));
    }
    if (typeof expression === 'function') {
      return await expression({ command, url: pageUrl, pid: chrome.pid, evaluate: async source => {
        const response = await evaluate(source);
        assert(!response.error && !response.result.exceptionDetails, JSON.stringify(response));
        return response.result.result.value;
      } });
    }
    const response = await evaluate(expression);
    assert(!response.error && !response.result.exceptionDetails, JSON.stringify(response));
    return response.result.result.value;
  } finally {
    socket?.close();
    server.close();
    if (!launchError && chrome.exitCode === null) {
      chrome.kill('SIGTERM');
      await new Promise(resolve => chrome.once('exit', resolve));
    }
    await rm(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }
}
