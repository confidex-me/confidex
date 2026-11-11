import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';

const [chrome] = process.argv.slice(2);
assert(chrome, 'Usage: node loader-check.mjs CHROME');
const html = await readFile(new URL('./index.html', import.meta.url));
const boot = await readFile(new URL('./boot.mjs', import.meta.url));
const files = {'/': html, '/boot.js': boot, '/app.js': `
  export default () => new Promise(resolve => { window.releaseInit = resolve; });
  export class WebHandle {
    start() { return new Promise(resolve => { window.releaseStart = resolve; }); }
    destroy() {}
  }
`};

await runBrowser(chrome, files, async ({command, evaluate}) => {
  const rpc = async (method, params = {}) => {
    const r = await command(method, params);
    assert(!r.error, JSON.stringify(r));
  };
  const until = async expression => {
    const end = Date.now() + 10000;
    while (!await evaluate(expression)) {
      assert(Date.now() < end, expression);
      await delay(25);
    }
  };
  await until('typeof releaseInit === "function"');
  for (const [width, scheme, motion] of [[1180, 'light', 'no-preference'], [390, 'dark', 'no-preference'], [320, 'light', 'reduce']]) {
    await rpc('Emulation.setDeviceMetricsOverride', {width, height: 640, deviceScaleFactor: 1, mobile: false});
    await rpc('Emulation.setEmulatedMedia', {features: [
      {name: 'prefers-color-scheme', value: scheme},
      {name: 'prefers-reduced-motion', value: motion},
    ]});
    const state = await evaluate(`(() => {
      const loader = document.getElementById('loading');
      const spinner = loader.querySelector('.spinner');
      const rect = spinner.getBoundingClientRect();
      const style = getComputedStyle(spinner);
      return {role: loader.role, hidden: spinner.getAttribute('aria-hidden'),
        text: loader.textContent, animation: style.animationName,
        centered: Math.abs(rect.x + rect.width / 2 - innerWidth / 2) < 1,
        inside: rect.y >= 0 && rect.bottom <= innerHeight,
        fits: loader.scrollWidth === loader.clientWidth};
    })()`);
    assert.equal(state.role, 'status');
    assert.equal(state.hidden, 'true');
    assert.equal(state.text, 'Loading Confidex…');
    assert.equal(state.animation, motion === 'reduce' ? 'pulse' : 'spin');
    assert(state.centered && state.inside && state.fits, JSON.stringify(state));
  }
  await evaluate('releaseInit()');
  await until('typeof releaseStart === "function"');
  assert(await evaluate('Boolean(document.querySelector("#loading .spinner"))'));
  await evaluate('releaseStart()');
  await until('Boolean(window.confidex)');
  assert.equal(await evaluate('document.getElementById("loading")'), null);
  await rpc('Emulation.setScriptExecutionDisabled', {value: true});
  await rpc('Page.enable');
  await rpc('Page.reload', {ignoreCache: true});
  await until('document.readyState === "complete" && Boolean(document.querySelector("#loading .spinner"))');
  assert.equal(await evaluate('typeof releaseInit'), 'undefined');
  await rpc('Emulation.setScriptExecutionDisabled', {value: false});
});

for (const [name, module] of [
  ['module download', undefined],
  ['WASM initialization', 'export default async () => { throw new Error("Invalid WASM"); };'],
  ['application start', 'export default async () => {}; export class WebHandle { async start() { throw new Error("Start failed"); } }'],
]) {
  await runBrowser(chrome, {...files, '/app.js': module}, async ({evaluate}) => {
    const end = Date.now() + 10000;
    while (!await evaluate('document.getElementById("loading").textContent.includes("could not start")')) {
      assert(Date.now() < end, name);
      await delay(25);
    }
    assert.equal(await evaluate('document.querySelector(".spinner")'), null, name);
    assert(await evaluate('document.getElementById("loading").textContent.includes("Reload the page")'), name);
    assert.equal(await evaluate('Boolean(window.confidex)'), false, name);
  });
}
console.log('Loader: initial HTML, desktop/mobile, light/dark, reduced motion, initialization/start gates and failures passed.');
