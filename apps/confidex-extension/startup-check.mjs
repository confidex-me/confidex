import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import {releaseAssets} from '../confidex/web/assets.mjs';
import {runBrowser} from '../../tools/browser-run.mjs';

const [browser, directory] = process.argv.slice(2);
assert(browser && directory, 'Usage: node startup-check.mjs BROWSER EXTENSION_DIRECTORY');
const files = await releaseAssets(directory);
files['/'] = files['/popup.html'];

for (const missing of ['/ui/ui.js', '/ui/ui_bg.wasm']) {
  const incomplete = {...files};
  delete incomplete[missing];
  const result = await runBrowser(browser, incomplete, async ({evaluate}) => {
    for (let attempt = 0; attempt < 100; attempt++) {
      const error = await evaluate(`(() => {
        const alert = document.querySelector('#startup[role=alert]');
        if (!alert) return null;
        const button = alert.querySelector('button');
        return {message: document.querySelector('#startup-message').textContent,
          detail: document.querySelector('#startup-detail').textContent,
          reloadVisible: !button.hidden && button.textContent.trim().length > 0};
      })()`);
      if (error) return error;
      await delay(100);
    }
    throw new Error(`No visible startup error for ${missing}`);
  });
  assert.notEqual(result.message, 'Confidex');
  assert(result.detail.length > 0, 'Startup error must include a diagnostic');
  assert.equal(result.reloadVisible, true, 'Reload action must be visible and labelled');
}
console.log(JSON.stringify({missingBindings: 'visible error', missingWasm: 'visible error'}));
