import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { runBrowser } from '../../tools/browser-run.mjs';

const [chrome, base] = process.argv.slice(2);
const origin = new URL(base).origin;
const result = await runBrowser(chrome, {}, async ({ command, evaluate }) => {
  await command('Page.navigate', { url: `${origin}/v1` });
  const deadline = Date.now() + 30000;
  while (await evaluate('document.querySelectorAll(".opblock").length') !== 6) {
    assert(Date.now() < deadline, 'Swagger UI did not render six operations');
    await delay(100);
  }
  const urls = await evaluate('performance.getEntriesByType("resource").map(entry => entry.name)');
  assert(urls.length >= 3, 'Swagger UI assets and specification must load');
  for (const url of urls) assert.equal(new URL(url).origin, origin, url);
  for (const file of ['swagger-ui.css', 'swagger-ui-bundle.js', 'openapi.json']) {
    assert(urls.some(url => url.endsWith(file)), `${file} did not load`);
  }
  assert(await evaluate('getComputedStyle(document.querySelector(".swagger-ui")).fontFamily.includes("sans-serif")'));
  assert(await evaluate(`Array.from(document.querySelectorAll('.json-schema-2020-12-head')).every(head => {
    const buttons = Array.from(head.children).filter(child => child.tagName === 'BUTTON');
    return buttons.every((button, index) => {
      const box = button.getBoundingClientRect();
      const previous = buttons[index - 1]?.getBoundingClientRect();
      return getComputedStyle(button).backgroundColor === 'rgba(0, 0, 0, 0)'
        && (!previous || box.left >= previous.right || box.top >= previous.bottom);
    });
  })`));
  return { operations: 6, requests: urls, externalRequests: 0 };
});
process.stdout.write(`${JSON.stringify(result)}\n`);
