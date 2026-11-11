import assert from 'node:assert/strict';
import {mkdir, readdir, writeFile, copyFile} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {assets} from './assets.mjs';

const [bundle, output] = process.argv.slice(2);
assert(bundle && output, 'Usage: node build-static.mjs WASM_BUNDLE EMPTY_OUTPUT');
const directory = resolve(output);
await mkdir(directory, {recursive: true});
assert.equal((await readdir(directory)).length, 0, 'Output directory must be empty');
const files = await assets(bundle);
assert(files['/app_bg.wasm']?.length > 0, 'WASM module is missing');
for (const [url, data] of Object.entries(files)) {
  const path = join(directory, url === '/' ? 'index.html' : url.slice(1));
  assert(path.startsWith(directory + '/'), 'Asset path is outside the output directory');
  await mkdir(resolve(path, '..'), {recursive: true});
  await writeFile(path, data);
}
await copyFile(new URL('./_headers', import.meta.url), join(directory, '_headers'));
console.log(`Built ${Object.keys(files).length} assets in ${directory}`);
