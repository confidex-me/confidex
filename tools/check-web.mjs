import assert from 'node:assert/strict';
import {readdir, readFile, writeFile} from 'node:fs/promises';
import {join, relative} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const directory = process.argv[2];
assert(directory, 'Usage: node tools/check-web.mjs WEB_DIRECTORY');
const files = {};
async function visit(path) {
  for (const entry of await readdir(path, {withFileTypes: true})) {
    const name = join(path, entry.name);
    if (entry.isDirectory()) await visit(name);
    else if (relative(directory, name) !== 'BUILD.json') {
      const bytes = await readFile(name);
      files[relative(directory, name)] = {bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex')};
    }
  }
}
await visit(directory);
for (const name of ['app_bg.wasm', 'image_codec_bg.wasm', 'index.html', 'sw.js', '_headers']) {
  assert(files[name]?.bytes > 0, `Missing release asset: ${name}`);
}
const commit = process.env.CONFIDEX_SOURCE_COMMIT || execFileSync('git', ['rev-parse', 'HEAD'], {encoding: 'utf8'}).trim();
const version = process.env.CONFIDEX_BUILD_VERSION;
assert(version, 'Build through builders/wasm/build.py to set the release version');
const manifest = JSON.stringify({version, commit, files}, null, 2) + '\n';
const total = Object.values(files).reduce((sum, file) => sum + file.bytes, Buffer.byteLength(manifest));
assert(total < 25_000_000, `Web package exceeds size budget: ${total} bytes`);
await writeFile(join(directory, 'BUILD.json'), manifest);
console.log(`${Object.keys(files).length} assets; ${total} bytes including BUILD.json; source ${commit}`);
