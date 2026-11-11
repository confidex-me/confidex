import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {copyFile, mkdir, mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';

const [sources, sdk, mode] = process.argv.slice(2);
assert(sources && sdk && (!mode || mode==='--write'),
  'usage: node capture-encrypted.mjs SOURCE_DIRECTORY SDK_DIRECTORY [--write]');
const root = fileURLToPath(new URL('../import_fixtures/', import.meta.url));
const output = fileURLToPath(new URL('./fixtures/encrypted/', import.meta.url));
const sha = value => createHash('sha256').update(value).digest('hex');
const run = (script, ...args) => execFileSync(process.execPath,
  [script, resolve(sources), resolve(sdk), ...args], {stdio:'inherit'});
const original = await readFile(join(root,'bitwarden_json/personal.json'),'utf8');
const from = JSON.stringify('PUBLIC-FIXTURE-PASSWORD');
assert.equal(original.split(from).length,2);
const modified = original.replace(from,JSON.stringify('SOURCE-EDIT-PASSWORD-PRIVATE'));
const temp = await mkdtemp(join(tmpdir(),'confidex-encrypted-pair-'));
try {
  const target = join(temp,'bitwarden_encrypted_json');
  await mkdir(target); await mkdir(join(temp,'bitwarden_json'));
  await writeFile(join(temp,'bitwarden_json/personal.json'),modified);
  const producer = join(root,'bitwarden_encrypted_json');
  run(join(producer,'capture.cjs'));
  let script = await readFile(join(producer,'capture.cjs'),'utf8');
  const end = '\n];\n\nasync function main()';
  assert.equal(script.split(end).length,2);
  // Select one profile; the pinned exporter and crypto methods stay unchanged.
  script = script.replace(end,"\n].filter(([name])=>name==='pbkdf2-legacy');\n\nasync function main()");
  const report = "Pinned Bitwarden encrypted producer and SDK: 6 KDF profiles, 2 invalid payloads PASS";
  assert.equal(script.split(report).length,2);
  script = script.replace(report,'Selected pinned Bitwarden producer and SDK: PBKDF2 5000 PASS');
  const runner = join(target,'capture.cjs');
  await writeFile(runner,script);
  const manifest = join(target,'capture-sources.json');
  await copyFile(join(mode==='--write' ? producer : output,'capture-sources.json'),manifest);
  if(mode==='--write') {
    run(runner,'--write');
    const captured = JSON.parse(await readFile(manifest,'utf8'));
    captured.original_plaintext_sha256 = sha(original);
    captured.modified_plaintext_sha256 = sha(modified);
    captured.capture_harness_sha256 = sha(script);
    await mkdir(output,{recursive:true});
    await copyFile(join(target,'pbkdf2-legacy.json'),join(output,'pbkdf2-legacy.json'));
    await writeFile(join(output,'capture-sources.json'),JSON.stringify(captured,null,2)+'\n');
    await copyFile(join(output,'capture-sources.json'),manifest);
  } else {
    await copyFile(join(output,'pbkdf2-legacy.json'),join(target,'pbkdf2-legacy.json'));
  }
  const captured = JSON.parse(await readFile(manifest,'utf8'));
  assert.equal(captured.original_plaintext_sha256,sha(original));
  assert.equal(captured.modified_plaintext_sha256,sha(modified));
  assert.equal(captured.capture_harness_sha256,sha(script));
  run(runner);
  console.log('Pinned encrypted source edit: exactly one password changed, SDK verified');
} finally {
  await rm(temp,{recursive:true,force:true});
}
