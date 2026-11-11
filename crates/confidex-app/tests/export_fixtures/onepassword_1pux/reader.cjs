// Execute the pinned consumer unchanged, with test view and service boundaries.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const fs = require('node:fs');
const {execFileSync} = require('node:child_process');
const path = require('node:path');
const vm = require('node:vm');
const {loadContext} = require('../bitwarden_json/reader.cjs');

function loadImporter(sharedSources, sources) {
  assert(sharedSources && sources, 'Usage: reader.cjs BITWARDEN_SOURCE_DIRECTORY ONEPASSWORD_SOURCE_DIRECTORY < export.data');
  const context = loadContext(sharedSources);
  context.FeatureFlag = {PM32009NewItemTypes:'new-item-types'};
  context.CipherRepromptType.Password = 1;
  // This profile contains no SSH keys or SDK-backed dedicated item types.
  context.import_ssh_key = () => { throw Error('Unexpected SSH SDK call'); };
  context.isSshKeyImportError = () => { throw Error('Unexpected SDK error classification'); };
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'reader-sources.json')));
  for (const file of manifest.files) {
    const bytes = fs.readFileSync(path.join(sources, path.basename(file.path)));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256, file.path);
    const text = bytes.toString('utf8').replace(/^import[\s\S]*?;\s*$/gm, '');
    const js = execFileSync(process.env.CONFIDEX_READER_ESBUILD ?? 'esbuild',
      ['--loader=ts', '--format=esm', '--log-level=error'], {input:text, encoding:'utf8'})
      .replace(/\bexport\s*\{[^}]*\};?/g, '');
    vm.runInContext(js, context, {filename:file.path, timeout:1000});
  }
  return vm.runInContext('OnePassword1PuxImporter', context);
}
async function main() {
  const Importer = loadImporter(...process.argv.slice(2));
  const importer = new Importer({getFeatureFlag:async flag => {
    assert.equal(flag, 'new-item-types'); return false;
  }});
  const result = await importer.parse(fs.readFileSync(0, 'utf8'));
  assert.equal(result.success, true);
  assert.equal(result.errors.length, 0);
  assert.equal(result.ciphers.length, 2);
  const [note, login] = result.ciphers;
  assert.equal(note.type, 2);
  assert.equal(note.name, 'Public worker');
  assert.deepEqual(Array.from(note.fields.slice(0, 3), f => [f.name, f.value, f.type]), [
    ['Repeated', 'PUBLIC-HIDDEN-TEXT', 1],
    ['Repeated', 'PUBLIC-HIDDEN-USER', 1],
    ['Repeated', 'https://private.invalid/', 1],
  ]);
  // The consumer moves multiline concealed values to notes and drops empty values/files.
  assert.equal(note.notes, 'Repeated: line one\nline two\n');
  assert.equal(note.fields.length, 4);
  assert.equal(note.fields[3].value, 'otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45');
  assert.equal(note.fields[3].type, 0);
  assert.equal(note.attachments, undefined);
  assert.equal(login.type, 1);
  assert.equal(login.login.username, 'public-user');
  assert.equal(login.login.password, 'PUBLIC-CURRENT');
  assert.deepEqual(Array.from(login.login.uris, u => u.uri), ['https://one.invalid/', 'https://two.invalid/']);
  assert.deepEqual(Array.from(result.folders, f => f.name), ['Public']);
  console.log('Pinned Bitwarden 1PUX mapping reader: 2 items PASS; empty fields, multiline protection, TOTP type, extra tags and attachments have consumer limits.');
}
module.exports = {loadImporter};
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
