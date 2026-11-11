// Execute the pinned JSON importer; this does not simulate attachment uploading.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {loadImporter} = require('../bitwarden_json/reader.cjs');
async function main() {
  const Importer = loadImporter(process.argv[2]);
  const result = await new Importer().parse(fs.readFileSync(0, 'utf8'));
  assert.equal(result.success, true);
  assert.equal(result.errors.length, 0);
  assert.equal(result.ciphers.length, 2);
  const [first, second] = result.ciphers;
  assert.equal(first.name, 'Почта / 東京');
  assert.equal(first.login.username, 'public-user');
  assert.equal(first.login.password, 'PUBLIC-CURRENT');
  assert.deepEqual(Array.from(first.login.uris, u => u.uri), ['https://one.invalid/?a=1&b=2']);
  assert.deepEqual(Array.from(first.fields, f => [f.name, f.value, f.type]), [
    ['', '', 0], ['Repeated', 'line one\n"two"\\公開', 0], ['Repeated', 'PUBLIC-HIDDEN', 1],
  ]);
  assert.equal(second.name, 'Second');
  assert.equal(second.login.password, 'PUBLIC-SECOND');
  assert.deepEqual(Array.from(result.folders, f => f.name), ['Shared']);
  assert.deepEqual(Array.from(result.folderRelationships, p => Array.from(p)), [[0, 0]]);
  assert(result.ciphers.every(c => c.id === null && c.attachments === undefined));
  console.log('Pinned Bitwarden JSON consumer: 2 items PASS; attachments require separate upload.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
