// Execute actual pinned CSV consumers, parser and hostname helper with public bytes.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {stripTypeScriptTypes} = require('node:module');
const {loadContext} = require('../bitwarden_json/reader.cjs');
function verified(directory, file) {
  const bytes = fs.readFileSync(path.join(directory, file.local ?? path.basename(file.path)));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256, file.path);
  return bytes.toString('utf8');
}
function loadImporter(shared, sources, profile) {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'reader-sources.json')));
  const context = loadContext(shared);
  for (const pkg of manifest.packages) {
    verified(sources, pkg);
    context[pkg.name === 'papaparse' ? 'papa' : 'getHostname'] = pkg.name === 'papaparse'
      ? require(path.join(sources, pkg.local)) : require(path.join(sources, pkg.local)).getHostname;
  }
  const dependencies = JSON.parse(verified(sources, manifest.files.find(f => f.path === 'package.json'))).dependencies;
  for (const pkg of manifest.packages) assert.equal(dependencies[pkg.name], pkg.version);
  const sharedManifest = JSON.parse(fs.readFileSync(path.join(__dirname, '../bitwarden_json/reader-sources.json')));
  const utils = verified(shared, sharedManifest.files.find(file => file.local === 'utils-platform.ts'));
  const from = utils.indexOf('  static getHostname(');
  const to = utils.indexOf('\n  }', from);
  const hosts = utils.match(/^  static readonly validHosts:.*$/m)[0];
  assert(from >= 0 && to > from && hosts);
  const helper = 'class CsvUtils {\n' + hosts + '\n' + utils.slice(from, to + 4) + '\n}\nUtils.getHostname=CsvUtils.getHostname.bind(CsvUtils);';
  vm.runInContext(stripTypeScriptTypes(helper), context);
  for (const file of manifest.files.filter(f => f.path.endsWith('.ts'))) {
    const source = verified(sources, file).replace(/^import[\s\S]*?;\s*$/gm, '');
    vm.runInContext(stripTypeScriptTypes(source).replace(/\bexport\s+(?=class\b)/g, ''), context, {filename:file.path, timeout:1000});
  }
  const classes = {chromium:'ChromeCsvImporter', firefox:'FirefoxCsvImporter', 'apple-passwords':'SafariCsvImporter'};
  assert(classes[profile], 'Unknown CSV profile');
  return vm.runInContext(classes[profile], context);
}
async function main() {
  const [shared, sources, profile] = process.argv.slice(2);
  const Reader = loadImporter(shared, sources, profile);
  const result = await new Reader().parse(fs.readFileSync(0, 'utf8'));
  assert.equal(result.success, true);
  assert.equal(result.errors.length, 0);
  assert.equal(result.ciphers.length, 1);
  const item = result.ciphers[0];
  assert.equal(item.name, profile === 'firefox' ? 'example.invalid' : '公開 / Public');
  assert.equal(item.login.username, 'public-user');
  assert.equal(item.login.password, 'PUBLIC-CURRENT');
  assert.deepEqual(Array.from(item.login.uris, uri => uri.uri), ['https://www.example.invalid/?a=1&b=2']);
  if (profile !== 'firefox') assert.equal(item.notes, 'line one\n"two"\\公開');
  if (profile === 'apple-passwords') assert.equal(item.login.totp, 'otpauth://totp/Provider:public?secret=MZXW6YTBOI&issuer=Provider&algorithm=SHA256&digits=8&period=45');
  console.log('Pinned Bitwarden ' + profile + ' CSV consumer: current login mapping PASS');
}
module.exports = {loadImporter};
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
