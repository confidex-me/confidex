// Run the pinned producer with public data and mocked decrypted providers.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const { stripTypeScriptTypes } = require('node:module');
const path = require('node:path');
const vm = require('node:vm');

async function main() {
  const sourceDir = process.argv[2];
  assert(sourceDir, 'Usage: node capture.cjs SOURCE_DIRECTORY [--write]');
  const sources = JSON.parse(fs.readFileSync(path.join(__dirname, 'capture-sources.json')));
  class UnusedCrypto {
    constructor() { throw new Error('The plaintext capture must not use crypto services'); }
  }
  class Fido2CredentialView {}
  const context = vm.createContext({
    BaseVaultExportService: class {},
    CipherDomain: class {},
    EncString: UnusedCrypto,
    SymmetricCryptoKey: UnusedCrypto,
    Fido2CredentialView,
    CipherRepromptType: { None: 0 },
    SecureNoteType: { Generic: 0 },
    firstValueFrom: async value => value,
    ExportHelper: { getFileName: () => 'public-fixture.json' },
  });
  for (const source of sources.files) {
    const bytes = fs.readFileSync(path.join(sourceDir, path.basename(source.path)));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), source.sha256, source.path);
    let text = bytes.toString('utf8').replace(/^import[\s\S]*?;\s*$/gm, '');
    // The capture injects providers and does not construct the service.
    if (source.path.endsWith('/individual-vault-export.service.ts')) {
      text = text.replace(/  constructor\([\s\S]*?    super\([^;]+;\n  }\n/, '');
    }
    const js = stripTypeScriptTypes(text)
      .replace(/\bexport\s+(?=(?:class|function|const)\b)/g, '');
    vm.runInContext(js, context, { filename: source.path, timeout: 1000 });
  }
  const input = JSON.parse(fs.readFileSync(path.join(__dirname, 'producer-input.json')), (key, value) =>
    key.endsWith('Date') && value !== null ? new Date(value) : value);
  for (const item of input.items) {
    if (item.login?.fido2Credentials) {
      item.login.fido2Credentials = item.login.fido2Credentials.map(value =>
        Object.assign(new Fido2CredentialView(), value));
    }
  }
  const Service = vm.runInContext('IndividualVaultExportService', context);
  const service = Object.assign(Object.create(Service.prototype), {
    folderService: { folderViews$: () => input.folders },
    cipherService: { getAllDecrypted: async () => input.items },
    restrictedItemTypesService: {
      restricted$: input.restrictedIds,
      isCipherRestricted: (item, restricted) => restricted.includes(item.id),
    },
  });
  const exported = await service.getExport('public-fixture-user', 'json');
  assert.equal(exported.type, 'text/plain');
  const output = JSON.parse(exported.data);
  assert.equal(output.encrypted, false);
  assert.deepEqual(output.items.map(item => item.type), [1, 2, 3, 4, 5, 6, 7, 8]);
  assert(output.items.every(item => item.collectionIds === null && !('key' in item)));
  assert(output.items.every(item => !item.organizationId && !item.deletedDate));
  assert.equal(output.folders.length, 1);
  const login = output.items[0];
  assert.deepEqual(login.fields.map(field => field.type), [0, 1, 0, 2, 3, 99]);
  assert.equal(login.fields[2].name, '');
  assert.equal(login.fields[2].value, '');
  assert.equal(login.login.uris.length, 2);
  assert.equal(login.login.fido2Credentials[0].counter, '7');
  assert.equal(login.login.fido2Credentials[0].discoverable, 'true');
  assert.equal(login.passwordHistory[0].password, 'PUBLIC-FIXTURE-OLD');
  const filename = path.join(__dirname, 'producer-personal.json');
  const bytes = exported.data + '\n';
  if (process.argv[3] === '--write') fs.writeFileSync(filename, bytes);
  else assert.equal(fs.readFileSync(filename, 'utf8'), bytes);
  console.log('Pinned Bitwarden producer capture: 8 items, deterministic output, PASS');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
