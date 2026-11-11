// Run the pinned producer with public data and mocked decrypted providers.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const { stripTypeScriptTypes } = require('node:module');
const path = require('node:path');
const vm = require('node:vm');

async function main() {
  const sourceDir = process.argv[2];
  const JSZip = require(process.argv[3]);
  assert.equal(JSZip.version, '3.10.1');
  JSZip.defaults.date = new Date('2026-01-01T00:00:00Z');
  assert(sourceDir, 'Usage: node capture.cjs SOURCE_DIRECTORY JSZIP_MODULE [--write]');
  const sources = JSON.parse(fs.readFileSync(path.join(__dirname, 'capture-sources.json')));
  class UnusedCrypto {
    constructor() { throw new Error('The plaintext capture must not use crypto services'); }
  }
  class Fido2CredentialView {}
  const context = vm.createContext({
    JSZip, Blob,
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
  const Service = vm.runInContext('IndividualVaultExportService', context);
  const item = (id, name, attachments = []) => ({
    id, name, attachments, type: 1, reprompt: 0, favorite: false,
    login: { username: 'public-user', password: 'PUBLIC-FIXTURE-PASSWORD', uris: [] },
  });
  const file = (id, fileName, bytes = [0, 255, 13, 10]) => ({ id, fileName, bytes });
  const cases = {
    personal: [
      item('item-a', 'Почта / 東京', [file('a', 'scan.part.txt'), file('b', 'scan.part.txt', []),
        file('c', 'résumé.txt', [195, 169])]),
      item('item-b', 'Second', [file('d', 'scan.part.txt', [42])]),
      item('empty', 'No files'),
    ],
    duplicate: [item('a', 'Same'), item('b', 'Same', [file('a', 'file.txt')])],
    sanitize: [item('a', 'a/b', [file('a', 'one')]), item('b', 'a\\b', [file('b', 'two')])],
    suffix: [item('a', 'Same', [file('a', 'file')]), item('b', 'Same', [file('b', 'file')]),
      item('c', 'Same_1', [file('c', 'other')])],
    skipped: [item('a', 'Skipped', [file('fail', 'missing.txt')])],
    restricted: [item('a', 'Restricted', [file('a', 'orphan.txt')])],
  };
  const manifest = {};
  for (const [name, items] of Object.entries(cases)) {
    let failures = 0;
    const service = Object.assign(Object.create(Service.prototype), {
      folderService: { folderViews$: () => [] },
      cipherService: { getAllDecrypted: async () => items,
        getDecryptedAttachmentBuffer: async (_, attachment) => Uint8Array.from(attachment.bytes) },
      restrictedItemTypesService: { restricted$: [],
        isCipherRestricted: () => name === 'restricted' },
      downloadAttachment: async (_, id) => {
        if (id === 'fail') throw new Error('Public fixture download failure');
        return {};
      },
      logService: { error: () => failures++ },
    });
    const exported = await service.getDecryptedExportZip('public-fixture-user');
    const bytes = Buffer.from(await exported.data.arrayBuffer());
    const zip = await JSZip.loadAsync(bytes);
    const document = JSON.parse(await zip.file('data.json').async('string'));
    assert(document.items.every(value => !('attachments' in value)));
    assert.equal(exported.skippedAttachmentCount, failures || undefined);
    const members = {};
    for (const [path, member] of Object.entries(zip.files)) {
      members[path] = member.dir ? null : createHash('sha256')
        .update(await member.async('nodebuffer')).digest('hex');
    }
    manifest[name] = { sha256: createHash('sha256').update(bytes).digest('hex'),
      skippedAttachmentCount: failures, items: document.items.map(value => value.id), members };
    const target = path.join(__dirname, name + '.zip');
    if (process.argv[4] === '--write') fs.writeFileSync(target, bytes);
    else assert.deepEqual(fs.readFileSync(target), bytes);
  }
  const output = JSON.stringify(manifest, null, 2) + '\n';
  const target = path.join(__dirname, 'manifest.json');
  if (process.argv[4] === '--write') fs.writeFileSync(target, output);
  else assert.equal(fs.readFileSync(target, 'utf8'), output);
  console.log('Pinned Bitwarden ZIP producer capture: six cases, PASS');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
