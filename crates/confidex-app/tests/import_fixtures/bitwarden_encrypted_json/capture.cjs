// Run the pinned exporter and crypto services with public synthetic data.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const password = ' Public test-only 密码 é e\u0301 ';
const profiles = [
  ['pbkdf2', { kdfType: 0, iterations: 600000 }],
  ['pbkdf2-legacy', { kdfType: 0, iterations: 5000 }],
  ['argon2', { kdfType: 1, iterations: 6, memory: 32, parallelism: 4 }],
  ['argon2-64', { kdfType: 1, iterations: 3, memory: 64, parallelism: 4 }],
  ['argon2-128', { kdfType: 1, iterations: 2, memory: 128, parallelism: 4 }],
  ['argon2-min', { kdfType: 1, iterations: 2, memory: 16, parallelism: 1 }],
  ['invalid-json', { kdfType: 0, iterations: 5000 }, '{'],
  ['encrypted-plaintext', { kdfType: 0, iterations: 5000 }, '{"encrypted":true}'],
];

function environment(sourceDir, sdkPath) {
  const sdk = require(sdkPath);
  const ts = require(path.resolve(sdkPath, '../../typescript'));
  assert.equal(require(path.join(sdkPath, 'package.json')).version, '0.2.0-main.1214');
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'capture-sources.json')));
  assert.equal(fs.readFileSync(path.join(sdkPath, 'VERSION'), 'utf8').trim(), manifest.sdk_commit);
  const context = vm.createContext({
    ...sdk, Uint8Array, ArrayBuffer, TextEncoder,
    SdkLoadService: { Ready: Promise.resolve() },
    PerfTrackGroup: { Crypto: 'crypto' },
    EncryptionType: { AesCbc256_B64: 0, AesCbc256_HmacSha256_B64: 2, CoseEncrypt0: 7 },
    EXPECTED_NUM_PARTS_BY_ENCRYPTION_TYPE: { 0: 2, 2: 3 },
    KdfType: { PBKDF2_SHA256: 0, Argon2id: 1 },
    Utils: {
      newGuid: () => crypto.randomUUID(),
      fromBufferToB64: b => Buffer.from(b).toString('base64'),
      fromUtf8ToArray: s => new TextEncoder().encode(s),
      fromB64ToArray: s => new Uint8Array(Buffer.from(s, 'base64')),
    },
  });
  for (const source of manifest.files) {
    const bytes = fs.readFileSync(path.join(sourceDir, path.basename(source.path)));
    assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), source.sha256);
    const text = bytes.toString('utf8')
      .replace(/^import[\s\S]*?;\s*$/gm, '')
      .replace(/^\s*@measured\([^\n]+\)\s*$/gm, '')
      .replace(/\bexport\s+(?=(?:class|function|const|type)\b)/g, '');
    const js = ts.transpileModule(text, { compilerOptions: {
      target: ts.ScriptTarget.ES2022,
    } }).outputText;
    context[source.class] = vm.runInContext(`(function(){${js}\nreturn ${source.class};})()`, context);
  }
  const functions = new context.WebCryptoFunctionService({ crypto: crypto.webcrypto });
  const keys = new context.DefaultKeyGenerationService(functions);
  const encryption = new context.EncryptServiceImplementation(functions, {
    warning: () => { throw new Error('Unexpected producer warning'); },
  }, false);
  return {sdk, keys, encryption, context};
}

async function main() {
  const [sourceDir, sdkPath, mode] = process.argv.slice(2);
  assert(sourceDir && sdkPath, 'Usage: node capture.cjs SOURCE_DIRECTORY SDK_DIRECTORY [--write]');
  const {sdk, keys, encryption, context} = environment(sourceDir, sdkPath);
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'capture-sources.json')));
  if (mode !== '--write') {
    for (const fixture of manifest.fixtures) {
      assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname,
        fixture.file))).digest('hex'), fixture.sha256);
    }
  }
  const plaintext = fs.readFileSync(path.join(__dirname, '../bitwarden_json/personal.json'), 'utf8');
  for (const [name, parameters, override] of profiles) {
    const cleartext = override ?? plaintext;
    const config = {
      ...parameters,
      toSdkConfig: () => parameters.kdfType === 0
        ? { pBKDF2: { iterations: parameters.iterations } }
        : { argon2id: { iterations: parameters.iterations, memory: parameters.memory,
          parallelism: parameters.parallelism } },
    };
    const file = path.join(__dirname, `${name}.json`);
    const producer = new context.BaseVaultExportService(keys, encryption, {
      getKdfConfig: async () => config,
    });
    if (mode === '--write') {
      fs.writeFileSync(file, await producer.buildPasswordExport('public-fixture', cleartext, password) + '\n');
    }
    const document = JSON.parse(fs.readFileSync(file, 'utf8'));
    const key = await keys.deriveVaultExportKey(password, document.salt, config);
    assert.equal(document.encrypted, true);
    assert.equal(document.passwordProtected, true);
    assert.equal(document.kdfType, config.kdfType);
    assert.equal(document.kdfIterations, config.iterations);
    if (config.kdfType === 1) {
      assert.equal(document.kdfMemory, config.memory);
      assert.equal(document.kdfParallelism, config.parallelism);
    }
    assert.equal(sdk.PureCrypto.symmetric_decrypt_string(document.data, key.toEncoded()), cleartext);
    assert.match(sdk.PureCrypto.symmetric_decrypt_string(document.encKeyValidation_DO_NOT_EDIT,
      key.toEncoded()), /^[a-f0-9-]{36}$/);
    assert.equal(document.data.slice(0, 2), '2.');
  }
  if (mode === '--write') {
    manifest.fixtures = profiles.map(([name]) => {
      const file = `${name}.json`;
      return { file, sha256: crypto.createHash('sha256').update(fs.readFileSync(
        path.join(__dirname, file))).digest('hex') };
    });
    fs.writeFileSync(path.join(__dirname, 'capture-sources.json'), JSON.stringify(manifest, null, 2) + '\n');
  }
  console.log('Pinned Bitwarden encrypted producer and SDK: 6 KDF profiles, 2 invalid payloads PASS');
}
module.exports = {environment};
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
