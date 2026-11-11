// Run the pinned Mozilla exporter with public logins and a local IO stub.
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [output] = process.argv.slice(2);
if (!output) throw new Error('Provide a new output CSV path');
const url = 'https://raw.githubusercontent.com/mozilla/gecko-dev/2483a0cbf2134f0696e2b8f62c61404116255ae7/toolkit/components/passwordmgr/LoginExport.sys.mjs';
const response = await fetch(url, { signal: AbortSignal.timeout(30000) });
if (!response.ok) throw new Error(`Producer download failed: ${response.status}`);
const source = new Uint8Array(await response.arrayBuffer());
const hash = createHash('sha256').update(source).digest('hex');
if (hash !== '2740e7d3af39d4022b74374ebca2017b90920d65e74bd638cf7c7191dde9fd61') {
  throw new Error('Producer digest mismatch');
}
const directory = await mkdtemp(join(tmpdir(), 'confidex-firefox-capture-'));
try {
  const modulePath = join(directory, 'LoginExport.sys.mjs');
  await writeFile(modulePath, source, { flag: 'wx' });
  const { LoginExport } = await import(pathToFileURL(modulePath).href);
  globalThis.IOUtils = { writeUTF8: (path, text) => writeFile(path, text, { flag: 'wx' }) };
  await LoginExport.exportAsCSV(output, [
    {
      origin: 'https://mail.example.invalid/a?x=1&x=2',
      username: 'alice@example.invalid', password: 'PUBLIC-FIXTURE-FIREFOX',
      httpRealm: null, formActionOrigin: 'https://mail.example.invalid/login',
      guid: '{11111111-2222-4333-8444-555555555555}',
      timeCreated: 1700000000000, timeLastUsed: 1700000001000, timePasswordChanged: 1700000002000,
    },
    {
      origin: 'https://service.example.invalid/日本語', username: 'Юзер, 東京',
      password: 'PUBLIC-"FIXTURE"\r\nSECOND-LINE', httpRealm: 'Public fixture realm',
      formActionOrigin: null, guid: '{22222222-3333-4444-8555-666666666666}',
      timeCreated: 1700000003000, timeLastUsed: 1700000004000, timePasswordChanged: 1700000005000,
    },
  ]);
} finally {
  await rm(directory, { recursive: true, force: true });
  delete globalThis.IOUtils;
}
