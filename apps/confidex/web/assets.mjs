import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

export async function assets(directory) {
  const local = name => readFile(new URL(name, import.meta.url));
  const files = {
    '/': await local('./index.html'), '/boot.js': await local('./boot.mjs'),
    '/worker.js': await local('./worker.mjs'),
  };
  async function visit(path, prefix = '') {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      if (entry.isDirectory()) await visit(join(path, entry.name), `${prefix}${entry.name}/`);
      else if (entry.name.endsWith('.js') || entry.name.endsWith('.wasm')) files[`/${prefix}${entry.name}`] = await readFile(join(path, entry.name));
    }
  }
  files['/password-host.js'] = await local('./password-host.mjs');
  files['/password-worker.js'] = await local('./password-worker.mjs');
  files['/image-host.js'] = await local('./image-host.mjs');
  files['/image-worker.js'] = await local('./image-worker.mjs');
  files['/image-codec.js'] = await local('./image-codec.mjs');
  files['/image-metadata.js'] = await local('./image-metadata.mjs');
  await visit(directory);
  const fonts = new URL('../../../crates/confidex-ui/assets/fonts/', import.meta.url);
  for (const name of await readdir(fonts)) {
    if (name.endsWith('.ttf') || name.endsWith('.txt')) {
      files[`/fonts/${name}`] = await readFile(new URL(name, fonts));
    }
  }
  for (const name of ['LICENSE-APACHE', 'LICENSE-MIT', 'ATTRIBUTION.md']) {
    files[`/notices/themes/${name}`] = await readFile(new URL(`../../../crates/confidex-ui/assets/themes/solidcraft/${name}`, import.meta.url));
  }
  files['/notices/wordlist.txt'] = await readFile(new URL('../../../crates/confidex-ui/assets/wordlists/README.md', import.meta.url));
  files['/notices/keepass.txt'] = await readFile(new URL('../../../vendor/keepass/LICENSE', import.meta.url));
  const hash = createHash('sha256');
  for (const [path, data] of Object.entries(files).sort(([a], [b]) => a.localeCompare(b))) { hash.update(path); hash.update(data); }
  const version = `confidex-${hash.digest('hex').slice(0, 16)}`;
  const paths = Object.keys(files);
  files['/sw.js'] = Buffer.from(`
const CACHE = ${JSON.stringify(version)};
const ASSETS = ${JSON.stringify(paths)};
self.addEventListener('install', event => event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(ASSETS))));
self.addEventListener('activate', event => event.waitUntil((async () => {
  for (const name of await caches.keys()) if (name.startsWith('confidex-') && name !== CACHE) await caches.delete(name);
  await self.clients.claim();
})()));
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin || !ASSETS.includes(url.pathname)) return;
  event.respondWith(caches.open(CACHE).then(cache => cache.match(url.pathname)).then(response => response || fetch(event.request)));
});
`);
  return files;
}
