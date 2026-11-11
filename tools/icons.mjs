// Rasterize the copied website logo and build the macOS icon set.
import assert from 'node:assert/strict';
import {readFile, writeFile, mkdir} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright';

const directory = new URL('../apps/confidex/assets/icons/', import.meta.url);
const set = new URL('Confidex.iconset/', directory);
await mkdir(set, {recursive: true});
const svg = await readFile(new URL('confidex.svg', directory), 'utf8');
const pngs = new Map();
const browser = await chromium.launch({headless: true});
try {
  const page = await browser.newPage();
  const pngDirectory = new URL('png/', directory);
  await mkdir(pngDirectory, {recursive: true});
  for (const pixels of [16, 24, 32, 48, 64, 128, 256, 512, 1024]) {
    const data = await page.evaluate(async ({svg, pixels}) => {
      const image = new Image();
      image.src = `data:image/svg+xml;base64,${btoa(svg)}`;
      await image.decode();
      const canvas = document.createElement('canvas');
      canvas.width = canvas.height = pixels;
      canvas.getContext('2d').drawImage(image, 0, 0, pixels, pixels);
      return canvas.toDataURL('image/png').split(',')[1];
    }, {svg, pixels});
    const png = Buffer.from(data, 'base64');
    assert.equal(png.readUInt32BE(16), pixels);
    assert.equal(png.readUInt32BE(20), pixels);
    pngs.set(pixels, png);
    await writeFile(new URL(`${pixels}.png`, pngDirectory), png);
  }
  for (const size of [16, 32, 128, 256, 512]) {
    for (const scale of [1, 2]) {
      await writeFile(new URL(`icon_${size}x${size}${scale === 2 ? '@2x' : ''}.png`, set), pngs.get(size * scale));
    }
  }
} finally {
  await browser.close();
}
const sizes = [16, 24, 32, 48, 64, 128, 256];
const header = Buffer.alloc(6 + 16 * sizes.length);
header.writeUInt16LE(1, 2);
header.writeUInt16LE(sizes.length, 4);
let offset = header.length;
for (const [index, size] of sizes.entries()) {
  const at = 6 + index * 16;
  header[at] = header[at + 1] = size === 256 ? 0 : size;
  header.writeUInt16LE(1, at + 4);
  header.writeUInt16LE(32, at + 6);
  header.writeUInt32LE(pngs.get(size).length, at + 8);
  header.writeUInt32LE(offset, at + 12);
  offset += pngs.get(size).length;
}
await writeFile(new URL('Confidex.ico', directory), Buffer.concat([header, ...sizes.map(size => pngs.get(size))]));
if (process.platform === 'darwin') {
  execFileSync('iconutil', ['-c', 'icns', fileURLToPath(set), '-o', fileURLToPath(new URL('Confidex.icns', directory))]);
}
