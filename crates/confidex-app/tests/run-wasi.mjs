import { WASI } from 'node:wasi';
import { readFile } from 'node:fs/promises';

const [path, ...args] = process.argv.slice(2);
if (!path) throw new Error('Expected a WASI test executable');
const wasi = new WASI({ version: 'preview1', args: [path, ...args], env: {}, returnOnExit: true });
const module = await WebAssembly.compile(await readFile(path));
const instance = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: wasi.wasiImport });
process.exitCode = wasi.start(instance) ?? 0;
const bytes = instance.exports.memory.buffer.byteLength;
process.stdout.write(`WASM linear memory high-water bytes=${bytes}\n`);
if (bytes > 256 * 1024 * 1024) throw new Error('WASM test exceeded the 256 MiB profile');
