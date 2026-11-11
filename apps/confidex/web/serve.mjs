import { createServer } from 'node:http';
import { assets } from './assets.mjs';
const files = await assets(process.argv[2]);
const port = Number(process.argv[3] ?? 4173);
createServer((request, response) => {
  const path = new URL(request.url, 'http://localhost').pathname;
  const file = files[path];
  if (!file) { response.writeHead(404).end(); return; }
  const type = path === '/' ? 'text/html; charset=utf-8'
    : path.endsWith('.js') ? 'text/javascript'
    : path.endsWith('.ttf') ? 'font/ttf'
    : path.endsWith('.txt') ? 'text/plain; charset=utf-8'
    : 'application/wasm';
  response.setHeader('Cache-Control', 'no-store');
  response.writeHead(200, { 'Content-Type': type }).end(file);
}).listen(port, '127.0.0.1', function () { console.log(`http://127.0.0.1:${this.address().port}/`); });
