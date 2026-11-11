// Keep the large original outside the UI's WASM heap until Apply or Cancel.
let source;
let running;
let prepared;
function workerCall(message, transfer = []) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('image-worker.js', document.baseURI), {type:'module'});
    running = {worker, reject};
    function finish() { worker.terminate(); if (running?.worker === worker) running = undefined; }
    worker.onmessage = ({data}) => { finish(); data?.error ? reject(new Error('image processing failed')) : resolve(data); };
    worker.onerror = () => { finish(); reject(new Error('image processing failed')); };
    worker.postMessage(message, transfer);
  });
}
export function discardImage(discardSource) {
  if (discardSource) source = undefined;
  prepared = undefined;
  if (running) { const {worker,reject} = running; running = undefined; worker.terminate(); reject(new Error('cancelled')); }
}
export async function readImage(file, max) {
  if (!file) return null;
  if (file.size > max) return {tooLarge:true};
  const info = await workerCall({probe:file});
  if (info.large) {
    source = file;
    return {name:file.name,large:true,webp:info.webp,exif:info.exif};
  }
  return {name:file.name,bytes:new Uint8Array(await file.arrayBuffer())};
}
export async function readFile(file, max) {
  if (!file) return null;
  if (file.size > max) return {tooLarge:true};
  return {name:file.name,bytes:new Uint8Array(await file.arrayBuffer())};
}
export function pickImage(max) {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input');
    input.type = 'file'; input.accept = 'image/jpeg,image/png,image/webp';
    input.hidden = true; document.body.append(input);
    input.addEventListener('cancel', () => { input.remove(); resolve(null); }, {once:true});
    input.addEventListener('change', async () => {
      try {
        resolve(await readImage(input.files[0], max));
      } catch (error) { reject(error); } finally { input.remove(); }
    }, {once:true});
    input.click();
  });
}
export function pickFile(max) {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input');
    input.type = 'file'; input.hidden = true; document.body.append(input);
    input.oncancel = () => { input.remove(); resolve(null); };
    input.onchange = async () => {
      try {
        resolve(await readFile(input.files?.[0], max));
      } catch (error) { reject(error); } finally { input.remove(); }
    };
    input.click();
  });
}
function download(name, blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url; link.download = name; document.body.append(link);
  try { link.click(); } finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
}
export function downloadImage() {
  if (!prepared) throw new Error('prepared export unavailable');
  const file = prepared; prepared = undefined; download(file.name,file.download);
}
export function saveImage(name, bytes) { download(name, new Blob([bytes])); }
export async function runImageWork(bytes) {
  const input = bytes.slice();
  const result = await workerCall({work:input, source}, [input.buffer]);
  if (result.download) { prepared = result; return result.reply; }
  if (!(result instanceof Uint8Array)) throw new Error('invalid worker reply');
  return result;
}
