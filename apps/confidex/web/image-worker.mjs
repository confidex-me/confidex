import init, {image_job,image_metadata,image_work,image_import_result,image_preview_result,image_download_result,image_full_result} from './app.js';
import {withExif} from './image-metadata.js';
import {bitmapCanvas} from './image-codec.js';
const ready = init();
async function nativeWebp() {
  const canvas = new OffscreenCanvas(1,1);
  try { return (await canvas.convertToBlob({type:'image/webp'})).type === 'image/webp'; }
  catch { return false; }
  finally { canvas.width = 1; canvas.height = 1; }
}
self.onmessage = async ({data}) => {
  try {
    await ready;
    if (data.probe) {
      const info = image_metadata(new Uint8Array(await data.probe.arrayBuffer()));
      self.postMessage({large:info.large,webp:info.webp,exif:info.exif.length > 0}); return;
    }
    const work = image_work(data.work);
    const external = work.kind === 1 && work.bytes.length === 0;
    const blob = external ? data.source : new Blob([work.bytes]);
    if (!(blob instanceof Blob)) throw new Error('original unavailable');
    const bytes = external ? new Uint8Array(await blob.arrayBuffer()) : work.bytes;
    const info = image_metadata(bytes);
    if (!external && (!info.large || work.kind < 2)) {
      const result = image_job(data.work); self.postMessage(result,[result.buffer]); return;
    }
    if (external && work.quality === 101 && info.webp && (work.keepExif || !info.exif.length)) {
      const bitmap = await createImageBitmap(blob); bitmap.close();
      const result = image_import_result(data.work,bytes); self.postMessage(result,[result.buffer]); return;
    }
    if (work.kind === 1 && (work.quality < 1 || work.quality > 100)) throw new Error('invalid quality');
    if (external && !(await nativeWebp())) {
      const codec = await import('./image_codec.js');
      await codec.default();
      let encoded;
      try { encoded = codec.image_compress(bytes,work.quality,work.keepExif); }
      catch (error) {
        if (error !== 'gallery-image-full') throw error;
        const result = image_full_result(); self.postMessage(result,[result.buffer]); return;
      }
      const result = image_import_result(data.work,encoded);
      self.postMessage(result,[result.buffer]); return;
    }
    const preview = work.kind === 2;
    const jpeg = work.kind === 4;
    const {canvas,context,naturalWidth,naturalHeight} = await bitmapCanvas(blob, info, preview ? false : work.keepExif || work.kind > 2, preview, jpeg);
    try {
      if (preview) {
        const rgba = context.getImageData(0,0,canvas.width,canvas.height).data;
        const result = image_preview_result(rgba,canvas.width,canvas.height,naturalWidth,naturalHeight);
        self.postMessage(result,[result.buffer]);
      } else {
        const type = work.kind === 1 ? 'image/webp' : jpeg ? 'image/jpeg' : 'image/png';
        let encoded = await canvas.convertToBlob({type,quality:work.kind === 1 ? work.quality / 100 : .9});
        if (encoded.type !== type) throw new Error('requested codec unavailable');
        if (work.keepExif || work.kind > 2) encoded = await withExif(encoded,info.exif,canvas.width,canvas.height);
        if (work.kind === 1) {
          if (encoded.size > 16*1024*1024) { const result = image_full_result(); self.postMessage(result,[result.buffer]); return; }
          const result = image_import_result(data.work,new Uint8Array(await encoded.arrayBuffer()));
          self.postMessage(result,[result.buffer]);
        } else {
          const name = work.name.replace(/\.[^.]*$/, '') + (jpeg ? '.jpg' : '.png');
          const reply = image_download_result();
          self.postMessage({download:encoded,name,reply},[reply.buffer]);
        }
      }
    } finally { canvas.width = 1; canvas.height = 1; }
  } catch { self.postMessage({error:'image processing failed'}); }
};
