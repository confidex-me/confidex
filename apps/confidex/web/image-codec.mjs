import {withoutWebpExif} from './image-metadata.js';
const side = 2048;
function dimensions(info) {
  return info.orientation >= 5 ? [info.height,info.width] : [info.width,info.height];
}
export async function bitmapCanvas(blob, info, keepExif, preview = false, jpeg = false) {
  const [naturalWidth,naturalHeight] = dimensions(info);
  const ratio = preview ? Math.min(1, side / Math.max(naturalWidth,naturalHeight)) : 1;
  const rawWebp = info.webp && info.exif.length > 0;
  if (rawWebp) blob = await withoutWebpExif(blob);
  const decodeWidth = rawWebp ? info.width : naturalWidth, decodeHeight = rawWebp ? info.height : naturalHeight;
  const options = preview ? {resizeWidth:Math.max(1,Math.round(decodeWidth*ratio)),resizeHeight:Math.max(1,Math.round(decodeHeight*ratio)),resizeQuality:'high'} : {};
  const bitmap = await createImageBitmap(blob, options);
  let canvas;
  try {
    const raw = keepExif && !preview;
    const swap = rawWebp && !raw && info.orientation >= 5;
    const width = raw ? info.width : swap ? bitmap.height : bitmap.width;
    const height = raw ? info.height : swap ? bitmap.width : bitmap.height;
    canvas = new OffscreenCanvas(width,height);
    const context = canvas.getContext('2d');
    if (!context) throw new Error('canvas unavailable');
    if (jpeg) { context.fillStyle = '#ffffff'; context.fillRect(0,0,width,height); }
    if ((rawWebp && !raw) || (!rawWebp && raw)) {
      // WebP EXIF support differs between browsers. Apply its orientation explicitly.
      const w = rawWebp ? bitmap.width : info.width, h = rawWebp ? bitmap.height : info.height;
      const matrices = [[1,0,0,1,0,0],[1,0,0,1,0,0],[-1,0,0,1,w,0],[-1,0,0,-1,w,h],[1,0,0,-1,0,h],[0,1,1,0,0,0],[0,1,-1,0,h,0],[0,-1,-1,0,h,w],[0,-1,1,0,0,w]];
      const matrix = new DOMMatrix(matrices[info.orientation]);
      context.setTransform(rawWebp ? matrix : matrix.inverse());
    }
    context.drawImage(bitmap,0,0);
    return {canvas,context,naturalWidth,naturalHeight};
  } catch (error) { if (canvas) { canvas.width = 1; canvas.height = 1; } throw error; }
  finally { bitmap.close(); }
}
