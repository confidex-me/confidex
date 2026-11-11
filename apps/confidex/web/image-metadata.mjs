// Attach TIFF data without decoding or changing image pixels.
const ascii = text => Uint8Array.from(text, c => c.charCodeAt(0));
function u32(value, little = false) {
  const bytes = new Uint8Array(4); new DataView(bytes.buffer).setUint32(0, value, little); return bytes;
}
function chunk(type, data) {
  return [ascii(type), u32(data.length, true), data, ...(data.length % 2 ? [new Uint8Array(1)] : [])];
}
function crc32(parts) {
  let crc = 0xffffffff;
  for (const part of parts) for (const byte of part) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
export async function withExif(blob, exif, width, height) {
  if (!exif?.length) return blob;
  if (blob.type === 'image/jpeg') {
    if (exif.length + 8 > 65535) throw new Error('EXIF exceeds JPEG segment limit');
    const length = exif.length + 8;
    return new Blob([blob.slice(0, 2), new Uint8Array([255,225,length >>> 8,length & 255]), ascii('Exif\0\0'), exif, blob.slice(2)], {type:blob.type});
  }
  if (blob.type === 'image/png') {
    const type = ascii('eXIf');
    return new Blob([blob.slice(0, 33), u32(exif.length), type, exif, u32(crc32([type,exif])), blob.slice(33)], {type:blob.type});
  }
  if (blob.type !== 'image/webp') throw new Error('unsupported metadata container');
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const view = new DataView(bytes.buffer);
  const tag = offset => String.fromCharCode(...bytes.subarray(offset,offset + 4));
  if (tag(0) !== 'RIFF' || tag(8) !== 'WEBP' || view.getUint32(4,true) + 8 !== bytes.length) throw new Error('invalid WebP');
  let flags = 8, hasImage = false;
  const parts = [];
  for (let at = 12; at < bytes.length;) {
    if (at + 8 > bytes.length) throw new Error('invalid WebP chunk');
    const size = view.getUint32(at + 4, true), end = at + 8 + size + size % 2, type = tag(at);
    if (end > bytes.length) throw new Error('invalid WebP chunk length');
    if (type === 'VP8X') {
      if (size !== 10) throw new Error('invalid extended WebP');
      flags |= bytes[at + 8];
    } else if (type !== 'EXIF') {
      parts.push(bytes.subarray(at,end));
      if (type === 'ALPH' || (type === 'VP8L' && size >= 5 && bytes[at + 12] & 16)) flags |= 16;
      if (type === 'VP8 ' || type === 'VP8L') hasImage = true;
    }
    at = end;
  }
  if (!hasImage || width < 1 || height < 1 || width > 16383 || height > 16383) throw new Error('invalid image dimensions');
  const extended = new Uint8Array(10); extended[0] = flags;
  for (let i = 0; i < 3; i++) { extended[4+i] = ((width-1) >>> (8*i)) & 255; extended[7+i] = ((height-1) >>> (8*i)) & 255; }
  const payload = new Blob([ascii('WEBP'), ...chunk('VP8X',extended), ...parts, ...chunk('EXIF',exif)]);
  return new Blob([ascii('RIFF'), u32(payload.size,true), payload], {type:blob.type});
}
export async function withoutWebpExif(blob) {
  const bytes = new Uint8Array(await blob.arrayBuffer()), view = new DataView(bytes.buffer);
  const tag = at => String.fromCharCode(...bytes.subarray(at,at+4));
  if (bytes.length < 12 || tag(0) !== 'RIFF' || tag(8) !== 'WEBP' || view.getUint32(4,true)+8 !== bytes.length) throw new Error('invalid WebP');
  const parts = [ascii('WEBP')];
  for(let at=12;at<bytes.length;) {
    if(at+8>bytes.length)throw new Error('invalid WebP chunk');
    const size=view.getUint32(at+4,true),end=at+8+size+size%2,type=tag(at);
    if(end>bytes.length)throw new Error('invalid WebP length');
    if(type==='VP8X') {
      if(size!==10)throw new Error('invalid extended WebP');
      const header=bytes.slice(at,end);header[8]&=~8;parts.push(header);
    } else if(type!=='EXIF')parts.push(bytes.subarray(at,end));
    at=end;
  }
  const payload=new Blob(parts);
  return new Blob([ascii('RIFF'),u32(payload.size,true),payload],{type:'image/webp'});
}
