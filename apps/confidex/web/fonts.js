export async function loadFonts(names) {
  return Promise.all(names.map(async name => {
    const response = await fetch(`/fonts/${name}`);
    if (!response.ok) throw new Error(`Could not load font ${name} (${response.status})`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length < 12 || bytes.length > 4 * 1024 * 1024) {
      throw new Error(`Invalid font size for ${name}`);
    }
    return bytes;
  }));
}
