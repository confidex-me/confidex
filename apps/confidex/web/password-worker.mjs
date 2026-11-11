self.onmessage = async ({data}) => {
  let report = null;
  try {
    if (!['/app.js','/gallery.js'].includes(data.module) || !(data.input instanceof Uint8Array) || data.input.length > 400) throw new Error();
    const wasm = await import(data.module);
    await wasm.default();
    report = wasm.assess_password(data.input);
  } catch {}
  finally { if (data.input instanceof Uint8Array) data.input.fill(0); }
  self.postMessage({report});
};
