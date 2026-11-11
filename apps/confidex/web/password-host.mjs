export function evaluatePassword(bytes, module) {
  if (bytes.length > 400) return Promise.reject(new Error('password analysis unavailable'));
  const input = new Uint8Array(bytes);
  return new Promise((resolve, reject) => {
    let worker;
    let timeout;
    let finished = false;
    const finish = (report) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeout);
      worker?.terminate();
      if (report) resolve(report);
      else reject(new Error('password analysis unavailable'));
    };
    try {
      worker = new Worker('/password-worker.js', {type:'module'});
      timeout = setTimeout(() => finish(null), 15000);
      worker.onmessage = event => finish(event.data?.report);
      worker.onerror = () => finish(null);
      worker.onmessageerror = () => finish(null);
      worker.postMessage({module, input}, [input.buffer]);
    } catch { if (input.byteLength) input.fill(0); finish(null); }
  });
}
