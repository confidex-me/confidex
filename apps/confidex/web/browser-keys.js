const keyWarnings = new WeakMap();
export function attachKeyFallback(worker) {
  worker.addEventListener('message', event => {
    if (event.data !== 'confidex-confirm-plaintext') return;
    event.stopImmediatePropagation();
    const port = event.ports[0];
    if (!port) return;
    const message = keyWarnings.get(worker);
    keyWarnings.delete(worker);
    port.postMessage(Boolean(message && window.confirm(message)));
    port.close();
  }, {capture: true});
}
export function setKeyStorageWarning(worker, message) {
  keyWarnings.set(worker, message);
}
export function confirmPlaintextKey() {
  if (typeof document !== 'undefined') return Promise.resolve(false);
  return new Promise(resolve => {
    const channel = new MessageChannel();
    channel.port1.onmessage = ({data}) => {
      channel.port1.close();
      resolve(data === true);
    };
    postMessage('confidex-confirm-plaintext', [channel.port2]);
  });
}
export function offlineShell() { return globalThis.confidexOfflineShell ?? 0; }
