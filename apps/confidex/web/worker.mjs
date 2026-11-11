import init, { WorkerService } from '/app.js';
await init();
const service = new WorkerService();
let queue = Promise.resolve();
self.onmessage = ({ data }) => {
  if (Number.isInteger(data) && data > 0 && data <= 2160) {
    queue = queue.then(() => { self.deviceUnlockMinutes = data; });
    return;
  }
  if (data?.cancelExport > 0 && Number.isInteger(data.cancelExport)) {
    self.confidexExportCanceled = data.cancelExport;
    return;
  }
  if (data?.cancelImport > 0 && Number.isInteger(data.cancelImport)) {
    self.confidexImportCanceled = data.cancelImport;
    return;
  }
  if (!(data instanceof Uint8Array)) { self.postMessage(new Uint8Array()); return; }
  queue = queue.then(async () => {
    try {
      const pending = service.execute(data);
      data.fill(0);
      const response = await pending;
      self.postMessage(response, [response.buffer]);
    } catch {
      data.fill(0);
      self.postMessage(new Uint8Array());
    }
  });
};
self.postMessage('ready');
