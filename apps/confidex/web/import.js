export function isImportCanceled(operation) {
  return operation !== 0 && self.confidexImportCanceled === operation;
}
export function isExportCanceled(operation) {
  return operation !== 0 && self.confidexExportCanceled === operation;
}
export function importProgress(bytes) {
  self.postMessage(bytes, [bytes.buffer]);
}
export function importYield() {
  return new Promise(resolve => setTimeout(resolve, 0));
}
export function pickImport(limit, keyfile = false) {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input');
    input.type = 'file'; if (!keyfile) input.accept = '.json,.xml,.kdbx,.1pux,.zip,.csv'; input.hidden = true;
    const finish = value => { input.remove(); resolve(value); };
    input.oncancel = () => finish(null);
    input.onchange = async () => {
      try {
        const file = input.files?.[0];
        if (!file) { finish(null); return; }
        if (file.size > limit) throw 'Limit';
        finish({ name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) });
      } catch (error) { input.remove(); reject(error); }
    };
    document.body.append(input);
    input.click();
  });
}
