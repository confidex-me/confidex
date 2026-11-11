export function pickBackup(limit) {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input');
    input.type = 'file'; input.accept = '.zip,application/zip';
    input.hidden = true;
    const finish = value => { input.remove(); resolve(value); };
    input.oncancel = () => finish(null);
    input.onchange = async () => {
      try {
        const file = input.files?.[0];
        if (!file) { finish(null); return; }
        if (file.size > limit) throw 'Limit';
        finish(new Uint8Array(await file.arrayBuffer()));
      } catch (error) { input.remove(); reject(error); }
    };
    document.body.append(input);
    input.click();
  });
}
export function saveBackup(bytes) {
  const url = URL.createObjectURL(new Blob([bytes], {type:'application/zip'}));
  const link = document.createElement('a');
  link.href = url; link.download = 'confidex-backup.zip';
  document.body.append(link);
  try { link.click(); } finally {
    link.remove(); setTimeout(() => URL.revokeObjectURL(url), 60000);
  }
}
