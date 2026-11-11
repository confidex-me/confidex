try {
  const { default: init, WebHandle } = await import('/app.js');
  await init();
  const app = new WebHandle();
  await app.start(document.getElementById('app'));
  document.getElementById('loading').remove();
  window.confidex = app;
  window.addEventListener('beforeunload', event => {
    if (app.has_unsaved_changes()) {
      event.preventDefault();
      event.returnValue = '';
    }
  });
  const canvas = document.getElementById('app');
  const filePosition = event => {
    if (!Array.from(event.dataTransfer?.types ?? []).includes('Files')) return;
    const rect = canvas.getBoundingClientRect();
    app.file_drag(event.clientX - rect.left, event.clientY - rect.top);
  };
  canvas.addEventListener('dragover', filePosition, {capture:true});
  canvas.addEventListener('drop', filePosition, {capture:true});
  canvas.addEventListener('dragleave', () => app.file_drag_end(), {capture:true});
  window.addEventListener('pagehide', () => app.destroy(), { once: true });
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').then(() => navigator.serviceWorker.ready)
      .then(() => { globalThis.confidexOfflineShell = 1; })
      .catch(() => { globalThis.confidexOfflineShell = -1; });
  } else globalThis.confidexOfflineShell = -1;
} catch (error) {
  document.getElementById('loading').textContent = `Confidex could not start. Reload the page to try again.\n\n${String(error)}`;
  throw error;
}
