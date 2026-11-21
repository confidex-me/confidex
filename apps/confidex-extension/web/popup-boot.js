import {extensionStrings} from './extension-strings.js';

const startup = document.getElementById('startup');
const message = document.getElementById('startup-message');
const reload = document.getElementById('startup-reload');
reload.addEventListener('click', () => location.reload());

const text = await extensionStrings().catch(() => ({}));
message.textContent = text['vault-working'] ?? 'Confidex';
try {
  const {default: init, PopupHandle} = await import('./ui/ui.js');
  await init();
  const handle = new PopupHandle();
  addEventListener('pagehide', () => {
    handle.destroy();
    handle.free();
  }, {once: true});
  const canvas = document.getElementById('popup');
  await handle.start(canvas);
  startup.remove();
  canvas.focus();
} catch {
  startup.setAttribute('role', 'alert');
  message.textContent = text['extension-startup-error'] ?? 'Confidex';
  reload.textContent = text['vault-refresh'] ?? '↻';
  reload.hidden = false;
}
