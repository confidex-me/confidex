import {extensionStrings} from './extension-strings.js';

import {setupSitePermissions} from './site-permissions.js';

const startup = document.getElementById('startup');
const message = document.getElementById('startup-message');
const reload = document.getElementById('startup-reload');
reload.addEventListener('click', () => location.reload());

const text = await extensionStrings().catch(() => ({}));
message.textContent = text['vault-working'] ?? 'Confidex';
try {
  const {default: init, WebHandle} = await import('./ui/ui.js');
  await init();
  if (!await chrome.runtime.sendMessage({kind: 'EnsureVaultHost'})) throw new Error('Vault unavailable');
  await setupSitePermissions(text);
  const handle = new WebHandle();
  addEventListener('pagehide', () => {
    handle.destroy();
    handle.free();
  }, {once: true});
  const canvas = document.getElementById('session');
  await handle.start(canvas);
  startup.remove();
  canvas.focus();
} catch (error) {
  const detail = document.getElementById("startup-detail");
  detail.textContent = String(error);
  detail.hidden = false;
  startup.setAttribute('role', 'alert');
  message.textContent = text['extension-startup-error'] ?? 'Confidex';
  reload.textContent = text['vault-refresh'] ?? '↻';
  reload.hidden = false;
}
