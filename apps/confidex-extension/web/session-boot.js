import {extensionStrings} from './extension-strings.js';
import {setupSitePermissions} from './site-permissions.js';

addEventListener('pageshow', event => {
  if (event.persisted) location.reload();
});

const startup = document.getElementById('startup');
const message = document.getElementById('startup-message');
const detail = document.getElementById('startup-detail');
const reload = document.getElementById('startup-reload');
reload.addEventListener('click', () => location.reload());

try {
  const text = await extensionStrings();
  reload.textContent = text['vault-refresh'];
  message.textContent = text['vault-working'];

  try {
    // Reloading or closing this page releases the lock and its Dedicated Worker.
    await navigator.locks.request('confidex-session', {ifAvailable: true}, async lock => {
      if (!lock) {
        const duplicate = await chrome.tabs.getCurrent();
        const tabs = await chrome.tabs.query({url: location.href});
        const current = tabs.find(tab => tab.id !== duplicate?.id);
        if (current?.id != null) {
          await chrome.tabs.update(current.id, {active: true});
          await chrome.windows.update(current.windowId, {focused: true});
        }
        if (duplicate?.id != null) await chrome.tabs.remove(duplicate.id);
        else window.close();
        return;
      }
      // Catch missing bindings, WASM, fonts and renderer initialization failures.
      const {default: init, WebHandle} = await import('./ui/ui.js');
      await init();
      const handle = new WebHandle();
      try {
        await handle.start(document.getElementById('session'));
        if (globalThis.chrome?.permissions) await setupSitePermissions(text);
        startup.remove();
        await new Promise(resolve => window.addEventListener('pagehide', resolve, {once: true}));
      } finally {
        handle.destroy();
        handle.free();
      }
    });
  } catch (error) {
    message.textContent = text['extension-startup-error'];
    throw error;
  }
} catch (error) {
  startup.setAttribute('role', 'alert');
  detail.textContent = String(error);
  detail.hidden = false;
  reload.hidden = false;
}
