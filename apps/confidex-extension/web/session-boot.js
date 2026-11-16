import init, { WebHandle } from './ui/ui.js';

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
    window.close();
    return;
  }
  await init();
  const handle = new WebHandle();
  await handle.start(document.getElementById('session'));
  await new Promise(resolve => window.addEventListener('pagehide', resolve, {once: true}));
  handle.destroy();
  handle.free();
});
