const sites = {origins: ['https://*/*']};

export async function setupSitePermissions(text) {
  const controls = document.getElementById('site-permissions');
  const button = document.getElementById('site-permissions-toggle');
  const status = document.getElementById('site-permissions-status');
  let granted = false;
  let pending;
  let refreshId = 0;

  async function refresh() {
    const id = ++refreshId;
    const allowed = await chrome.permissions.contains(sites);
    if (id !== refreshId) return;
    granted = allowed;
    button.textContent = text[granted ? 'extension-sites-revoke' : 'extension-sites-grant'];
    button.disabled = Boolean(pending);
    controls.hidden = false;
  }

  button.addEventListener('click', async event => {
    if (!event.isTrusted || pending) return;
    status.textContent = '';
    button.disabled = true;
    try {
      // Call directly in the trusted DOM event so Chromium can show its prompt.
      pending = granted ? chrome.permissions.remove(sites) : chrome.permissions.request(sites);
      if (!await pending) status.textContent = text['extension-sites-unavailable'];
    } catch {
      status.textContent = text['extension-sites-unavailable'];
    } finally {
      pending = undefined;
      refresh().catch(() => { button.disabled = true; });
    }
  });

  const onChange = () => { refresh().catch(() => { button.disabled = true; }); };
  chrome.permissions.onAdded.addListener(onChange);
  chrome.permissions.onRemoved.addListener(onChange);
  addEventListener('pagehide', () => {
    chrome.permissions.onAdded.removeListener(onChange);
    chrome.permissions.onRemoved.removeListener(onChange);
  }, {once: true});
  await refresh();
}
