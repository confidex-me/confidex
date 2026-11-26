let port;
let pending;
let notify;
let revision = 0;
let syncRevision = 0;
let hostRevision;

function connect() {
  if (port) return port;
  port = chrome.runtime.connect({name: 'vault-ui'});
  port.onMessage.addListener(message => {
    if ('revision' in message) {
      if (!message.initial && message.revision !== hostRevision) revision++;
      hostRevision = message.revision;
      syncRevision = message.syncRevision;
      notify?.();
    } else if (pending) {
      const request = pending;
      pending = undefined;
      if (message.failed) request.reject(new Error('Confidex session closed'));
      else request.resolve(new TextEncoder().encode(message.result));
    }
  });
  port.onDisconnect.addListener(() => {
    port = undefined;
    pending?.reject(new Error('Session closed'));
    pending = undefined;
    revision++;
    notify?.();
  });
  return port;
}
function activity(event) {
  if (event.isTrusted) port?.postMessage({kind: 'Activity'});
}
export function observeSession(callback) {
  notify = callback;
  chrome.storage.onChanged.addListener(autoSettingChanged);
  void chrome.storage.local.get('autoFillOnOpen').then(value => {
    autoSetting = value.autoFillOnOpen === true;
    notify?.();
  });
  addEventListener('confidex-permission-change', callback);
  for (const event of ['pointerdown', 'wheel', 'keydown']) addEventListener(event, activity, true);
}
export function disposeSession() {
  if (notify) removeEventListener('confidex-permission-change', notify);
  chrome.storage.onChanged.removeListener(autoSettingChanged);
  notify = undefined;
  for (const event of ['pointerdown', 'wheel', 'keydown']) removeEventListener(event, activity, true);
  port?.disconnect();
}
export function cancelSession() { port?.postMessage({kind: 'Lock'}); }
export function sessionRevision() { return revision; }
export function syncStatusRevision() { return syncRevision; }
export function exchange(bytes) {
  return new Promise((resolve, reject) => {
    try {
      if (pending) throw new Error("Confidex session request already pending");
      connect().postMessage({kind: 'Exchange', input: new TextDecoder().decode(bytes)});
      pending = {resolve, reject};
    } finally { bytes.fill(0); }
  });
}
export function showPermissions(visible) {
  const controls = document.getElementById('site-permissions');
  if (controls.hidden === visible) controls.hidden = !visible;
}

export function hasSiteAccess() {
  return document.getElementById('site-permissions-toggle').dataset.granted === 'true';
}

export function placePermissionButton(x, y, width, accent, foreground) {
  const controls = document.getElementById('site-permissions');
  const canvas = document.getElementById('session').getBoundingClientRect();
  Object.assign(controls.style, {
    left: (canvas.left + x) + 'px', top: (canvas.top + y) + 'px', width: width + 'px',
  });
  controls.style.setProperty('--accent', accent);
  controls.style.setProperty('--on-accent', foreground);
}

let autoSetting;
function autoSettingChanged(changes, area) {
  if (area === 'local' && changes.autoFillOnOpen) {
    autoSetting = changes.autoFillOnOpen.newValue === true;
    notify?.();
  }
}
export function autoFillSetting() { return autoSetting === undefined ? -1 : Number(autoSetting); }
export function setAutoFillSetting(enabled) {
  autoSetting = undefined;
  chrome.storage.local.set({autoFillOnOpen: enabled}).then(() => {
    autoSetting = enabled;
  }, () => { autoSetting = !enabled; }).finally(() => notify?.());
}
