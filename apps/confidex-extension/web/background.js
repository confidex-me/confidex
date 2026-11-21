const sessionUrl = chrome.runtime.getURL('session.html');
const popupUrl = chrome.runtime.getURL('popup.html');
const sites = {origins: ['https://*/*']};
const scriptId = 'confidex-site-channel';
let opening;
let registration = Promise.resolve();

async function focusSession() {
  const [tab] = await chrome.tabs.query({url: sessionUrl});
  if (tab?.id == null) {
    await chrome.tabs.create({url: sessionUrl});
  } else {
    await chrome.tabs.update(tab.id, {active: true});
    await chrome.windows.update(tab.windowId, {focused: true});
  }
}

function reconcileRegistration() {
  registration = registration.then(async () => {
    const [script] = await chrome.scripting.getRegisteredContentScripts({ids: [scriptId]});
    const granted = await chrome.permissions.contains(sites);
    if (granted && !script) {
      await chrome.scripting.registerContentScripts([{
        id: scriptId, matches: sites.origins, js: ['content-channel.js'],
        allFrames: false, world: 'ISOLATED', runAt: 'document_start',
      }]);
    } else if (!granted && script) {
      await chrome.scripting.unregisterContentScripts({ids: [scriptId]});
    }
  }).catch(() => {
    // Chrome enforces host permissions at injection time. Retry on the next
    // permission change or background start.
  });
}

chrome.permissions.onAdded.addListener(reconcileRegistration);
chrome.permissions.onRemoved.addListener(() => {
  reconcileRegistration();
  void sessionMessage('ConfidexSiteReset').catch(() => {});
});
reconcileRegistration();

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.kind !== 'FormPresence') return;
  const context = siteContext(sender);
  if (!context || message.version !== 1 || message.hasPassword !== true
      || Object.keys(message).length !== 3) {
    reply(false);
    return;
  }
  const report = {kind: 'FormPresence', version: 1, hasPassword: true};
  routeForm(context, report).then(reply, () => reply(false));
  return true;
});

function siteContext(sender) {
  if (sender.id !== chrome.runtime.id || sender.frameId !== 0
      || sender.documentLifecycle !== 'active' || sender.tab?.incognito !== false
      || typeof sender.url !== 'string' || !Number.isInteger(sender.tab.id) || sender.tab.id < 0
      || !/^[\da-f-]{1,64}$/i.test(sender.documentId ?? '')) return;
  const url = new URL(sender.url);
  if (url.protocol !== 'https:' || url.origin !== sender.origin) return;
  return {tabId: sender.tab.id, frameId: sender.frameId, documentId: sender.documentId, origin: url.origin};
}

async function resolveDocument(tabId) {
  if (!await chrome.permissions.contains(sites)) return;
  const frameId = 0;
  const [current] = await chrome.scripting.executeScript({
    target: {tabId, frameIds: [frameId]}, world: 'ISOLATED',
    func: () => location.protocol === 'https:' && globalThis.origin === location.origin
      && !document.prerendering ? location.origin : null,
  });
  if (current?.result && current.documentId) {
    return {tabId, frameId, documentId: current.documentId, origin: current.result};
  }
}

async function currentDocument({tabId, frameId, documentId, origin}) {
  // Sender metadata can predate navigation or a permission change.
  const current = await resolveDocument(tabId);
  if (current?.documentId !== documentId || current.origin !== origin) return false;
  // The browser delivers the challenge to the document ID, not just the tab.
  // Existing isolated worlds can outlive host permission revocation.
  const result = await chrome.tabs.sendMessage(tabId, {kind: 'ConfidexDocumentCheck', version: 1},
    {frameId, documentId});
  return result === true && await chrome.permissions.contains(sites);
}

async function routeForm(context, report) {
  if (!await currentDocument(context)) return false;
  const live = await chrome.runtime.sendMessage({kind: 'ConfidexRoutedForm', version: 1, context, report});
  return live === true && await currentDocument(context);
}

function sessionMessage(kind, data) {
  return chrome.runtime.sendMessage({kind, version: 1, ...data});
}

function liveSession(operation = '', owner) {
  return sessionMessage('ConfidexSiteCheck', {operation, owner}).catch(() => false);
}

function sendToDocument(context, kind, data) {
  return chrome.tabs.sendMessage(context.tabId, {kind, version: 1, origin: context.origin, ...data},
    {documentId: context.documentId, frameId: 0});
}

async function siteCommand(owner, context, action) {
  const result = await sessionMessage('ConfidexSiteCommand', {owner, request: {version: 1, context, action}});
  return result?.response ? JSON.parse(result.response) : {Popup: result?.status ?? 'Locked'};
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({active: true, lastFocusedWindow: true});
  return tab?.incognito === false ? tab.id : undefined;
}

async function inspectDocument(context) {
  try {
    return await sendToDocument(context, 'ConfidexInspect');
  } catch {
    // Registration does not retroactively inject into pages open before grant.
    await chrome.scripting.executeScript({
      target: {tabId: context.tabId, documentIds: [context.documentId]},
      files: ['content-channel.js'], world: 'ISOLATED',
    });
    return sendToDocument(context, 'ConfidexInspect');
  }
}

async function popupAction(action) {
  if (action === 'OpenSession') {
    opening ??= focusSession().finally(() => { opening = undefined; });
    await opening;
    return 'Live';
  }
  const owner = await liveSession();
  if (!owner) return 'Locked';
  if (action?.Check) {
    if (await liveSession(action.Check.operation, owner) && await chrome.permissions.contains(sites)) return 'Live';
    return await liveSession('', owner) ? 'Changed' : 'Locked';
  }

  const tabId = await activeTab();
  if (tabId == null) return 'Unavailable';
  const context = await resolveDocument(tabId).catch(() => undefined);
  if (!context) return action?.Fill ? 'Changed' : 'Unavailable';

  if (action?.Discover) {
    const operation = crypto.randomUUID();
    const snapshot = await inspectDocument(context).catch(() => undefined);
    if (!snapshot || !await currentDocument(context).catch(() => false)) return 'Unavailable';
    const result = await siteCommand(owner, context, {
      Find: {operation, snapshot, after: action.Discover.after},
    });
    if (!await currentDocument(context).catch(() => false) || tabId !== await activeTab()) return 'Changed';
    return result.Popup ?? 'Error';
  }
  if (action?.Fill) {
    const {operation, form, target} = action.Fill;
    if (!await currentDocument(context).catch(() => false)) return 'Changed';
    const snapshot = await sendToDocument(context, 'ConfidexPreflight', {operation, form}).catch(() => false);
    if (!snapshot || !await currentDocument(context).catch(() => false) || tabId !== await activeTab()) return 'Changed';
    const result = await siteCommand(owner, context, {Fill: {operation, form, target, snapshot}});
    if (!result.Fill) return result.Popup ?? 'Error';
    if (!await currentDocument(context).catch(() => false) || tabId !== await activeTab()
        || !await liveSession('', owner) || !await chrome.permissions.contains(sites)) return 'Changed';

    if (!await sendToDocument(context, 'ConfidexValidateFill', {operation, form}).catch(() => false)
        || !await chrome.permissions.contains(sites)) return 'Changed';
    const {fields, login} = result.Fill;
    const filled = await sendToDocument(context, 'ConfidexFill', {operation, fields, login}).catch(() => false);
    if (!filled) return 'Changed';
    if (fields.password === null) {
      await siteCommand(owner, context, {Complete: {operation}}).catch(() => {});
    }
    return 'Filled';
  }
  return 'Error';
}

function popupRequest(message) {
  const id = value => typeof value === 'string' && /^[\da-f-]{1,64}$/i.test(value);
  const action = message?.action;
  if (message?.version !== 1 || Object.keys(message).length !== 3) return false;
  if (action === 'OpenSession') return true;
  if (action === null || typeof action !== 'object' || Object.keys(action).length !== 1) return false;
  if (action.Check) return id(action.Check.operation);
  if (action.Fill) return id(action.Fill.operation) && Number.isInteger(action.Fill.form);
  return Boolean(action.Discover);
}

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.kind !== 'ConfidexPopup') return;
  if (sender.id !== chrome.runtime.id || sender.url !== popupUrl || sender.frameId > 0
      || !popupRequest(message)) {
    reply('Error');
    return;
  }
  popupAction(message.action).then(reply, () => reply('Error'));
  return true;
});

function navigation(tabId, url) {
  let origin = null;
  try {
    const target = new URL(url);
    if (target.protocol === 'https:') origin = target.origin;
  } catch {
    // Chrome omits the address for hosts this extension cannot access.
  }
  void sessionMessage('ConfidexSiteNavigation', {tabId, origin}).catch(() => {});
}

chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (change.url || change.status === 'loading' || (change.status === 'complete' && !tab.url)) {
    navigation(tabId, change.url ?? tab.pendingUrl ?? tab.url);
  }
});
chrome.tabs.onRemoved.addListener(tabId => navigation(tabId));
chrome.tabs.onReplaced.addListener((_, removedTabId) => navigation(removedTabId));
