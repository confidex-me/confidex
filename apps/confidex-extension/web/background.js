const sessionUrl = chrome.runtime.getURL('session.html');
const popupUrl = chrome.runtime.getURL('popup.html');
const sites = {origins: ['https://*/*']};
const scriptId = 'confidex-site-channel';
let opening;
let registration = Promise.resolve();
let settingPolicy = Promise.resolve();
let paintingBadges = Promise.resolve();
let badgeTabs = new Set();
let badgeRevision = 0;
const captureRoutes = new Map();

void chrome.storage.local.setAccessLevel({accessLevel: 'TRUSTED_CONTEXTS'}).catch(() => {});

async function sitePolicy(origin) {
  const {siteExceptions} = await chrome.storage.local.get('siteExceptions');
  return siteExceptions?.[origin] ?? 'Allow';
}

function setSitePolicy(origin, policy) {
  const update = settingPolicy.then(async () => {
    const {siteExceptions: exceptions = {}} = await chrome.storage.local.get('siteExceptions');
    if (policy === 'Allow') delete exceptions[origin];
    else {
      if (!Object.hasOwn(exceptions, origin) && Object.keys(exceptions).length >= 512) return 'Error';
      if (exceptions[origin] !== 'Disabled') exceptions[origin] = policy;
    }
    await chrome.storage.local.set({siteExceptions: exceptions});
    return 'PolicyChanged';
  });
  settingPolicy = update.catch(() => {});
  return update;
}

async function captureStateChanged() {
  const tabs = await chrome.tabs.query({});
  await Promise.allSettled(tabs.filter(tab => !tab.incognito).map(({id}) =>
    chrome.tabs.sendMessage(id, {kind: 'ConfidexCaptureReset', version: 1}, {frameId: 0})));
}

function paintBadges(tabs) {
  badgeRevision++;
  badgeTabs = new Set(tabs);
  paintingBadges = paintingBadges.then(async () => {
    const tabs = await chrome.tabs.query({});
    await Promise.allSettled(tabs.filter(tab => !tab.incognito).map(tab => paintBadge(tab.id)));
  }).catch(() => {});
}

function paintBadge(tabId) {
  return chrome.action.setBadgeText({tabId, text: badgeTabs.has(tabId) ? '1' : ''});
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.siteExceptions) void captureStateChanged().catch(() => {});
});

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

chrome.permissions.onAdded.addListener(() => {
  reconcileRegistration();
  void captureStateChanged().catch(() => {});
});
chrome.permissions.onRemoved.addListener(() => {
  reconcileRegistration();
  paintBadges([]);
  void captureStateChanged().catch(() => {});
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

function httpsOrigin(url) {
  try {
    const target = new URL(url);
    if (target.protocol === 'https:' && !target.username && !target.password) return target.origin;
  } catch {
    // Some tab addresses are hidden or have no HTTPS origin.
  }
}

function siteContext(sender) {
  if (sender.id !== chrome.runtime.id || sender.frameId !== 0
      || sender.documentLifecycle !== 'active' || sender.tab?.incognito !== false
      || typeof sender.url !== 'string' || !Number.isInteger(sender.tab.id) || sender.tab.id < 0
      || !/^[\da-f-]{1,64}$/i.test(sender.documentId ?? '')) return;
  const origin = httpsOrigin(sender.url);
  if (!origin || origin !== sender.origin) return;
  return {tabId: sender.tab.id, frameId: sender.frameId, documentId: sender.documentId, origin};
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
  if (await sitePolicy(context.origin) === 'Disabled' || !await currentDocument(context)) return false;
  const live = await chrome.runtime.sendMessage({kind: 'ConfidexRoutedForm', version: 1, context, report});
  return live === true && await currentDocument(context);
}

function sessionMessage(kind, data) {
  return chrome.runtime.sendMessage({kind, version: 1, ...data});
}

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.kind !== 'CapturePlan' && message?.kind !== 'CaptureCandidate') return;
  const context = siteContext(sender);
  const plan = message.kind === 'CapturePlan';
  if (!context || message.version !== 1 || Object.keys(message).length !== (plan ? 3 : 6)
      || (!plan && (!operationId(message.owner) || !Number.isInteger(message.revision)
        || typeof message.values !== 'object' || message.values === null))) {
    reply(false);
    return;
  }
  const snapshot = plan && message.snapshot === null ? {page: 1, forms: []} : message.snapshot;
  if (!snapshot || JSON.stringify(snapshot).length > (plan ? 192 * 1024 : 32 * 1024)
      || (!plan && JSON.stringify(message.values).length > 74 * 1024)) {
    reply(false);
    return;
  }
  // The active top-frame sender identifies the document at send time. A
  // native submit can already have navigated by the time this route runs.
  async function route() {
    if (!await chrome.permissions.contains(sites) || await sitePolicy(context.origin) !== 'Allow') return false;
    if (plan) return sessionMessage('ConfidexCapturePlan', {context, snapshot});
    const tab = await chrome.tabs.get(context.tabId);
    if (tab.incognito || captureRoutes.get(context.tabId) !== routes) return false;
    const report = {version: 1, id: crypto.randomUUID(), revision: message.revision,
      snapshot, values: message.values};
    return await sessionMessage('ConfidexSiteCapture', {context, owner: message.owner, report}) === true;
  }
  const routes = plan ? null : captureRoutes.get(context.tabId) ?? {count: 0};
  if (routes) {
    if (routes.count >= 4) {
      reply(false);
      return;
    }
    routes.count++;
    captureRoutes.set(context.tabId, routes);
  }
  route().then(reply, () => reply(false)).finally(() => {
    if (routes && --routes.count === 0 && captureRoutes.get(context.tabId) === routes) {
      captureRoutes.delete(context.tabId);
    }
  });
  return true;
});

function isSessionPage(sender) {
  return sender.id === chrome.runtime.id && sender.url === sessionUrl && sender.frameId === 0
    && sender.tab?.incognito === false;
}

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.version !== 1 || !isSessionPage(sender)) return;
  if (message.kind === 'ConfidexCaptureState' && typeof message.open === 'boolean') {
    if (!message.open) paintBadges([]);
    void captureStateChanged().catch(() => {});
    reply(true);
  } else if (message.kind === 'ConfidexSaveBadges' && Array.isArray(message.tabs)
    && message.tabs.length <= 10 && message.tabs.every(tab => Number.isInteger(tab) && tab >= 0)) {
    paintBadges(message.tabs);
    reply(true);
  }
});

const initialBadgeRevision = badgeRevision;
void sessionMessage('ConfidexReadBadges').catch(() => []).then(tabs => {
  if (badgeRevision === initialBadgeRevision) paintBadges(Array.isArray(tabs) ? tabs : []);
});

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

async function enableCaptureInTab(tabId) {
  if (!await liveSession()) return;
  const context = await resolveDocument(tabId);
  if (!context || await sitePolicy(context.origin) !== 'Allow') return;
  try {
    await sendToDocument(context, 'ConfidexDocumentCheck');
  } catch {
    await chrome.scripting.executeScript({
      target: {tabId, documentIds: [context.documentId]},
      files: ['content-channel.js'], world: 'ISOLATED',
    });
  }
}

chrome.tabs.onActivated.addListener(({tabId}) => {
  void enableCaptureInTab(tabId).catch(() => {});
});

async function popupAction(action, inSession) {
  if (action === 'OpenSession') {
    opening ??= focusSession().finally(() => { opening = undefined; });
    await opening;
    return 'Live';
  }
  if (action?.SetPolicy) {
    const {origin, policy} = action.SetPolicy;
    if (!await chrome.permissions.contains(sites)) return 'Unavailable';
    return setSitePolicy(origin, policy);
  }
  const owner = await liveSession();
  if (!owner) return 'Locked';
  if (action?.Save) {
    const tab = inSession ? null : await activeTab();
    if (tab === undefined) return {Save: 'Locked'};
    if (action.Save === 'List') {
      return {Save: await sessionMessage('ConfidexListSaves', {owner, tab}) ?? 'Locked'};
    }
    const result = await sessionMessage('ConfidexSaveCommand', {owner,
      request: {version: 1, tab, action: action.Save}});
    return {Save: result?.response ? JSON.parse(result.response) : result?.status ?? 'Locked'};
  }
  if (action?.Check) {
    if (await liveSession(action.Check.operation, owner) && await chrome.permissions.contains(sites)) return 'Live';
    return await liveSession('', owner) ? 'Changed' : 'Locked';
  }

  const tabId = await activeTab();
  if (tabId == null) return 'Unavailable';
  const context = await resolveDocument(tabId).catch(() => undefined);
  if (!context) return action?.Fill ? 'Changed' : 'Unavailable';
  const policy = await sitePolicy(context.origin);
  if (policy === 'Disabled') return {SiteDisabled: {origin: context.origin}};

  if (action?.Discover) {
    const operation = crypto.randomUUID();
    const snapshot = await inspectDocument(context).catch(() => undefined);
    if (!snapshot || !await currentDocument(context).catch(() => false)) return 'Unavailable';
    const result = await siteCommand(owner, context, {
      Find: {operation, snapshot, after: action.Discover.after, previous: action.Discover.previous},
    });
    if (!await currentDocument(context).catch(() => false) || tabId !== await activeTab()) return 'Changed';
    if (await sitePolicy(context.origin) === 'Disabled') return {SiteDisabled: {origin: context.origin}};
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
        || await sitePolicy(context.origin) === 'Disabled'
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

function operationId(value) {
  return typeof value === 'string' && /^[\da-f-]{1,64}$/i.test(value);
}

function popupRequest(message, inSession) {
  const action = message?.action;
  if (message?.version !== 1 || Object.keys(message).length !== 3) return false;
  if (action === 'OpenSession') return !inSession;
  if (action === null || typeof action !== 'object' || Object.keys(action).length !== 1) return false;
  if (action.Save) {
    const save = action.Save;
    return save === 'List' || (typeof save === 'object' && Object.keys(save).length === 1
      && operationId(save.Confirm?.id ?? save.Dismiss?.id));
  }
  if (action.SetPolicy) {
    const {origin, policy} = action.SetPolicy;
    return typeof origin === 'string' && origin.length <= 1024 && origin.startsWith('https://')
      && httpsOrigin(origin) === origin
      && (inSession ? policy === 'NoSave' : ['Allow', 'NoSave', 'Disabled'].includes(policy));
  }
  if (inSession) return false;
  if (action.Check) return operationId(action.Check.operation);
  if (action.Fill) return operationId(action.Fill.operation) && Number.isInteger(action.Fill.form);
  return Boolean(action.Discover)
    && (action.Discover.previous == null || operationId(action.Discover.previous));
}

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.kind !== 'ConfidexPopup') return;
  const inSession = isSessionPage(sender);
  if (sender.id !== chrome.runtime.id || (!inSession && sender.url !== popupUrl) || sender.frameId > 0
      || !popupRequest(message, inSession)) {
    reply('Error');
    return;
  }
  popupAction(message.action, inSession).then(reply, () => reply('Error'));
  return true;
});

function navigation(tabId, url) {
  const origin = httpsOrigin(url) ?? null;
  void sessionMessage('ConfidexSiteNavigation', {tabId, origin}).catch(() => {});
}

chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (change.url || change.status === 'loading' || (change.status === 'complete' && !tab.url)) {
    navigation(tabId, change.url ?? tab.pendingUrl ?? tab.url);
  }
  if (change.status === 'complete' && badgeTabs.has(tabId)) void paintBadge(tabId).catch(() => {});
});
function closeSite(tabId) {
  captureRoutes.delete(tabId);
  badgeTabs.delete(tabId);
  const revision = badgeRevision;
  void sessionMessage('ConfidexSiteClosed', {tabId}).catch(() => false).then(handled => {
    if (!handled && badgeTabs.size && revision === badgeRevision) paintBadges([]);
  });
}
chrome.tabs.onRemoved.addListener(closeSite);
chrome.tabs.onReplaced.addListener((_, removedTabId) => closeSite(removedTabId));
