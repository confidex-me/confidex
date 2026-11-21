const sessionUrl = chrome.runtime.getURL('session.html');
const sites = {origins: ['https://*/*']};
const scriptId = 'confidex-site-channel';
let opening;
let registration = Promise.resolve();

chrome.action.onClicked.addListener(() => {
  opening ??= focusSession().catch(() => {}).finally(() => { opening = undefined; });
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

chrome.permissions.onAdded.addListener(reconcileRegistration);
chrome.permissions.onRemoved.addListener(reconcileRegistration);
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

async function currentDocument({tabId, frameId, documentId, origin}) {
  if (!await chrome.permissions.contains(sites)) return false;
  // Resolve the current top frame under the browser's current site access.
  // Sender metadata can predate navigation or a permission change.
  const [current] = await chrome.scripting.executeScript({
    target: {tabId, frameIds: [frameId]}, world: 'ISOLATED', func: () => location.origin,
  });
  if (current?.documentId !== documentId || current.result !== origin) return false;
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
