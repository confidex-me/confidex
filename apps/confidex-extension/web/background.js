const session = chrome.runtime.getURL('session.html');
let opening;
chrome.action.onClicked.addListener(() => {
  opening ??= focusSession().catch(() => {}).finally(() => { opening = undefined; });
});

async function focusSession() {
  const [tab] = await chrome.tabs.query({url: session});
  if (tab?.id == null) {
    await chrome.tabs.create({url: session});
  } else {
    await chrome.tabs.update(tab.id, {active: true});
    await chrome.windows.update(tab.windowId, {focused: true});
  }
}
