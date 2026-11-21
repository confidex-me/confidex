// Document addressing only. Form inspection belongs to the autofill stage.
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id === chrome.runtime.id && !sender.tab
      && sender.url === chrome.runtime.getURL('background.js')
      && message?.kind === 'ConfidexDocumentCheck' && message.version === 1) {
    reply(true);
  }
});
