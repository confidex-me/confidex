(() => {
  const url = chrome.runtime.getURL('content/content.js');
  globalThis.confidexContent ??= import(url).then(async module => {
    await module.default();
    return module;
  });
})();
