export async function popupCall(input) {
  const request = JSON.parse(input);
  const result = await chrome.runtime.sendMessage({kind: 'ConfidexPopup', ...request});
  if (request.action?.Fill && result === 'Filled') window.close();
  return JSON.stringify(result ?? 'Locked');
}
