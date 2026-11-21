export async function popupCall(input) {
  const request = JSON.parse(input);
  const result = await chrome.runtime.sendMessage({kind: 'ConfidexPopup', ...request});
  return JSON.stringify(result ?? 'Locked');
}
