export async function extensionStrings() {
  const response = await fetch('./session-messages.json');
  if (!response.ok) throw new Error(`session-messages.json (${response.status})`);
  const catalogues = await response.json();
  let language = 'en-US';
  for (const preference of navigator.languages) {
    const locale = new Intl.Locale(preference);
    const chinese = locale.language === 'zh' ? `zh-${locale.maximize().script}` : undefined;
    const match = [locale.baseName, chinese, locale.language].find(id => catalogues[id]);
    if (match) {
      language = match;
      break;
    }
  }
  document.documentElement.lang = language;
  return catalogues[language];
}
