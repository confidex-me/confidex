// A download is published only from the explicit Save action.
export function saveExport(bytes, name, mediaType) {
  const link = document.createElement('a');
  const url = URL.createObjectURL(new Blob([bytes], {type: mediaType}));
  let started = false;
  try {
    link.href = url;
    link.download = name;
    document.body.append(link);
    link.click();
    started = true;
  }
  finally {
    link.remove();
    if (started) setTimeout(() => URL.revokeObjectURL(url), 60000);
    else URL.revokeObjectURL(url);
  }
}
