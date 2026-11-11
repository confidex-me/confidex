# Bitwarden ZIP producer capture

All values are public synthetic test data. No account, stored vault or network
attachment is read. These archives come from the actual individual ZIP export
method and JSON models in Bitwarden clients commit
`2ff80e50951792379f970f65cd4fb585fc50bbd5`, with decrypted providers and downloads
replaced by local fixtures. This is a producer-code capture, not a CLI or UI run.

The pinned source paths and SHA-256 values are in `capture-sources.json`.
The ZIP implementation is JSZip 3.10.1, as pinned in the upstream
[package.json](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/package.json).
The actual layout comes from
[getDecryptedExportZip](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/tools/export-vault-core/src/services/individual-vault-export.service.ts).

Run with Node 26, the checked source files in one directory and JSZip installed
outside this repository:

```
npm install --prefix /tmp/confidex-zip-capture --ignore-scripts --no-audit --no-fund jszip@3.10.1
node capture.cjs SOURCE_DIRECTORY /tmp/confidex-zip-capture/node_modules/jszip
```

Add `--write` to regenerate fixtures. Only ZIP member dates are fixed to make
the output deterministic. The exporter, sanitization, collision behavior, JSON
serialization and ZIP generation run unchanged. The manifest verifies whole
archives and every file. Its skipped count is the producer's separate return
value; that count is **not** stored in the ZIP.

| Capture | Observed behavior |
| --- | --- |
| personal | `data.json`, `attachments/<sanitized name>/<file>`; Unicode, equal filenames in different records, duplicate filename suffix, empty file |
| duplicate | Two equal record names, only the second has a file; no ID in the folder or JSON identifies the owner |
| sanitize | Distinct names `a/b` and `a\b` share `a_b/` |
| suffix | Duplicate names create `Same_1/`, which collides with a real record named `Same_1` |
| skipped | Failed download leaves an empty folder; JSON contains no missing-file reference |
| restricted | The JSON excludes a restricted item, but its file remains as an orphan |

Filename sanitization can discard original characters (`scan.part.txt` becomes
`scanpart.txt`). Import preserves the archived name; the discarded original is
not recoverable. Partial download failures leave no detectable reference when
another file succeeds. The importer must report archive-only coverage and must
not claim that the original vault's attachment inventory was verified.

Ambiguous ownership must block import, not select a record by order or basename.
This profile is individual export only, not organization backup.
