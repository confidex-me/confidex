# 1PUX export checks

All data here is public synthetic data. The source JSON is hand-authored, not
produced by the writer under test or captured from an installed 1Password app.

`section-files.input.json` checks the shared attachment mapping needed for an
export roundtrip: two ordered section files with the same filename and different
document IDs, an empty payload, empty/repeated field labels, an intervening
concealed field and a separate main document. Expected bytes are literal test
data. Both historical double-underscore and documented triple-underscore paths
are checked. Missing IDs cannot match a different same-named file; ambiguous
paths, unsafe descriptors and wrong sizes cannot apply.

The shared resolver retains each field's section metadata and exact source path.
It keeps file-buffer and reservation-header charges until the Record enters the
common plan. Canonical current sections retain empty groups and repeated titles;
native layout takes precedence over stale field import hints.

## Writer

`onepassword_1pux::Writer::new(unix_seconds)` writes version 3 with stored ZIP
members, private file permissions, fresh random account/vault/item scopes and
unique document bindings. The caller supplies the export time; source timestamps
and Confidex revisions do not become foreign password history. New exports use
new scopes. The writer streams borrowed values and file chunks into the common
bounded output, without a plaintext extraction tree or network calls.

| Current Record value | 1PUX output and review |
| --- | --- |
| Username/password | Designated login fields; additional fields retain their names and values |
| Text, empty/repeated labels | Independent login or section fields |
| Public URL | Ordered overview URL or section URL, according to its current position |
| Secret / secure note | Concealed section value; secure notes also retain multiline |
| Protected text/username/URL | Concealed value; explicit type-change loss, never an ordinary public string |
| Public note | Multiline section value; secure-note conversion reported |
| TOTP | Current seed/algorithm/digits/period; original provisioning text reused only while it matches current values |
| Nonzero TOTP start / unsupported parameters | Loss report, no guessed replacement |
| File | Exact bytes and filename, unique ID, multiple same-named and empty files |
| Photo | Exact stored bytes as an attachment; type and additional metadata losses reported |
| Sections | Current v1 groups, including empty/repeated titles; required anonymous containers count toward the 512-section cap |
| Cleared/opaque native layout | Old imported titles are never restored; unsupported layout requires consent |
| Tags/title | Current values |
| Unsupported field/value/metadata | Located loss report before writing; default consent rejects losses |
| Unsafe filename | Blocked; loss consent cannot override it |
| Source snapshots, policies and history | Omitted with source-context loss, never replayed over current edits/deletions |

The format separates login fields, overview URLs and sections. A Record whose
order cannot fit that separation gets an order warning. Unsupported field types
(including date/month-year, location, SSH and compound card values) require loss
consent; this writer does not invent a generic lossless representation for them.

Portable tests check the literal version/JSON structure, ordered values and
protection, current edits, distinct ZIP member bindings, canonical sections,
fresh scopes, unsafe names, directory-memory admission, output limits, progress,
cancellation and release of the shared memory budget. The public worker proof
also runs in an actual Chrome WASM Worker with external fetch prohibited. It
checks concealed values, advanced TOTP, exact file bytes, failure and cancellation.
The host also registers the writer in the common export window.

## Independent reader

The optional `pinned_independent_consumer_reads_actual_writer_output` test writes
a real two-item archive. Python's standard ZIP reader checks CRC, version,
unique scopes/member names and both exact document bindings. It passes the
unaltered `export.data` to the SHA-pinned Bitwarden 1PUX mapping reader, reusing
the existing source-loader fixture. TypeScript is compiled with esbuild; view
objects and configuration are test boundaries. No SSH SDK path is substituted.
Source identities are recorded in `reader-sources.json`; the shared Bitwarden
loader verifies its own source manifests too.

This executed reader confirms login credentials, multiple URLs, short concealed
fields and source item traversal. Its conversion has material limits: empty
values and attachments are skipped, only the first tag becomes a folder,
multiline concealed values become ordinary notes, and a TOTP on a secure-note
item becomes a text custom field. These are consumer limits, not changes to the
archive: the independent ZIP check and our importer retain both payloads. Do not
claim this consumer preserves the complete Record or all protection semantics.

The shared captured-source reverse check also exercises a login with a later
section URL and TOTP. This pinned reader exposes both as text custom fields:
it promotes TOTP to the native login slot only when the field ID starts with
`TOTP_`, while this writer uses opaque generated field IDs. The check compares
the current URI and seed/algorithm/digits/period in that custom value;
it does not claim native TOTP recognition by this consumer. The current note
text, exact attachment bytes and absence of removed source secrets are checked
separately. See the [shared scenario](../../export_flow/README.md#captured-source-reverse-conversion).

The optional test needs Python, Node (with `stripTypeScriptTypes` for the shared
loader), esbuild, `CONFIDEX_BITWARDEN_READER_SOURCE` and
`CONFIDEX_ONEPASSWORD_READER_SOURCE`. Set `CONFIDEX_READER_ESBUILD` if esbuild is
not on PATH. The source directories contain the files identified by the pinned
manifests. Only public fixture bytes are written to the temporary test directory.

Evidence:

- [Official 1PUX format](https://support.1password.com/1pux-format/): version 3,
  ZIP members, section values and document/file bindings; read 2026-11-10.
- [Pinned KeePassXC reader](https://github.com/keepassxreboot/keepassxc/blob/6bcb901aefdd6c7a525466d7dfe099c5ebc13c0e/src/format/OPUXReader.cpp):
  its `value.file` branch reads multiple section attachments by document ID and
  filename. SHA256 `f0b72c867e4bd6e2830c3a9cf48b52e4ba1df850fa380b5f31d1e2572784f9fe`.
  The destination attachment map can overwrite repeated filenames. This is a
  consumer limitation, not permission to omit payloads from the 1PUX archive.

The KeePassXC C++ source was inspected, not executed against this writer. The
executed Bitwarden source reader is a separate consumer, not a fresh installed
vendor application. No import into the 1Password application is certified.

The shared host check (`apps/confidex/web/export-ui-check.mjs`, `onepassword-1pux`, production
`export-ui-check` bundle) downloads one selected record and all records at
desktop and narrow widths. The independent ZIP reader checks member CRCs,
unique scopes, document bindings and the exact 600001-byte attachment. The
same pinned mapping reader checks current Unicode/multiline credentials and
short hidden custom fields from these downloaded bytes. Its existing empty
value, multiline custom-field and attachment limits still apply. Separate loss
and plaintext confirmations, Save, save failure, Ready cancellation and vault
lock are exercised through the shared form. No new vendor-app import claim is
made by registering this format.
