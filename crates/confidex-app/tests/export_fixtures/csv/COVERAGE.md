# CSV writer

`csv::Writer::new(export::Csv)` accepts an explicit ordered column selection or
one of the existing verified header profiles: `chromium`, `firefox`, and
`apple-passwords`. It uses current CoreRecord values and never restores old
credential values from an import snapshot. The host supplies configuration,
renders the shared review, obtains consent, and publishes the final artifact.
This module does not register formats or provide a second export window.

## Explicit mapping

Each column has an exact heading and one source:

- `Title` selects the current `confidex.title` string.
- `Field { index, type_name, key }` selects a current positional field and value
  key. The type is a guard, not a lookup by an editable field name. Missing
  positions, changed types or missing keys block the export. Duplicate source
  bindings are invalid; repeated and empty headings remain valid and positional.
- For `totp/v1`, selecting `secret` emits a provisioning URI for the current
  seed, algorithm, digits and period. It uses the shared TOTP helper. Original
  provider text is reused only while it matches the current parameters; changed
  seeds and parameters never replay the old URI. Unsupported TOTP parameters
  require loss consent. Further values are reported, not silently removed.
- `Tags` writes a compact JSON array inside a CSV cell. This does not create a
  tag mapping in a destination reader. Tag semantics always have a loss issue,
  including when tags were selected as text.

Manual mapping supports comma, semicolon, TAB and pipe, with or without a header.
Output is UTF-8, with CRLF row framing. Text cells and headings are quoted, quotes
are doubled, and embedded CR, LF, CRLF, Unicode, whitespace and empty strings
are preserved. No BOM, trimming, Unicode normalization, numeric conversion,
formula prefix or spreadsheet formatting changes a secret. NUL text and NUL
headings are refused because the shared CSV reader does not accept them.

Reimport uses the same delimiter, header choice, positional names and type
mapping. CSV itself does not embed that mapping or arbitrary protection flags.
Private types can be reconstructed by an explicit mapping; private flags on
public roles cannot. Different labels, field order, extra components, structured
types and unknown metadata appear in the review. A string projection of an
unsupported object is not presented as preservation of its type or structure.
Unselected fields, files, photos, additional URIs, TOTP, tags, sections and source
context have explicit issues. Lossless consent refuses all such results.

## Profile behavior

Header order and import targets are shared with the existing CSV profile table.
Profiles require a comma delimiter and a header. They select native typed roles
without matching editable field names; an additional field of the same role is
reported instead of silently merged into a cell.

| Profile | Current shape | Limits |
| --- | --- | --- |
| Chromium | `name,url,username,password,note` | One URL, username, password and note; no TOTP, files or custom columns |
| Firefox | Nine columns from `url` through `timePasswordChanged` | No title, notes or TOTP columns; source-only roles require a verified original mapping |
| Apple Passwords | `Title,URL,Username,Password,Notes,OTPAuth` | One URL, username, password, note and TOTP; no files or custom columns |

Versioned CSV provenance can supply the original role binding only when its
source format, delimiter, header names, column positions and targets match the
selected profile. The writer then uses the current field at each unique column
binding, even after record fields have moved. Duplicate bindings or changed
types block the export. Realm, form action, GUID and timestamps are never
inferred from a local secret field's label. The writer does not create vendor
history or ownership from Confidex revision metadata.

Firefox's otherwise absent source-only columns use unquoted empty cells.
Verified source metadata retains quoted-empty versus unquoted-empty cells while
the corresponding current value is still empty. Edited nonempty values take
precedence. Private notes and source-only policy fields lose their private-role
semantics in the destination profile; the review reports that loss. Missing
native columns can introduce empty fields on reimport, also reported. An empty
TOTP column represents an absent code and does not create a TOTP field.

## Independent evidence

The normal portable proof covers all four delimiters, header/no-header,
repeated/empty headings, multiple URLs, exact text and TOTP roundtrips, current
Firefox values and nullable empties. It checks monotonic progress, bounded
output, cancellation and release of all admitted export memory. Values stream
from borrowed fields through a bounded quoting writer; no complete CSV text
tree or plaintext temporary file is built.

`reader.py` reads actual writer output with Python's standard CSV reader before
`reader.cjs` executes the pinned Bitwarden Chromium, Firefox and Safari CSV
consumers. The reader verifies every executed source and package hash. It uses
the existing JSON reader's model/cleanup harness, actual PapaParse and the
actual hostname helper with its pinned `tldts` dependency. View constructors
are test property bags; encryption and account storage are outside the test.

`reader-sources.json` pins the three consumers, the upstream dependency versions,
and the NPM tarball integrity plus executed-file SHA256 for PapaParse and tldts.
Fetch the Bitwarden files from the pinned GitHub commit by basename into a
separate source directory. Download each exact package tarball, verify its
SHA512 integrity, and copy only the listed member to its `local` filename.
The shared model sources use the sibling
[JSON reader instructions](../bitwarden_json/COVERAGE.md).

With Python3, Node26 and those local source caches:

```sh
CONFIDEX_BITWARDEN_SOURCE=/path/to/shared-sources CONFIDEX_CSV_READER_SOURCE=/path/to/csv-sources cargo test -p confidex-app --test export_csv -- --include-ignored --nocapture
```

Only synthetic public data enters the subprocesses through pipes. Normal tests
do not access a network, user profile, vault or account. The `export-check`
browser Worker runs the same portable proof without adding a production format.

The independent result proves CSV framing and those consumers' read/mapping
layers. It does not prove installed Chrome, Firefox or Apple Passwords import
UI behavior. Bitwarden's CSV parser normalizes line endings; Firefox's consumer
derives a title from the URL and ignores realm/GUID/time columns. Those consumer
limits do not change the exact bytes stored in the CSV. Our own importer checks
the retained source-only values and nullable markers separately. No complete
vendor migration, autofill-policy restoration or protection transfer is implied.

## Host setup metadata

The typed export protocol has a `Fields` request for one current record head and
a source offset. Its reply contains only field positions, names, types and value
component keys. Field values, source snapshots and attachment payloads stay in
the service. These bindings use positions and types, not editable display names.

Each page has at most 16 bindings. Names fit the 4096-byte CSV heading limit
without splitting UTF-8; type and component-key bounds match the writer options.
An original name beyond that limit needs a shorter CSV heading and the writer's
normal name-loss review. The service admits one MiB for metadata, including
worst-case JSON escaping. Each page owns that charge; its descriptors clear their
strings on drop.

The service authenticates the envelope and checks the current head before and
after each page. Stale heads, deletion revisions, wrong record headers,
corruption, cancellation and lock return no fields. A setup request invalidates
an older export review or ready artifact. It never writes the vault.

Native SQLite and browser Worker checks exercise the serialized protocol,
repeated and empty names, multiple components, long Unicode names, maximum
valid escaped keys, page boundaries and absence of field values in replies.
This is the setup contract; it does not by itself certify a completed CSV window.

The shared setup model retains one charged metadata page and an ordered manual
column draft. Switching to a fixed profile preserves that draft; fixed profiles
always use a comma and a header. Duplicate source bindings and invalid headings
prevent review. Column movement preserves the original field position. Review
transfers the exact configuration without cloning its strings. Cancel, lock and
failure clear the setup, and an outdated metadata response cannot restore it.
Native host tests and the production WASM worker exercise these transitions.
CSV remains outside the production catalog until the form and translations are
complete.

The common writer factory accepts CSV options without copying their strings.
Native SQLite and browser Worker session checks export current signed revisions
through that factory, shared review, consent and chunk transfer. Exact byte
expectations cover all four delimiters, header/no-header and the three fixed
profiles, including CRLF, quotes, Unicode, repeated headings and empty cells.
A positional mapping incompatible with another selected record blocks generation
even with loss consent. The public command protocol still refuses CSV while it
is absent from the catalog; these checks do not claim a completed CSV form or
browser download.

Sources:

- [Pinned Chromium CSV consumer](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/importer/src/importers/chrome-csv-importer.ts).
- [Pinned Firefox CSV consumer](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/importer/src/importers/firefox-csv-importer.ts).
- [Pinned Safari CSV consumer](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/importer/src/importers/safari-csv-importer.ts).
- [Source schemas and producer evidence](../../import_fixtures/csv/COVERAGE.md).
