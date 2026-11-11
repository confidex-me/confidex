# CSV import evidence and integration contract

The adapter maps one CSV data row to one ordered Core Record. It produces the
shared Plan and never writes to a vault, opens a URL or reads a path in a cell.
Normal tests use public data and need no network.

## Inputs and producer evidence

`sources.json` pins each additional fixture and its source digest. The existing
`generic.csv`, `mapping.json` and expected JSON remain the reviewed baseline.

| Input | Evidence |
| --- | --- |
| `chromium-upstream.csv` | Exact LF output expected by the pinned Chromium producer unit test; not a local browser capture |
| `chromium-100.csv` | Schema-derived from Chromium 100.0.4896.127 and its public unit-test values; the older producer has four columns |
| `firefox.csv` | The pinned, unmodified Mozilla LoginExport module executed with public logins and a local IOUtils stub |
| `apple-passwords-upstream.csv` | Exact published Bitwarden Safari reader fixture data, with URL, notes and OTPAuth |
| `apple-passwords-legacy-upstream.csv` | Exact published Bitwarden reader fixture data for the older Url spelling and four columns |

The current Chromium [producer](https://github.com/chromium/chromium/blob/2895b9a20bfc379d767f3b253c3a0f780d15061f/components/password_manager/core/browser/export/password_csv_writer.cc)
and [unit test](https://github.com/chromium/chromium/blob/2895b9a20bfc379d767f3b253c3a0f780d15061f/components/password_manager/core/browser/export/password_csv_writer_unittest.cc)
confirm the five-column layout and platform line endings. Chromium 100's
[producer](https://chromium.googlesource.com/chromium/src/+/refs/tags/100.0.4896.127/components/password_manager/core/browser/export/password_csv_writer.cc)
confirms the older layout. Chromium source uses its
[BSD-style license](https://github.com/chromium/chromium/blob/2895b9a20bfc379d767f3b253c3a0f780d15061f/LICENSE).

The Mozilla [export module](https://github.com/mozilla/gecko-dev/blob/2483a0cbf2134f0696e2b8f62c61404116255ae7/toolkit/components/passwordmgr/LoginExport.sys.mjs)
uses nine columns and CRLF, and quotes non-null values. Its source is MPL 2.0.
The capture passes explicit test logins, so the module never requests real
browser logins. Only IOUtils.writeUTF8 is replaced by Node's local file write.
This tests the producer function, not Firefox UI or a real user profile. To
repeat it, use a new output path; the script refuses to replace existing files:

```sh
node crates/confidex-app/tests/import_fixtures/csv/capture_firefox.mjs /tmp/new-firefox-capture.csv
```

The script downloads only the pinned module and checks its SHA-256 before running
it. Fixture hashes do not refresh automatically.

Apple's export implementation is closed. The two pinned
[reader fixtures](https://github.com/bitwarden/clients/tree/8ad47071a77e41a694ab0939a733e051618e10a4/libs/importer/src/importers/spec-data/safari-csv)
and [reader](https://github.com/bitwarden/clients/blob/8ad47071a77e41a694ab0939a733e051618e10a4/libs/importer/src/importers/safari-csv-importer.ts)
are independent compatibility evidence, not a local Apple Passwords capture or
proof of a current destination writer. The source has a
[GPL license](https://github.com/bitwarden/clients/blob/8ad47071a77e41a694ab0939a733e051618e10a4/LICENSE.txt).
The newer published example's illustrative OTP seed fails strict base32 trailing
bit validation. It is retained as a protected note with review, not presented as
a valid TOTP code. The generic fixture tests valid SHA256/8-digit/45-second URI
conversion. Apple's [export guide](https://support.apple.com/guide/iphone/export-passwords-iphf28f2e93e/ios)
also lists source data that its export omits. CSV does not reconstruct omitted
files, passkeys, sharing policies, history or Wi-Fi credentials.

## Mapping-step API

All helpers live in `import::formats::csv`; no registry or UI changes are hidden
inside this adapter.

- `column_count(input, delimiter, limits, callback)` reads only the first row's
  width and returns no possible credential values. Use it for input without
  confirmed column names.
- `header(input, delimiter, limits, callback)` returns a bounded, immutable Header.
  `names()` keeps empty/repeated source labels; `delimiter()` returns the selected
  delimiter. It reads only the header row and does not certify the remaining CSV.
- `Header::profiles()` returns suggestions for exact, verified header sequences.
  Chromium's four/five-column, Firefox's nine-column and Apple's four/six-column
  shapes are supported. Reordered, repeated or additional headers require manual
  mapping. A suggestion is compatible shape, not proof of the exporting program.
- `Profile::mapping(&Header)` returns the existing shared CsvMapping. Notes default
  to secure-note; Firefox's realm, action, GUID and timestamps remain independent
  private fields, not active autofill policies or signed revision history.
- `Header::private_mapping()` assigns every column to a private field until the
  user chooses its meaning. `TARGETS` lists the supported role IDs.
- `parse(input, Context)` requires explicit Options.csv and produces the Plan.
  The host runs it on its background worker and uses normal Engine review/apply.

A first row can contain passwords when the file has no header. Do not render
unknown first-row values as labels before the user confirms the header choice.
A failed profile suggestion must not make those values public. Data previews
use the existing protected field display and require reveal.

Targets are title, username/v1, password/v1, url/v1, text/v1, secret/v1, note/v1,
secure-note/v1 and totp/v1. Names are independent of roles and may be empty or
repeated. Each source column has at most one role and there is at most one title.
Unknown targets, repeated index assignments and out-of-range indices are errors.
There is no implicit ignore role. Unassigned columns become private fields with
source-preserved review. Explicit note/v1 is the user's public-note choice.

The mapper iterates source positions rather than names or mapping-array order.
Two URL columns and repeated names remain separate. It never trims or normalizes
URL, password or note data. Known TOTP goes through the shared import::totp helper;
unsupported text becomes a protected note at the same position with diagnostics.
An empty optional TOTP produces no invalid code field; its exact column is kept
in `empty_totp_columns` provenance, as required by the reviewed generic baseline.

Header/delimiter/BOM and the complete effective mapping are retained once in
container attributes. Row and byte spans are locators in private item attributes,
not IDs. Empty-cell positions and their quoted flags are also retained: a nullable
producer can encode empty strings differently from null-like slots. The importer
does not invent a distinction between null and missing that the file cannot give.

Every CSV item has no stable source item ID, including Firefox GUID columns.
The caller may provide its source instance, but row/title/URL/filename do not
become identity. Common apply matches content/baselines and requires explicit
conflict decisions. Reordered source metadata can require review. It cannot
silently update a record because the row or title matches.

Mapping changes require a fresh parse/review token. Call Engine.begin_import
before new parsing, discard stale worker replies, and release the Header/input
and credential options when no longer needed. Source provenance is encrypted and
excluded from search. A future writer must use current fields and report losses;
source metadata must not restore changed or removed secrets.

## CSV syntax and admission

Input is UTF-8 with an optional initial BOM. Invalid UTF-8 and NUL are refused;
no fallback encoding or replacement characters are guessed. Comma, semicolon,
TAB and pipe are explicit choices. Records may end with LF, CRLF or CR. Quoted
values keep their exact line breaks, doubled quotes and surrounding whitespace.
An unquoted quote, unclosed quoted field, or text after a closing quote is an
error. Empty records are not silently skipped. All rows must have the first
row's width; short and long rows are errors.

The reader scans borrowed spans before cloning values, with cancellation at
row boundaries and 64 KiB intervals during long reads. Cells, source nodes and
record counts are bounded. Default
input/plan budgets are 64 MiB, admitted memory 192 MiB, 10000 records, 512 columns,
1000000 source nodes, and 4096 bytes per column name. Decoded cell strings use the
smaller of the import string budget and the existing core string limit (currently
1 MiB). The shared pipeline enforces the entire Record's 4000000-byte compressed
cap, including all mapped fields. A compressed-small string can still exceed
its separate string limit. Records are not split and values are not shortened.

Decoded temporary values and header names clear on drop. Encoded plans and Core
values use their existing cleanup. The caller owns the original input and must
release/wipe it; the importer does not delete the source file. Library/OS/browser
copies remain outside Rust ownership guarantees.

## Checks

Private tests cover strict quoting, line endings, delimiters, source budgets,
cancellation and exact profile matching. Public `tests/import_csv.rs` checks the
real prepare/parser/validated Plan, the reviewed generic values, all five added
fixtures, manual reset/re-preview, multiple URLs, empty/repeated names, hidden
fallbacks, nullable empty cells, malformed input, reduced budgets and whole-Record
compression overflow. Native/WASI canonical record/source/container/diagnostic
hashes must match on all six inputs. Normal tests have no network dependency.

The shared test proof runs against actual native SQLite and against the real
BrowserStore/IndexedDB bridge in a browser Worker. It verifies no writes during
preview, exact decrypted canonical fields, encrypted storage, public search,
protected values/source context excluded from search, reopening, duplicate skip,
and safe row reordering with identical titles. The browser launcher uses the
existing browser runner/assets and a temporary crate; production host files stay
unchanged. Its page is a probe, not the import UI.

```sh
cargo test --release -p confidex-app --test import_csv
node crates/confidex-app/tests/import_csv/browser.mjs /path/to/chrome
```

Set CONFIDEX_TEST_CARGO/CONFIDEX_TEST_BINDGEN and CARGO_TARGET_DIR when the matching
WASM tools are outside PATH. Use wasm-bindgen 0.2.130 and the installed matching
Rust WASM target. The worker is linked with the normal 256 MiB maximum.

The separate ignored 10000-row test has ten mixed fields per record, Unicode,
quoted multiline notes, private values, empty/repeated names and TOTP. Measure
the built native test with `/usr/bin/time -l` and the WASI test with the existing
run-wasi.mjs. Measurements describe parser/encoded Plan only, not full UI/apply or
total browser process memory.

A second ignored native test and the browser `--load` mode use that same dataset
through actual SQLite or BrowserStore/IndexedDB. They create and seal all 10000
records, build/search the index, reopen with a fresh Engine and store handle,
verify every decrypted canonical Record against the source Plan, and repeat the
import with explicit duplicate skips. Protected values stay outside search.
The native wrapper closes and reopens the SQLite database file. BrowserStore has
no persistent handle to close; its new wrapper uses the existing IndexedDB bridge.
Both record phase timings; browser timings also include test-vault cleanup after
the final search. The browser reports Worker-independent page heartbeats and
retained WASM linear memory, not total browser process memory or UI cancellation.

```sh
cargo test --release -p confidex-app --test import_csv apply::ten_thousand_rows_parse_apply_reopen_search_and_repeat -- --ignored --exact --nocapture --test-threads=1
node crates/confidex-app/tests/import_csv/browser.mjs /path/to/chrome --load
```

## Application mapping step

The application's import window offers an explicit CSV mapping step. Before the
user confirms a header, only column counts and private default roles are shown.
Verified header shapes offer Chromium, Firefox or Apple Passwords profiles for
explicit selection. Manual roles and names remain editable. Reset restores
private roles; editing the header, delimiter or mapping requires a fresh preview
before Apply. A header-only file does not enable an empty import.

The production application check covers profiles, private initial/reset state,
all nine manual roles, renamed fields, back-edit/re-preview, duplicate detection,
semicolon input, malformed quoting, header-only input and unsupported UTF-16.
It checks zero writes before Apply and saves real screenshots at desktop,
intermediate and phone widths. From the repository root, build the browser
application bundle, then run:

```sh
node apps/confidex/web/import-csv-ui-check.mjs "$CHROME" "$BUNDLE" "$ARTIFACTS"
```

These checks use synthetic files and disposable browser profiles. They do not
certify native OS windows, physical phones or every browser. The separate
[stage and memory calibration](../../import_csv/performance/README.md) records
the full 10000-record native/browser pipeline measurements and their limits.
