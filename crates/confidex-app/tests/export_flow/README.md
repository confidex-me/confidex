# Export session checks

All passwords, keys, records and file bytes in this directory are public synthetic
test data. `proof.rs` runs against the real Store trait. Native tests use actual
SQLite files; the opt-in client feature `export-check` runs the same proof inside
a browser Worker with production BrowserStore and its IndexedDB bridge. It does
not install a writer or test fixture in normal builds.

The client feature `export-ui-check` keeps the production registry and enables
only public fixtures and browser inspection. `export-check` includes that feature
and replaces the registry with its diagnostic writers. These build profiles are
separate so a vendor download test cannot pass with a diagnostic file.

The artificial full writer emits length-prefixed canonical CoreRecords. The text
writer exports only current password values and reports every lost field,
protection flag, tag and source context. The reused Format enum slot is only a
test identifier: these files are not CSV or another certified vendor export.

The shared scenarios check:

- Only the current signed head is exported. An older password and a removed
  field remain in source context but do not reappear as current fields. The full
  output matches the independently opened authenticated payload byte for byte,
  including unknown values, metadata and a 600,001-byte binary file.
- Record/issue pages retain positions and empty names, bound display labels,
  and reject invalid offsets. Chunk reads stay at or below 256 KiB and survive
  the actual Rust JSON codec shape; the assembled file matches its declared
  size. Generation invalidates the old review token; completion invalidates the
  artifact token.
- Default consent rejects losses before writing, keeps the review available for
  an explicit decision, and refuses blocked data even with loss acceptance.
  Writer failure returns no readable artifact. Text output contains the edited
  current password rather than deleted values from source context.
- Wrong tokens cannot cancel a valid review. Lock/unlock invalidates both review
  and artifact tokens. A new import, failed prepare and destination change
  discard the old session. The original vault snapshot stays unchanged.
- External head changes reject confirmation. All-record scope detects an added
  record; explicit selection permits changes to unselected records. Authenticated
  deletion events are excluded from all-record scope and cannot be selected
  explicitly.
- Cancellation in read/check/review, at writing, and at the asynchronous boundary
  after the writer returns releases the session and returns no artifact. The
  last case proves serialization actually ran before cancellation was observed.
  These hooks do not prove live UI cancellation or physical interruption/wiping.

Native-only checks corrupt a signature and associate a valid signed revision with
the wrong record ID. Both reject the entire preview; restoring the source permits
a fresh review. Another check performs a valid append through an independent
SQLite connection after serialization and proves that the final head check
discards the obsolete artifact.

The shared storage-failure scenario injects read failures during preparation and
before or after serialization, for all-record and explicit selection. SQLite uses
temporary table renames; the browser temporarily makes readonly IndexedDB
transaction creation throw. The failed session exposes no artifact; restoring
access permits a fresh export with an unchanged vault snapshot. These injections
do not simulate filesystem corruption or every IndexedDB transaction-abort cause.

## Commands

From the repository root:

```sh
cargo test -p confidex-app --test export_flow --test export
cargo test -p confidex-app --test export_flow --test export --features export-check
cargo test -p confidex --lib --features export-check
cargo build -p confidex --lib --release --target wasm32-unknown-unknown --features export-check
wasm-bindgen --target web --out-dir PATH_TO_BUNDLE --out-name app PATH_TO_TARGET/wasm32-unknown-unknown/release/confidex.wasm
node apps/confidex/web/export-check.mjs PATH_TO_CHROME PATH_TO_BUNDLE
```

For the production writer factories and both Bitwarden profiles, build the client with
`--features export-ui-check` instead of `export-check`. Generate its bindings into
a separate bundle, then run the same script with a final `production` argument.
That mode keeps the real catalog and checks current values, loss reports, group
memberships, attachment bytes, old artifact invalidation and the unchanged source
store. CSV factory checks call the shared Engine directly while its form remains
outside the catalog. A valid CSV Prepare request is still refused by the runtime.

The Fields checks read one current authenticated head, page field positions,
names, types and value-map keys, and verify that no values or attachment payloads
enter the reply. Native SQLite and BrowserStore use the same corpus, including
worst-case escaped metadata. Stale heads, malformed scope, cancellation and lock
cannot restore an old setup or review.

For the explicit 10,000-record workload, run:

```sh
cargo test -p confidex-app --release --test export_flow ten_thousand_current_records_use_real_storage_and_all_writer_factories -- --ignored --nocapture --test-threads=1
```

Alternatively, use the browser runner's `load` argument with a production bundle.
Seven real factories export the same
signed scalar records. Each output is read back with Confidex's own importer,
checking every title, username, password, URL and secure note. The report records
stage wall times and output sizes; the browser also reports linear-memory
high-water. See the [client instructions](../../../../apps/confidex/README.md#record-export)
for measurement scope. This is not independent consumer or file-save evidence.

## Large failure checks

`load_faults.rs` reuses the same signed 10,000-record seed and all seven genuine
factories. For each format it cancels halfway through authenticated reading,
during writing, after serialization, and after reading the first Ready chunk.
It injects storage read failures halfway through preparation and before/after
serialization, then locks a Ready artifact and unlocks the vault. Every failed
session rejects its old token; subsequent review/generation succeeds. Native
SQLite executes 56 cases. The browser also executes 14 review/Ready token
entropy failures and two crypto-writer entropy failures, for 72 cases.

Native storage injection uses temporary table renames; the Worker makes
readonly IndexedDB transaction creation fail. The small shared storage-failure
scenario also runs as the browser prelude. Web Crypto is replaced temporarily
only inside that isolated test Worker. Native OS entropy is not injected: the
core's native entropy unit tests separately check failed-source output clearing,
request limits and the real platform source. No production entropy hook is added.

The exact head set is checked during recovery. A bounded chained witness using
the core's framed SHA256 covers the lock, sync state, head IDs and all 10,002
known encrypted objects before and after the run, including the two original
historical revisions. One object is read at a time; backup limits are unchanged.
This proves stored data stability, not physical wiping or filesystem corruption
recovery. Cancellation is cooperative; it does not interrupt an Argon2 library
call. Ready chunks are read but no host save/download is requested here.

```sh
cargo test -p confidex-app --release --test export_flow ten_thousand_records_reject_cancellation_storage_failures_and_locked_artifacts -- --ignored --nocapture --test-threads=1
node apps/confidex/web/export-check.mjs PATH_TO_CHROME PRODUCTION_EXPORT_CHECK_BUNDLE faults
```

Use a genuine `export-ui-check` bundle. The browser checks every reported case,
main-thread heartbeat and the existing 256 MiB linear-memory bound. These runs
are failure checks, not performance measurements or a UI latency guarantee.

The rendered UI has a separate live-cancellation check using the same seed:

```sh
CONFIDEX_BITWARDEN_SOURCE=PATH_TO_PINNED_BITWARDEN_SOURCE node apps/confidex/web/export-ui-check.mjs PATH_TO_CHROME PRODUCTION_EXPORT_CHECK_BUNDLE PUBLIC_OUTPUT_DIRECTORY en-US load-cancel
```

At both desktop and narrow widths it clicks Cancel during authenticated reading
and during KDBX writing, then locks the vault during another KDBX write. A
test-only observer delegates messages to the actual Worker unchanged and records
operation/progress metadata, never field values, credentials or session tokens.
Each case requires a real cancel control and canceled reply, no Ready reply,
no download and no late restoration of the closed form. After unlocking, a fresh
review and explicit Save produce a Bitwarden JSON download; the pinned independent
reader checks all 10,000 current records and values. Screenshots and metadata
traces accompany the output. This checks the UI/onmessage path, not physical
wiping, native dialogs or cancellation latency bounds.

## File-host measurements

The rendered `load` runner also reports monotonic observed review, generation,
save and independent-reader times for each download. Save starts before clicking
the real Save control and ends when the completed filename can be read. It
includes chunk transfer, browser handoff, automation waits and the completion
probe; it is not a browser-only disk or encryption timing. Screenshots, consent
and reader work are outside that save interval. Generation includes both
serialization and encryption where applicable.

The native file host can separately save these independently checked public
downloads, without opening a GUI or dialog:

```sh
CONFIDEX_EXPORT_SAVE_FIXTURES=PUBLIC_OUTPUT_DIRECTORY/1320 cargo test -p confidex --lib export_files::tests::native_save_calibration_for_public_downloads -- --ignored --nocapture --test-threads=1
```

It checks exact output bytes, final Unix mode 0600, transfer closure and absence
of leftover temporary files for all six registered formats. The report separates
bounded Transfer assembly from the actual temporary-file write, sync and atomic
replacement. Input reads and post-save verification are outside those intervals.
Build first and run the test executable under `/usr/bin/time -l` for process RSS;
report the build profile. This is file-host evidence using existing public
artifacts, not another native end-to-end export or an OS-picker measurement.
Run native and browser calibration separately; neither establishes a latency SLA.

Use the repository's pinned wasm-bindgen version. The browser runner rejects
external fetches, checks main-thread heartbeat and enforces the existing 256 MiB
WASM linear-memory profile. Each case starts a fresh Worker in an isolated test
browser profile. None of these checks opens an OS keychain or a user's vault.

With `export-check`, the shared protocol scenario uses the top-level serialized
Command/Output dispatcher and its actual catalog/factory. It tests all five
optional credential combinations, unsupported-format invalidation, blocked data,
rows/issues, generation, chunk collection and final token invalidation. Credentials
are transported, not certified as working vendor encryption.

The native client library also tests the real NativeRuntime thread/queue on a
synthetic SQLite file, cancellation versus retry, independent cancel channels,
chunk output and lock invalidation. Its worker-codec checks include absent/empty
keyfiles, binary length validation, truncation, inline bytes and oversize rejection.
Browser `service` runs actual WorkerService plus that codec and JS cancel flags.
The production JS worker-queue check additionally sends byte packets with transfer
lists, cancels through the real onmessage control path, checks malformed-control
recovery and independent channels, collects binary chunks and rejects a token
after Lock. These checks are distinct from a rendered UI.

No export form, native picker, filesystem save, browser download, mobile gestures,
Safari/Firefox, physical phone or vendor reader is certified by this proof.
Those checks remain separate. The existing encrypted ZIP backup is not an
external export and its import integration regression remains separate.

## Captured-source reverse conversion

`reverse.rs` reuses the real [import integration cases](../import_integration/README.md)
and the pinned Bitwarden individual serializer
[capture](../import_fixtures/bitwarden_json/CAPTURE.md). Its fourteen sources are:

| Sources | Cases |
| --- | ---: |
| Captured Bitwarden individual JSON | 1 |
| Personal and organization Bitwarden JSON fixtures | 2 |
| 1PUX, KeePass XML, mapped CSV, Bitwarden ZIP, portable encrypted Bitwarden JSON | 5 |
| KDBX: password, keyfile, both, empty password, empty password with keyfile | 5 |
| Native signed record without import provenance | 1 |

Each imported case uses real review/apply and opens the authenticated stored
revision. Current edits change the title, field names/order, username, password,
note and TOTP seed/parameters; missing roles are explicitly added. Public notes
become secure notes. Extra source fields, old section layout and additional old
URLs are removed. A new later URL and four-byte attachment are added. Existing
field metadata and original provenance remain in the edited signed revision;
guards confirm that stale TOTP source text and applicable URI metadata are still
present. Native input is explicitly checked to have no import origin.
Section clearing uses the canonical version-1 empty group list, so legacy source
section hints cannot restore a deleted group title. The 1PUX output explicitly
checks that all resulting section titles are empty.

All seven genuine writer factories export each current head through shared
review, explicit loss consent, chunks and Finish: 98 actual outputs per platform.
The stored snapshot stays unchanged after every export.

The independent readers check actual output: pinned Bitwarden JSON/1PUX/Chromium
CSV mapping code, actual Bitwarden crypto/SDK for encrypted JSON, Python ZIP/CSV,
and KeePassXC CLI for KDBX/XML and attachment extraction. Current values and
TOTP parameters are checked; removed secrets and the old seed must not appear.
KeePass source URL protection stays set in the current record. XML/KDBX retain
that flag; 1PUX uses a concealed field. Bitwarden's native URI and notes slots and
CSV cannot retain those flags: their exact field-level protection-loss issues
must appear before consent. This check does not silently treat public output as
preserved protection.
The 1PUX consumer exposes the later section URL and TOTP as custom text fields;
its multiline concealed-note conversion also differs from native note semantics.
These limits do not change the source Record or the typed values in the archive.

Set the reader source paths described in the linked format coverage:
`CONFIDEX_BITWARDEN_SOURCE`, `CONFIDEX_ONEPASSWORD_READER_SOURCE`,
`CONFIDEX_CSV_READER_SOURCE`, `CONFIDEX_BITWARDEN_CRYPTO_SOURCE`,
`CONFIDEX_BITWARDEN_SDK`, and `CONFIDEX_KEEPASSXC_CLI`.
Use `CONFIDEX_READER_ESBUILD` if esbuild is outside PATH. Then run:

```sh
cargo test -p confidex-app --test export_flow captured_source_edits_reach_all_writers_and_independent_readers -- --ignored --nocapture
node apps/confidex/web/export-reverse-check.mjs --browser PATH_TO_CHROME PRODUCTION_EXPORT_CHECK_BUNDLE PUBLIC_OUTPUT_DIRECTORY
```

The browser uses an `export-ui-check` bundle with genuine factories and a real
Worker/BrowserStore. It prohibits external fetches and enforces the 256 MiB
linear-memory profile. Its output files contain only public test values. This is
an edited common-field corpus across the enumerated fixtures, not a claim that
every vendor version, field layout, profile, UI download or arbitrary Record is covered.
CSV remains outside the production form.

`apps/confidex/web/export-ui-check.mjs` also has a separate `load` mode. It reuses
the signed 10,000-record fixture and the ordinary UI driver for six registered
formats at desktop and narrow widths, including actual Save/download and
independent-reader checks. Its fault cases use the common JSON path. CSV remains
outside the form; other profiles/credential combinations have separate checks.
