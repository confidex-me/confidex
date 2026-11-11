# Import storage integration checks

All inputs are the repository's public synthetic fixtures. This is an actual
Engine/Store check, not a UI mock. The same Rust proof runs against native SQLite
and the production BrowserStore/IndexedDB bridge in a browser Worker.

| Input | Source items | Created records | Explicitly skipped |
| --- | ---: | ---: | ---: |
| Bitwarden personal JSON | 3 | 3 | 0 |
| Bitwarden organization JSON | 1 | 1 | 0 |
| 1Password 1PUX | 4 | 3 | 1 archived |
| KeePass 2 XML | 3 | 1 | 1 unresolved reference, 1 recycle item |
| Generic CSV with explicit mapping | 2 | 2 | 0 |
| Bitwarden ZIP | 3 | 3 | 0 |
| Password-protected Bitwarden JSON, PBKDF2 5,000 | 3 | 3 | 0 |
| KDBX, five credential modes | 3 each | 1 each | 1 unresolved reference, 1 recycle item per file |

Each case uses the published bounded parser contract and its existing fixture;
there is no production registry or adapter change. The parser-specific tests and
producer evidence still determine which source versions and fields are supported.
These cases do not certify additional vendor versions or other encryption profiles.
The encrypted adapter's own tests cover its broader KDF matrix separately.

Format-specific support and producer evidence remain explicit:

| Format | Checked profile and boundary | Details |
| --- | --- | --- |
| Bitwarden JSON | Personal and organization plaintext JSON; hidden and unknown data retain protection | [Field contract](../import_fixtures/README.md) |
| 1Password 1PUX | Version 3, documented and published-reader attachment layouts; no fresh vendor capture claim | [Adapter coverage](../import_fixtures/onepassword_1pux/ADAPTER.md) |
| KeePass XML | Bounded UTF-8 KeePass 2 XML; inner-stream ciphertext requires KDBX instead | [XML coverage](../import_fixtures/keepass_xml/COVERAGE.md) |
| CSV | Explicit positional mapping and documented Chromium, Firefox and Apple Passwords profiles | [CSV evidence](../import_fixtures/csv/COVERAGE.md) |
| Bitwarden ZIP | Individual plaintext data.json plus attachments; original download completeness cannot be proven | [ZIP coverage](../import_fixtures/bitwarden_zip/COVERAGE.md) |
| Encrypted Bitwarden JSON | Portable password-protected PBKDF2/Argon2 profiles; account-restricted exports are refused | [Encrypted coverage](../import_fixtures/bitwarden_encrypted_json/COVERAGE.md) |
| KDBX | Enumerated 3.1/4.0/4.1 cipher/KDF/keyfile combinations; hardware-bound keys are unsupported | [KDBX matrix](../../src/import/formats/kdbx/README.md) |

A second scenario uses the production registry and the top-level
`Command::VendorImport` dispatcher, not an injected parser. Requests and responses
pass through the actual Rust JSON codec in cleared byte buffers. It covers every
currently registered format: both Bitwarden JSON fixtures, 1PUX, KeePass XML,
CSV, Bitwarden ZIP, portable encrypted JSON and KDBX. Its twelve fixtures cover
all seven registered formats, including all five KDBX credential modes. A coverage
guard requires a shared fixture for every registry entry.

This scenario checks Begin's destination/format list, Prepare with misleading
filenames, rejection of a conflicting explicit format, and invalidation of the
previous valid token on that rejection. PasswordRequired, incorrect-password
retry, successful Unlock and rejection of the old credential token use the same
messages as the host. Cancel releases the preview without changing the complete
snapshot. Rows and Preview match the independent parser Plan's metadata, field
counts, tags and warnings. Preview fields also match the real stored Open result,
including opaque retention. Apply's report, signed payload, full provenance and
search use the existing verification proof. A fresh Engine/SQLite file reopen
then reimports a renamed file through the same registry, requires Duplicate for
every accepted item and verifies that explicit Skip preserves the exact snapshot.

CSV uses the real CsvRequired → ConfigureCsv → PreviewCsv messages. Prepare has
no injected mapping. Before header consent, setup returns only the column count,
empty names and private roles. Configure preserves the source token and keeps
roles private; the explicit fixture mapping then creates a distinct review token.
A second Configure invalidates all old Rows/Preview/Candidates/Apply requests.
Re-preview creates another review token while retaining the same source token.
The resulting Plan, Preview, stored records and renamed-file repeat use the same
independent canonical/provenance/search checks as the other formats.

KDBX uses KdbxRequired → UnlockKdbx → Reviewed. Prepare must request credentials
even when Options already contains an explicit empty password or a keyfile. A
wrong database password fails authentication and permits a correct retry. Correct
credentials retain their optional components, including None versus Some("").
The consumed credential token cannot unlock again. Each mode then uses the full
Rows/Preview/Apply/canonical payload/search/file-reopen/renamed-duplicate proof.

The codec check is Rust-to-Rust JSON, not a JavaScript structured-clone or UI
transport test. It uses Quiet control and does not prove event-driven Worker
cancellation or render progress controls. The browser repeats this same protocol
proof against production BrowserStore/IndexedDB.

A session-isolation scenario starts with two nonempty synthetic vaults. Locking
rejects old Rows, Preview, Candidates and Apply tokens, including after the same
vault is unlocked again. Pending Bitwarden and KDBX credential tokens cannot
survive Cancel, Lock or a subsequent unlock. Creating another destination
invalidates a pending Bitwarden token; switching destinations also invalidates a
pending KDBX token. Switching from a reviewed second vault to the first invalidates
that review too. Both
complete snapshots, original signed objects and searchable sentinel records stay
unchanged; fresh preview/cancel and fresh Engines can still open either vault.
These are sequential top-level commands, not a test of interrupting an in-flight
operation or of physical memory erasure.

The input-rejection scenario starts with a signed searchable sentinel in a
nonempty vault. A valid preview precedes each truncated JSON, over-depth JSON,
unknown JSON shape, unsupported text encoding and record whose fields exceed
the editable-text budget. Each typed rejection invalidates the previous
Rows/Preview/Candidates/Apply token and preserves the entire original snapshot
and search results. A fresh valid Prepare/Apply then adds all three expected
records, preserves the original head and wire, and passes independent payload,
provenance and private-search checks. Fresh Engines and a native SQLite file
reopen repeat those checks. A sixth case supplies exactly MAX_FILE_BYTES + 1
(currently 64 MiB + 1) to the actual top-level dispatcher and checks the same
invariants. Only this large request skips the Rust JSON roundtrip to avoid
byte-array expansion in the test. It checks raw Rust input admission, not a
64 MiB file passing through JavaScript transport.

The proof checks:

- Preview creates no objects. Unacknowledged item/container review, attempted
  creation of blocked/excluded items, and cancellation at the precommit checkpoint
  leave both heads and objects empty. Each failed session requires a new preview.
- Explicit Create/Skip choices produce the expected report and count. Opening
  each signed envelope verifies its Record ID and the locally chosen epoch;
  source dates do not become local revision history.
- Every stored canonical Record matches its parser Plan, including ordered mixed
  fields, empty values, binary attachments and protection. Source scope/locator
  and item attributes match exactly inside encrypted provenance. Shared container
  attributes have one carrier; every reference resolves to that carrier's actual
  immutable record/revision and matching digest.
- Public title search returns the stored record. Passwords, guarded/hidden values,
  secure notes, TOTP material, usernames and source-only scope stay outside search.
  Known password/scope markers do not appear in the stored wire bytes.
- A new Engine and Store wrapper reopen the vault. SQLite also closes and reopens
  the database file. An own encrypted ZIP backup is exported and identified as
  `OwnBackup`, outside the vendor-import flow. Inspection invalidates a pending
  vendor preview. Restore refuses to replace an existing vault without changing
  any stored data; a wrong password creates no vault. Successful recovery preserves
  exact lock/wire bytes, heads and tag indexes, with sync unconfigured. Every
  decrypted payload is then checked again. All accepted items become duplicates;
  explicit Skip preserves the exact existing heads and search results.

The Plan is the oracle for preservation through Apply. Independent source-value
checks remain in each adapter's golden/producer tests; this proof does not replace
them. Source locators are used only to compare test results, never as record IDs.

The edit scenario changes the first login's password through the real Open/Save
commands. It compares the complete decrypted Record with an independently edited
original, so a password edit cannot discard unrelated fields, binary data or
unknown metadata. For the 1PUX fixture, first Save also materializes its imported
Security section as explicit encrypted layout metadata. The proof independently
expects that exact name and span (five fields starting at position five), while
retaining the source section hints and all other bytes. An unchanged source then
reports a local conflict. A modified
fixture changes only the source password; scoped IDs report both source and local
changes. Missing IDs, including CSV, produce a new item despite the same title and
refuse an Update of the existing record. Unreviewed updates and explicit Skip
leave storage unchanged. An acknowledged scoped Update or weak-source Copy
preserves other heads and every old wire object. New signed epochs deliberately
decrease; conflict decisions do not depend on clocks. The resulting linear history
also passes the own encrypted backup/restore cycle and duplicate detection.

Source mutations operate only on these trusted fixtures. JSON strings are replaced
at validated borrowed spans, and ZIP members are retained while that JSON member
is repacked. XML/CSV password slots follow the fixed fixture layout. These helpers
are test mutations, not reverse-export writers. The table counts initial imports;
the explicit CSV Copy adds one further record during the edit scenario.

The encrypted case uses the published portable PBKDF2 fixture and its public
Unicode/space-sensitive export password. Missing, incorrect and trimmed passwords
cannot reuse a previous valid preview or change the vault. No export password is
present in the authenticated decrypted Records, including provenance. The modified
source is a second authenticated capture made by the same pinned Bitwarden
exporter/SDK, with only the first login password changed in its plaintext. Its
Records, source fields/attributes, statuses and diagnostics are also compared with
the independent modified plaintext JSON path. It then runs the same local/source
edit, explicit conflict decision, history and backup checks as all other cases.

`capture-encrypted.mjs` reuses the existing capture harness, selecting only its
PBKDF2 5,000 profile; it adds no cryptography or reverse-export implementation.
Pinned sources, SDK identity, plaintext and captured-file digests are recorded in
`fixtures/encrypted/capture-sources.json`. To verify the checked-in capture, use
the source files and SDK installation described by the encrypted adapter's
fixture coverage document:

```sh
TMPDIR=/path/to/scratch node crates/confidex-app/tests/import_integration/capture-encrypted.mjs SOURCE_DIRECTORY SDK_DIRECTORY
```

Add `--write` only to regenerate this synthetic fixture with new salt/IVs. The
generator operates in its own temporary tree and never rewrites the adapter's
fixtures. It verifies the original capture set and the edited ciphertext with the
actual pinned SDK. This is a producer-code capture, not an installed vendor UI run.

A separate destination-concurrency scenario reviews a Bitwarden batch, then
commits an independent record at the import's precommit checkpoint. Native SQLite
uses a second process with its own connection to the ordinary database path;
credentials travel through a cleared pipe buffer, not arguments or environment
variables. The browser uses a second Engine/BrowserStore and a separate IndexedDB
transaction. The stale import fails with Conflict and publishes no imported
objects. The independent record remains intact. A fresh preview and retry preserve
it, create the complete batch, verify every imported payload and detect duplicates.
This is a deterministic conflicting write, not a sustained concurrency benchmark.

Storage-failure checks keep a previously saved signed record and import a public
Bitwarden fixture with a 64 KiB counter string in its first password. After failure,
the complete snapshot and existing search result must match; the failed preview
cannot be reused. A fresh Engine and explicit retry verify every canonical payload,
source attributes, public search and private-value exclusion, then detect duplicates.

- Native uses a disposable SQLite database with a
  [page-count ceiling](https://www.sqlite.org/pragma.html#pragma_max_page_count).
  A controller on the test-only shared pager sets the ceiling to the current page
  count with no free pages and independently confirms `SQLITE_FULL`. The real
  SqliteStore Apply returns Storage, rolls back, and preserves every previous byte.
  After closing both connections and restoring the ceiling, a normal file-path
  reopen/retry succeeds. The saved wire exceeds one page, the database grows beyond
  the old ceiling and `integrity_check` returns `ok`. This tests actual database
  capacity failure without filling the host disk; shared cache is not enabled in
  the ordinary independent-process concurrency test or production configuration.
- Browser first throws `QuotaExceededError` at the second actual object insertion
  in the unchanged production IndexedDB transaction. Its counter proves the first
  insertion was reached, and snapshot equality proves transaction rollback. It then
  repeats failure/retry with Chromium's actual origin quota overridden to one byte,
  without replacing IndexedDB methods. The launcher verifies the override, waits
  35 seconds for Chromium's cached free-space result to expire, and clears the
  override before retry, including cleanup after a failed assertion. That fixed wait
  is part of the reported elapsed time; this run is not an import-speed benchmark.

Index recovery uses a separate three-record Bitwarden import. The test changes one
wire byte of its last head directly in the disposable SQLite/IndexedDB database;
the production reader and signature checks remain unchanged. A fresh Engine is
unlocked before corruption, so the failure occurs in search rather than the initial
record listing. Two consecutive rebuild attempts must fail with Integrity,
returning no partial Rows.
Restoring the exact original ciphertext lets that same Engine rebuild and return
all records. Full snapshot, canonical payload, provenance, private search exclusion
and duplicate checks pass again, followed by a fresh Engine/SQLite file reopen and
the encrypted backup/restore regression. This is an authenticated-object read
failure during a small rebuild, not a simulated FTS allocation failure or a
multi-chunk stress check.

## Run

```sh
cargo test --release -p confidex-app --test import_integration -- --nocapture
node crates/confidex-app/tests/import_integration/browser.mjs /path/to/chrome
```

Use release mode for this suite's repeated password derivations and backup cycles.
Use the installed Rust `wasm32-unknown-unknown` target and matching wasm-bindgen
0.2.130. CONFIDEX_TEST_CARGO/CONFIDEX_TEST_BINDGEN and CARGO_TARGET_DIR may locate
those existing tools and keep builds separate from other worktrees. The browser
launcher creates a temporary probe crate and copies the unchanged storage bridge.
It blocks external fetches, links a 256 MiB WASM maximum, measures retained linear
memory and records page heartbeats while the Worker runs. It removes only its own
synthetic vaults/profile. Native tests never access an operating-system keychain.

## KDBX storage proof

The default browser check includes KDBX in both its direct parser/Store loop and
its production registry loop. The separate `--kdbx` mode runs only the direct KDBX
adapter through the same Engine and BrowserStore proof; native has dedicated
SQLite tests for these cases. Its five independently captured files use password,
keyfile, both, an explicit empty password, or an explicit empty password with a
keyfile. Optional credentials retain presence: `None` and `Some("")` differ.
Each file has three source items; one is accepted, one has an unresolved reference
and one is excluded as trash. Denial and precommit cancellation checks precede the
successful atomic Apply.

Verification covers complete canonical fields, binary attachments, encrypted
source attributes/container references, protection, public/private search,
native file reopen, exact own-ZIP restore and duplicate Skip. The decrypted
records must not contain the nonempty source-database password or raw keyfile bytes.

The same browser mode also runs the existing source/local edit scenario for all
five credential modes. Real [KeePassXC source-edit captures](fixtures/kdbx/README.md)
change the source password. Local Save creates another signed revision; the
candidate must report both changes. Unacknowledged Update fails without writes,
Skip preserves the local snapshot, and explicit Update preserves old signed
history, attachments and unrelated fields. A subsequent repeat and own-ZIP
restore remain duplicates. Password markers never enter the search index.

The direct proof uses the real parser with explicit Options; registry dispatch
is checked separately in the default mode. Neither mode draws a credential dialog
or proves user-message cancellation during its KDF. Cipher/version
coverage remains documented by the [adapter](../../src/import/formats/kdbx/README.md).

```sh
cargo test --release -p confidex-app --test import_integration kdbx_credential_modes_apply_reopen_backup_and_repeat_in_real_sqlite -- --exact --nocapture
cargo test --release -p confidex-app --test import_integration kdbx_local_and_source_changes_require_explicit_decisions_in_real_sqlite -- --exact --nocapture
node crates/confidex-app/tests/import_integration/browser.mjs /path/to/chrome --kdbx
```

Both browser modes have a 30-minute test watchdog. The proof decrypts each of
five sources repeatedly for initial import, repetition and source edits; the
registry loop additionally checks wrong-credential retries. The AES fixtures
have taken up to 15 seconds per open on the shared calibration host. The watchdog
leaves room for repeated opens and backup cycles. It is not a product KDF limit
or a latency guarantee. Both modes retain the 256 MiB WASM memory cap.

## Remaining coverage

This probe draws no import UI. Registry selection is checked through the messages
above; the direct parser/Store loop checks the same twelve fixtures independently.
The precommit cancellation is a deterministic library callback,
not a user message interrupting a parser. Page heartbeats do not prove responsive
progress/cancel controls inside the Worker. Actual UI screenshots, event-driven
cancellation and registry wiring require the production host checks.

Existing `tests/import_apply.rs` and `apps/confidex/web/import-check.mjs` exercise
storage/concurrency, quota rollback, lock/cancel and index recovery independently.
They remain necessary; this matrix does not claim every such fault for every
source. Full 10000-record load checks are in `tests/import_csv/` and its fixture
coverage document. Common stage timing, full browser process memory, expanded
failure coverage remain separate requirements. The quota/capacity scenarios above
use Bitwarden personal JSON, not every adapter. They do not simulate an FTS
allocation failure or a full physical filesystem. The backup check exercises the
library commands and linear edit history; it does not save a file through the UI
or test historical forks.
