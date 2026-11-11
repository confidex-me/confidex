# External export contract

This module reviews immutable current CoreRecords and produces a bounded file.
The writer boundary has no storage, UI, network or registry access. It is separate from
the signed encrypted ZIP backup. Vendor writers belong beside their existing
parsers in `import/formats/<format>`; do not add another crate or registry there.

## Writer boundary

1. The host authenticates the selected current revisions, admits each decode
   against `Records::memory().available()`, and moves full CoreRecords into
   `Records::push`. Editable Draft projections are not export input. Records
   become read-only during review and writing; no caller can change this snapshot
   after confirmation.
2. Construct one `Writer` with its format options. Keep passwords and keyfiles in
   cleared buffers owned by that writer. Do not change these options in `review`
   or `write`. The plan owns the same writer for both calls.
3. `prepare` calls `Writer::review` for every record. Inspect each field's name,
   order, full value, protection and extra metadata. Call `Review::preserved`
   for a representable field or `Review::issue` with its index for a concrete
   loss/blocker. Missing field coverage rejects the plan. Check all nonempty
   tags and Record.extra too, then acknowledge them with `tags` and `metadata`.
   These acknowledgements are a guard against accidental omissions, not proof
   that a vendor mapping preserves its semantics; each writer needs independent
   fixtures and reader checks.
4. Issues contain only record/field positions and typed codes. Never put field
   values, passwords or a raw source snapshot in a diagnostic or error. A field
   may have several issues, for example an unsupported TOTP parameter and a lost
   protection flag. Use `Blocked` when there is no safe output option; explicit
   acceptance cannot override it.
5. Present the complete report before calling `Plan::write`. `Consent::Lossless`
   is the default; any loss prevents writer execution. `AllowLosses` must follow
   explicit acceptance of this report. To exclude a record or change options,
   prepare another plan and show its report.
6. `Writer::write` reads these same current records and writes only to `Output`.
   It implements `Write` and `Seek` for text formats and ZIP container headers.
   Call `checkpoint` during record loops and bounded expensive work. Charge
   parser/writer/KDF scratch with `Output::reserve` before allocating it. Use
   cleared owners for plaintext scratch and serialized intermediate values.
7. Only a completed writer with a final successful cancellation checkpoint can
   return an `Artifact`. Writer errors, ignored output errors, limit violations
   and cancellation return no artifact. The file metadata declares whether the
   export is encrypted; the UI must warn about plaintext secrets before writing.

Current values and field presence are authoritative. Source context can explain
an unknown value or mapping, but must not restore a deleted field or old password.
Core epochs, signed revisions, lock keys and signatures are not vendor history.
Source references that a writer cannot resolve or represent need an explicit
report; they are not permission to replay old container bytes.

## Resource and lifetime boundaries

Defaults admit 10,000 records, 64 MiB of canonical snapshot content, a 64 MiB
output, 100,000 issues, and 192 MiB of shared logical memory. Callers can reduce
these limits. Snapshot record allocations use the same resident accounting as
import apply, including nested values and map overhead. Canonical encoding checks
core structure and decode budgets without keeping another full encoded snapshot.
The issue table and record headers are charged before allocation.

Output grows on demand in bounded allocations. Both old and new capacities stay
charged during a move; the old plaintext allocation is cleared before its charge
is released. Ordinary Vec growth is not used. A small file does not reserve the
whole output ceiling before a writer's KDF or other working phase. Snapshot,
report, output and writer scratch share the memory budget; the output cap is not
an additional independent 192 MiB allowance. A resource error can still occur
after preview, for example when scratch or a buffer move does not fit. It must
produce an error, not a partial file.
The memory counter is logical accounting, not a physical RSS guarantee.

Records, core encoding buffers and artifacts clear owned plaintext on drop.
Drop the plan/artifact on cancel or lock and reject stale host replies. A callback
is cooperative: it does not stop a foreign library in the middle of a bounded
operation or clear copies held by the OS/browser. Output checks cancellation on
write, seek and flush. Its cancellation I/O error is terminal for `write_all`;
`Interrupted` would cause that standard helper to retry forever.

This contract does not publish files. The host must still bind the plan and save
request to the open-vault generation, prevent stale publication, and perform an
explicit atomic native save or browser download. None of that can be inferred
from an artifact being generated. No production format is advertised by this
module until its writer and host integration are registered.

## Engine session adapter

`export_flow` connects this contract to an open Engine and a real Store. The host
can select all current records or explicit current heads. Heads are ordered by
record ID; entry order inside each Record stays unchanged. The adapter verifies
each signature, expected revision and record identity before opening the full
CoreRecord. All-record selection excludes authenticated deletion events; explicit
selection of a deleted record is rejected. The head index has a separate 100,000
entry bound, including deletions, while the active record limit remains 10,000.

The review token permits bounded record/issue pages of 64 entries. Labels contain
at most 128 characters; record and field positions still identify empty,
duplicate or truncated names. Pages expose no field values. Explicit consent is
checked before the writer runs. Rejected consent keeps the review available;
failed preparation or generation requires a fresh review.

The Engine compares selected heads before and after writing. All-record selection
also detects new or removed heads; explicit selection permits changes to other
records. A detected change discards the generated artifact. These are read-only
checks around an immutable snapshot, not a database transaction that prevents a
different process from changing the vault after the final check.

Successful generation replaces the review token with a new artifact token. The
host can read chunks of at most 256 KiB, then acknowledge completion with
`finish_export`. Chunk buffers own a memory charge and clear their byte storage
when its last owner drops. Lock, destination changes, a new import/export and
record-changing commands release the session. A failed new prepare cannot leave
an older valid review behind. Cancellation is checked again asynchronously after
the synchronous writer returns, before an artifact becomes readable.

The generated file is still not published. Host code must clear transferred
chunks on lock/cancel, reject stale generations, enforce its collection bound,
and report an actual save/download result. File save and its visible form are
separate from generation and transport.

## Runtime protocol and writer registration

`Command::VendorExport` and `Output::VendorExport` carry Begin, Prepare, Rows,
List, Fields, Issues, Generate, Chunk, Finish and Cancel. Begin returns the open
vault and available format labels. List reads one authenticated storage page for the record
selector, with 128-character titles and no field values or tags. It clears an
older review and accepts an operation ID for cancellation. Metadata is bounded
before IPC; the selector does not collect unbounded general-purpose summaries.
Fields reads one current authenticated record head and returns at most 16 source
bindings: field index, display name, type and value-map key, without values or
attachments. Each page owns its bounded memory charge. A changed head requires
a fresh selection; a Fields request invalidates an older review or artifact.
Prepare clears the old session before validating its
format/options or calling a factory. A factory error cannot preserve an older
confirmation. The factory must return a writer for the requested Format.

The factory has the signature
`fn(Format, Options, u64) -> Result<Box<dyn Writer>, Error>` at the
integration boundary. Their implementation stays beside the matching parser;
the integrator owns `export::catalog` and `export::writer`. No real writer is
advertised until registered and checked. The timestamp is Unix seconds. Normal
builds register plaintext and password-protected Bitwarden JSON, Bitwarden ZIP,
KeePass XML/KDBX and 1Password 1PUX. Both JSON variants have Personal and
Organization profiles; ZIP uses Personal only. The factory also accepts CSV
options, but CSV stays outside the catalog and the runtime Prepare command until
its form and translations are complete.
The opt-in `export-check` feature installs three explicitly labelled
synthetic writers for contract tests. The synthetic KDBX identifier exercises
credential transport and emits a plaintext diagnostic binary, not an encrypted
KDBX file. Never ship that test feature as a vendor export implementation.

Options are typed and cleared on drop:

- Plain for JSON, XML and ZIP formats that have no file credentials. Plain
  Bitwarden JSON selects the personal profile.
- Bitwarden with an explicit organization flag and an optional password.
  Personal uses one folder per record; organization uses collection memberships.
  Both profiles report unsupported data before writing and do not restore ACLs.
  Plaintext JSON requires an absent password; password-protected JSON requires a
  nonempty password of at most 65,536 UTF-8 bytes and rejects keyfiles.
- Password with optional password/keyfile components. None and Some(empty) stay
  distinct. KDBX passwords are bounded to 4096 UTF-8 bytes and keyfiles to 1 MiB.
  Portable encrypted JSON also accepts a password-only option for Personal.
  A writer still validates its actual crypto profile.
- Csv with a profile ID or explicit ordered columns, not both. A column selects
  title, tags, or a current field index with an expected type and value-map key.
  A writer must check the type/index/key on every record and report missing or
  ambiguous mappings. Headers can be empty/repeated and are not normalized.
  Delimiter/count/string/aggregate-option bounds apply before a factory runs.
  Profile support, cell semantics and protection loss remain writer decisions.

List, Fields, Prepare and Generate use nonzero operation IDs. The UI must not
reuse these IDs within one runtime lifetime. Native and browser runtimes have separate import
and export cancel flags and throttle progress independently of cancellation.
Browser async checkpoints drain pending cancellation around synchronous work.

The worker codec moves keyfiles and file chunks in binary attachments. Its JSON
header declares the attachment length; truncated/extended bodies, inline bytes,
oversized keyfiles/chunks and unexpected attachments are rejected. Legacy bare
JSON without an attachment remains readable, but binary frames require a length.
UI and Worker bundles must use the same internal codec version. A malformed raw
Worker request clears an existing export session before returning an error.
The production JS queue accepts only typed byte packets and the two cancel
control messages; a malformed control message does not poison subsequent work.

## File publication and shared form

The shared form selects all records or explicit current heads. It collects every
issue page before enabling confirmation. Loss acceptance starts unchecked;
blockers cannot be overridden. A plaintext file needs a separate acknowledgement.
Changing records or format starts a fresh review. Credentials stay masked and
are moved into the prepared writer; they are not preferences.

After generation, `export_flow::Transfer` allocates at most the declared 64 MiB
file ceiling. It requires exact chunk offsets, lengths and continuations. A gap,
truncation, extension or malformed continuation closes the transfer. The worker
artifact is released after the final chunk, before the Save action is enabled.
This bounded host buffer is separate from the worker's logical memory counter;
both may coexist during collection. It is not an additional unbounded cache.

`Runtime::save_export` publishes only on the explicit Save action. Native hosts
open the OS picker off the UI thread, keep one cleared <=256 KiB write chunk,
write a private temporary file in the destination directory, sync its contents,
and atomically rename it. I/O errors remove the temporary file. Cancellation
before publication preserves the destination. The cancellation flag does not
wait for blocked disk I/O; a chunk already in an OS write remains owned by that
bounded operation until it returns. No physical erasure guarantee is implied.

The transfer serializes its final publication claim against cancellation. After
the host claims a rename or browser click, that operation cannot be retracted.
The browser clears its mutable staging bytes and revokes the Blob URL; a failed
handoff revokes it immediately. A successful click reports DownloadStarted,
not a completed browser save. The OS/browser can retain copies of a published
file. Closing or locking cannot remove those files.

The UI cancels transferred buffers, invalidates file-picker/save callbacks on
close or lock, and retains increasing operation IDs across window reopenings.
Automatic sync and record editing pause while the export window is open. Native,
floating browser and phone layouts use the existing window and Form components.
The six registered formats use this same form. Bitwarden profile
selection uses explicit typed options; Personal folders and Organization
collections use the same selected profile during review and writing. The
diagnostic catalog is opt-in. CSV-specific configuration belongs with its writer
integration and must be added before that format is advertised.

## Checked format profiles

These are the written profiles and executed independent-reader boundaries.
The linked coverage records the exact source pins, hashes, fixtures and commands.
Source-reader checks do not certify an installed vendor application's import UI.
Unsupported data still requires the writer's loss report; no row promises a
lossless conversion of an arbitrary Record.

| Format | Written profile | Independent checks and material limits |
| --- | --- | --- |
| [Bitwarden JSON](../../tests/export_fixtures/bitwarden_json/COVERAGE.md) | Plaintext Personal or Organization | Pinned Bitwarden importer, models and cleanup read actual output. Empty/repeated/hidden custom fields, current credentials, multiple URIs, card/identity bindings and TOTP are covered. Attachments are a loss; Personal retains one tag as a folder; ACLs do not transfer. |
| [Password-protected Bitwarden JSON](../../tests/export_fixtures/bitwarden_encrypted/COVERAGE.md) | Portable Personal or Organization; Argon2id v19, 64 MiB, three passes, four lanes; authenticated type-2 EncStrings | Actual pinned Bitwarden crypto services and SDK decrypt output before the JSON reader checks it. Wrong/altered passwords and ciphertext are rejected. Same representation limits as plaintext JSON; no account-restricted exports or attachments. |
| [Bitwarden ZIP](../../tests/export_fixtures/bitwarden_zip/COVERAGE.md) | Individual Personal archive with `data.json` and named attachment paths | Python's ZIP reader checks framing, CRC, unique paths and exact file bytes; the pinned JSON reader checks `data.json`. Ambiguous attachment ownership is blocked. This does not automate attachment upload into Bitwarden or prove completeness of a source vault's downloads. |
| [KeePass XML](../../tests/export_fixtures/keepass_xml/COVERAGE.md) | Plaintext KeePass 2 XML with a binary pool | KeePassXC 2.8.0 CLI imports actual output and checks values, protection flags and attachment bytes. The consumer sorts String keys, normalizes unprotected CR, and omits pool bytes in a subsequent XML export. Duplicate keys and unsafe placeholders are blocked. |
| [KDBX](../import/formats/kdbx/README.md#encrypted-writer) | KDBX 4.1, AES256, Argon2id v19, 64 MiB, three passes, one lane; ChaCha20 inner protection; no compression | KeePassXC 2.8.0 CLI reads password/keyfile variants, current values, TOTP and exact attachments, including protected pool bytes after a save. Wrong credentials and MAC changes fail. KeePass field-name/order losses and duplicate-key blocks still apply. |
| [1Password 1PUX](../../tests/export_fixtures/onepassword_1pux/COVERAGE.md) | Version 3 stored ZIP with scoped document bindings | Python's ZIP reader checks exact file payloads; the pinned Bitwarden 1PUX mapper checks login values, multiple URLs and short concealed fields. That consumer skips empty values/files, converts multiline concealed fields to notes, and exposes generated-ID TOTP and later section URLs as text custom fields. Import into an installed 1Password app is not certified. |
| [CSV](../../tests/export_fixtures/csv/COVERAGE.md) | Explicit positional mapping or Chromium, Firefox and Apple Passwords headers | Python's CSV reader checks framing; pinned Bitwarden CSV consumers use actual PapaParse and hostname helpers. Consumer line-ending normalization and Firefox title/source-column limits are explicit. CSV cannot carry arbitrary protection flags, files or a self-describing mapping. Writer checks do not enable its unfinished form. |

## Checks

`cargo test -p confidex-app --test export` uses artificial supported, lossy,
blocked and failing writers. It checks current values versus stale source data,
consent before writing, coverage omissions, cancellation, ignored output errors,
seekable headers/gaps, snapshot limits, and reservation release on every path.
The small module unit check rejects unsafe output names and header controls.
The same integration suite can run with the existing WASI runner:

```sh
CARGO_TARGET_WASM32_WASIP1_RUNNER="node $PWD/crates/confidex-app/tests/run-wasi.mjs" cargo test -p confidex-app --test export --target wasm32-wasip1 -- --test-threads=1
```

These checks do not certify a vendor file, native picker, browser download,
lock/session transport or UI layout. Those gates belong to the host integration
and each format's compatibility tests.

The separate [Engine session proof](../../tests/export_flow/README.md) runs the
same real-Store scenarios on SQLite and production BrowserStore/IndexedDB.

`cargo test -p confidex-app --test export_transfer` checks bounded host collection,
cancellation between chunks and the final publication claim. The same target
runs under WASI (the two native thread-race checks are excluded there). Native
file-host tests cover replacement, cancellation, I/O failure and temporary-file
cleanup. `node apps/confidex/web/export.test.mjs` checks Blob URL cleanup on
success and failed DOM handoff.

The opt-in `apps/confidex/web/export-ui-check.mjs` drives the actual browser UI,
worker and IndexedDB at wide and phone widths. It uses only public synthetic
records. Its default diagnostic mode checks subset selection, plaintext/loss
consent, non-overridable blockers, credential masking, failed download handoff,
Save-only publication and lock invalidation. The `production` mode checks real
Bitwarden profile downloads with the pinned independent JSON importer. The
`kdbx` mode retains the real KDBX credential/download regression. The
`bitwarden-encrypted`, `bitwarden-zip`, `keepass-xml` and `onepassword-1pux` modes
also drive their real shared forms and read the downloaded bytes independently.
These checks do not replace each format's full compatibility matrix or a manual
OS-picker check.

The separate `load` mode of `apps/confidex/web/export-check.mjs` and the ignored
native 10,000-record test exercise all seven factories with real authenticated
storage. They check every output with Confidex's own importer, not an independent
reader. The [client instructions](../../../../apps/confidex/README.md#record-export)
describe timings, memory scope and reproduction. This workload does not certify
UI selection/save, large attachments or every failure mode at that scale.

The `load` mode of `apps/confidex/web/export-ui-check.mjs` separately drives the
six registered formats at desktop and narrow widths using that same corpus.
It filters the paginated record selector, reads issue pages, requires explicit
consent and Save, and verifies 10,000 records in each real download with the
independent readers above. This workload uses Personal for both JSON variants
and a password for KDBX. Its common cancellation, failed handoff and lock cases
must publish no extra file. It does not cover CSV's unfinished form, native
picker interaction or a physical phone.
