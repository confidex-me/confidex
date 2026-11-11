# Individual Bitwarden ZIP import

Profile: the pinned producer in [CAPTURE.md](CAPTURE.md), with root `data.json`
and `attachments/<sanitized item name>/<archived filename>`. Parsing is local
and uses the shared bounded archive reader and Bitwarden JSON mapper.

| Data or condition | Result |
| --- | --- |
| JSON fields, groups, protection and unsupported source data | Same semantics as plain Bitwarden JSON |
| Unique attachment owner | Append `file/v1`, exact bytes, archived filename and encrypted source path |
| Unicode, empty files, equal names in different records | Preserved |
| Images | Preserve as files; no automatic decoding, conversion or size reduction |
| Duplicate item name or sanitization/suffix collision | Container Blocked / UnresolvedFieldReference; no guessed assignment |
| Unknown owner or extra/nested layout | Container Blocked; unresolved paths retained in container attributes |
| Empty item attachment folder | Item Blocked / MissingAttachment |
| Partially failed source downloads | Not detectable; every ZIP requires independent container Review |
| Original filenames before producer sanitization | Not recoverable; preserve the name actually present in the archive |
| Organization ZIP, encrypted JSON, missing data.json | UnsupportedFormat |
| Corruption, unsafe/duplicate paths, unsupported compression, bombs | Shared archive validation rejects input |
| Record over the compressed 4,000,000-byte core cap | Limit error; files are not removed or transformed |

Shared metadata includes `bitwarden.zip.profile`,
`bitwarden.zip.attachment-inventory-verified=false`, and, when applicable,
`bitwarden.zip.unresolved`. Container Blocked cannot be bypassed by deselecting
items. Container Review requires its own acknowledgement.

The ZIP cannot prove completeness of the original vault's attachments: the
producer returns its skipped-download count separately. An archive with some
successful downloads can omit others without a reference. The importer does
not present these files as a verified complete migration.

## Evidence

- Twelve parser tests pass on macOS native and wasm32-wasip1 (Node WASI).
  They compare all mapped JSON fields and every binary byte with the pinned
  producer output, and cover collisions, missing/orphan files, malformed JSON,
  CRC/truncation/paths, deflate, budgets, cancellation and whole-record overflow.
- A native SQLite test exercises Engine preview, independent acknowledgement,
  sealed persistence, exact decrypted canonical records, reopen, search,
  duplicate skip and rejection of globally blocked plans.
- A real Chrome dedicated Worker uses the application's BrowserStore and
  IndexedDB bridge with a 256 MiB WASM maximum memory. The probe verifies preview,
  three sealed records, exact decrypted records including files, a new Engine
  after lock, duplicate skip, and collision/orphan refusal. The main thread
  heartbeat advances. It removes its synthetic vault afterward.
- Strict native Clippy and the browser target compile check pass.

Run parser and native app tests from the repository root:

```
cargo test --locked -p confidex-app --test import_bitwarden_zip
cargo clippy --locked -p confidex-app --test import_bitwarden_zip -- -D warnings
```

For the browser probe, install wasm32-unknown-unknown for the chosen Rust
toolchain and wasm-bindgen-cli 0.2.130. `browser.mjs` builds a temporary probe
crate from the real app/core/BrowserStore, without changing their sources or
workspace manifests. It uses the workspace lockfile and cached dependencies.
Set `CONFIDEX_TEST_CARGO`, `RUSTC` and `CONFIDEX_TEST_BINDGEN` if the selected tools
are not on PATH. An optional `CARGO_TARGET_DIR` reuses build output.

```
node crates/confidex-app/tests/import_bitwarden_zip/browser.mjs CHROME_EXECUTABLE
```

The test probe is not included in production binaries. Shared
[UI and registry checks](../../../../../apps/confidex/README.md) and
[whole-pipeline storage checks](../../import_integration/README.md) run separately.
[Stage measurements](../../import_csv/performance/README.md) cover the common
10,000-record workload. No account-based Bitwarden UI/CLI export or
Safari/Firefox/Linux/Windows runtime compatibility is claimed here.
