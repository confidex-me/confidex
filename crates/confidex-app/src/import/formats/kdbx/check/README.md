# KDBX native and browser calibration

This test-only runner builds the real `confidex-app` library from its source path.
A temporary manifest adds the reviewed `keepass` dependency if it is not yet
registered in the app manifest. It does not replace
application types, change the production manifest or register an adapter. Nothing
in this directory is included by a normal application build.

On macOS with the WASM target, Node, Chrome and the pinned wasm-bindgen CLI:

```
node crates/confidex-app/src/import/formats/kdbx/check/run.mjs
```

Set `CARGO`, `RUSTC`, `CARGO_TARGET_DIR`, `WASM_BINDGEN` and `CHROME` when the tools
are not on PATH. Match the Rust compiler for native and WASM. The runner uses
`probe.lock` and leaves source, encrypted inputs, build products and `result.json`
in a permanent sibling directory. To update the dependency lock explicitly, use
`node .../check/run.mjs --lock`. Do not share a Cargo target directory between
different Rust/Clippy compiler versions.

The twenty-one cases cover actual KDBX 3.1 and 4.0 files, five independently checked
4.1 variants, a generated 10k workload, wrong credentials, early and late cancel,
an excessive KDF request, and explicit empty/absent credential cases.
The workload has six current fields per entry,
three protected fields, ten equal attachments, Argon2id 64 MiB/3 passes/1 lane and
KDBX 4.1. Generation is outside measurements and uses the library's save feature
only in the separate producer binary. Read builds use `default-features=false`.

Native and Chrome run the same bytes. Counts, errors, shared-budget release and
a fingerprint of every Record, source metadata, source ID, status, diagnostic and
container are compared. The probe does not apply a plan or write a destination
vault. For independent producer verification:

```
python3 crates/confidex-app/src/import/formats/kdbx/check/verify.py KEEPASSXC_CLI WORK/public-10k.kdbx
```

This checks 10k entries, all six field values, protection flags and two exact
attachment exports. It keeps public plaintext XML in memory, not in a file.

## Memory and time scope

The allocator observes all Rust-owned allocations in the input/decode/map/validate/
Plan path. `rust_peak` treats realloc replacement as atomic; `realloc_upper_bound`
also allows simultaneous old and new blocks. Neither includes allocator metadata,
stack, code, V8 or OS buffers. Input capacity is included. A small alloc/realloc/dealloc self-check verifies both counters before each measured case. `rust_after_drop=0`
means the measured allocations returned to their baseline, excluding the retained
public result fingerprint. It is not a physical erasure test.

`elapsed_ms` covers preparation and the result fingerprint. It excludes reading
the file, Worker initialization and cleanup. Each native case also reports macOS
process maximum RSS. Chrome's `linear` is the WASM memory high-water size. Its
separate JS source buffer size is reported as `jsInput`.

The runner samples the test Chrome process tree every 100 ms. `baselineRss` and
`peakRss` sum RSS across those processes: shared pages can be counted more than
once and short peaks can be missed. This is not unique physical memory. It is
the minimal Worker harness, not the full application UI or storage/apply path.

## Cancellation

The shared `tools/browser-run.mjs` helper supplies COOP/COEP headers only
for this isolated test and provides the exact Chrome PID for RSS sampling.
The runner asserts cross-origin isolation.
A `SharedArrayBuffer` flag reaches synchronous Rust checkpoints without waiting
for the Worker's message queue. Cancel is requested after at least 100 checkpoints
inside the long AES-KDF case. The result must be `Canceled`, release the budget
and return Rust allocations to baseline. The main page continues to run.

A separate test terminates a disposable Worker during the 10k workload and checks
that no late result arrives. Termination skips Rust destructors; that test proves
discard and responsiveness, not buffer wiping. Neither mechanism is wired into
production by this runner. This isolated harness does not verify the host's
credential presence, cancellation transport or stale-result handling. The separate
UI runner below checks logical cancellation during bounded work without early CPU
interruption. Argon2 remains one noninterruptible library call.

## Production UI cancellation

To measure Cancel and the lock shortcut during the public AES-KDF fixture:

```
node crates/confidex-app/src/import/formats/kdbx/check/cancel-ui.mjs APP_SOURCE WASM_BUNDLE OUTPUT
```

The runner reuses the existing application's UI-test setup, picker and hit-box
helpers from `APP_SOURCE`. It rejects changed helper anchors. A fresh browser
profile and vault keep the test independent of user storage. The supplied bundle
is not rebuilt. The result pins the helper, generated runner, fixture and exact
served assets. Only public credentials and fixtures are used.

A test-only listener observes progress metadata from the real Worker before the
application clears each message. Each case waits for repeated KDF progress before
clicking Cancel or pressing the browser's Ctrl+Shift+L shortcut. It does not alter
cancellation, replace the parser, terminate the Worker or require cross-origin
isolation. Screenshots, `cancel-result.json` and `lock-result.json` report UI
feedback and completion separately. Cancel returns to file selection. Lock closes
the import window immediately, then must stay on the locked vault's unlock screen
after queued Worker replies arrive. A stale reply may reach the host; the locked
UI must discard it.
Feedback time includes the shared click helper's input and settling delays.

The test requires continued main-page heartbeat, an unchanged full vault snapshot
and no late usable preview. Bounded computation may continue after logical cancel;
the measurements do not promise early CPU termination or physical memory erasure.
These are two desktop Chrome cases, not the full UI, native OS window or
storage-load acceptance suite.

## Recorded run

Apple M4, Rust 1.98.0 release, Chrome 156.0.8078.80, 2026-11-09:

These measurements use source commit
`03d564a727a4ce1a9aa4cea64e059b6af06d1634`, before rebasing onto later app changes.
They are not a benchmark of the current UI or storage path.

| 10k input to Plan | Native | Chrome Worker |
| --- | ---: | ---: |
| Input bytes | 1,104,949 | 1,104,949 |
| Canonical plan bytes | 12,062,670 | 12,062,670 |
| Prepare plus fingerprint | 652 ms | 733 ms |
| Rust allocation upper bound | 70,722,808 B | 69,468,400 B |
| Retained Rust allocations | 18,966,353 B | 16,592,005 B |
| After dropping source and plan | baseline | baseline |
| Native max RSS / WASM linear size | 120,438,784 B | 71,630,848 B |

All fifteen cases matched. Main-page heartbeat: 2,908 ticks. Shared cancel
returned about 0.84 ms after the signal, after 101 checkpoints, with no plan and
released Rust allocations. These are observed values, not a latency guarantee.
The sampled Chrome RSS sum rose from 1,207,484,416 to 1,421,131,776 B; interpret
it using the process/shared-page qualifications above. The independent KeePassXC
2.8.0 reader check is separate from native/WASM parity.
