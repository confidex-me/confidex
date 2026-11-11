# Import stage measurements

This runner observes the existing 10,000-row CSV store proof. The generated input
has ten mixed fields per record: URL, username, password, secure note, public and
protected custom fields, an empty-name field, TOTP and a public note. It uses real
SQLite or BrowserStore/IndexedDB, signatures, encryption and the session index.
After the timed import, the existing proof reopens the vault, compares every
decrypted canonical Record with its Plan after removing the generated provenance,
requires 10,000 duplicates, skips them and checks public/private search again.
Exact provenance attributes and carrier references are covered by the separate
shared fixture matrix. Failed assertions produce no measurement.

## Boundaries

Times are accumulated wall-clock intervals between actual production checkpoints,
using native Instant or Worker performance.now. Their instrumentation overhead is
included. Source generation is counted; vault creation and its initial KDF are
excluded by resetting the observer at the existing `create` boundary.
Only `--profile` serves the local probe with COOP/COEP isolation for a finer clock.
The Worker reports its measured clock quantum and rejects a resolution above
10 microseconds. Short stage aggregates remain subject to clock quantization;
they are not per-cell latency measurements. Other browser checks keep their
existing response headers.

| Field | Work included |
| --- | --- |
| inspect_ms | Adapter setup before the first CSV read |
| read_ms | CSV scanning, grammar/byte bounds and row setup before field mapping |
| map_ms | Cell decoding and typed field mapping |
| validate_ms | Common Record/value admission, canonical encoding, compression-cap checks and Plan retention |
| review_ms | Preview matching plus Apply catalog/selection/provenance preparation |
| seal_ms | Per-record Plan decoding, provenance, compression, encryption/signing, verification and staging |
| commit_ms | Exact awaited Store::batch_commit, including the browser bridge and IndexedDB transaction |
| commit_release_ms | Remaining Apply cleanup after that Store call |
| index_ms | First full index build and the proof's public/private search assertions |
| other_ms | Source generation, setup and post-Apply head-count verification |

The fields sum to total_ms. They are pipeline measurements, not isolated crypto
primitive or search-latency benchmarks. The parser's Read boundary at each row
prevents CSV scanning from being charged to the preceding validation interval.
Checkpoints inside long reads/compression keep their existing cancellation guards.
An independent timeline test checks the arithmetic and I/O split; a small CSV
test proves cancellation before mapping the next row and release of reservations.

## Run

```sh
cargo test -p confidex-app --release --test import_csv --no-run
/usr/bin/time -l PATH_TO_IMPORT_CSV_TEST --exact apply::performance::ten_thousand_stages --ignored --nocapture --test-threads=1
node crates/confidex-app/tests/import_csv/browser.mjs /path/to/chrome --profile
```

Cargo prints the native test executable path. Keep builds out of measured runs
and use fresh test processes/browser profiles for repeated observations. Browser
tools use the existing wasm32-unknown-unknown target, matching wasm-bindgen 0.2.130
and the CONFIDEX_TEST_CARGO/CONFIDEX_TEST_BINDGEN/CARGO_TARGET_DIR overrides.
Set TMPDIR to a suitable scratch directory. The profile still enforces the 256 MiB
WASM linear-memory maximum and blocks external Worker fetches.
Its three-minute timeout includes all subsequent verification and cleanup. Initial
complete runs took about 30 seconds on the measured host; the timeout leaves room
for concurrent host load and is a test watchdog, not a product latency guarantee.

## Memory scope

On macOS, native `/usr/bin/time -l` reports the test process's maximum resident
set in bytes. It includes vault creation and the subsequent full reopen/verification
proof, not just the timed first import. The WASM report is allocated linear-memory
high-water, not JavaScript or whole-browser memory. Retained_budget_bytes is the
Plan's logical admission accounting, not an allocator or process measurement.

The optional browser profile samples the actual launched Chrome PID and its
current descendants with POSIX ps every 100 ms. It reports their summed RSS in
bytes, baseline, largest process count and sample count. Shared pages can be
counted more than once; short peaks between samples and reparented helpers can be
missed. This is observed process-tree RSS, not unique private memory or a strict
upper bound. Sampling continues through module loading, import, reopen and cleanup.
Its host-process overhead is included; ps failures reject the report.

The native workload is explicitly ignored in ordinary test runs. It must be run
with the command above. The normal CSV tests, default browser check and `--load`
mode keep their existing behavior. This probe does not render the import UI or
prove Worker message cancellation or performance on a physical phone.

## Observed series

Raw [results.json](results.json) contains three fresh native processes and three
fresh Chrome profiles, all built from source commit
`e86cea5f3cf2fee9ab4d86065986475d447ac37c`. Each run completed the full
10,000-record reopen/all-field/duplicate/search proof. Builds ran outside the
measured workload, and native/browser trials ran sequentially. This shared
development machine had uncontrolled CPU, scheduling and I/O load.
No outliers were removed. These six observations do not establish p95 or a
performance guarantee, and do not support a native-versus-browser speed claim.

Host: Apple M4, 10 logical CPUs, 24 GiB RAM, macOS 26.2 arm64.
Rust 1.98.0 release, Node 26.10.0, headless Chrome 156. The isolated Worker clock
had an observed 5 microsecond quantum in all three trials.

Input: 2,050,076 bytes; encoded Plan: 11,009,048 bytes. Retained logical Plan
accounting was 15,007,720 bytes native and 13,753,384 bytes WASM. The empty local
vault is the initial destination. These are small scalar records, not 10,000
near-limit records or image attachments; all per-record and batch caps still apply.

Times below are milliseconds: median [minimum–maximum]. Per-stage medians are
computed independently and need not sum to the median total; each raw run does sum.

| Stage | Native | Chrome/WASM |
| --- | ---: | ---: |
| inspect | 0.84 [0.84–0.86] | 3.25 [2.53–3.68] |
| read | 4.80 [4.34–4.87] | 8.79 [7.68–10.08] |
| map | 23.53 [20.83–23.66] | 41.38 [35.97–51.20] |
| validate | 266.49 [237.98–268.95] | 260.06 [235.33–323.21] |
| review | 24.99 [21.00–25.50] | 71.47 [64.76–82.84] |
| seal | 14,559.09 [12,864.08–22,783.45] | 10,075.81 [8,750.37–11,918.69] |
| commit | 255.13 [216.18–1,158.82] | 1,058.42 [716.20–1,483.84] |
| commit_release | 6.84 [5.65–22.43] | 6.19 [4.38–7.91] |
| index | 1,976.56 [1,741.57–5,146.65] | 4,089.52 [3,922.48–4,582.76] |
| other | 18.58 [15.59–171.49] | 201.70 [139.88–321.74] |
| total | 17,101.18 [15,166.19–29,604.21] | 16,857.00 [13,879.57–17,745.52] |

| Memory observation | Maximum across the three trials |
| --- | ---: |
| Native kernel max RSS, whole proof | 125,763,584 bytes |
| WASM allocated linear high-water | 135,725,056 bytes |
| Chrome sampled process-tree RSS sum | 1,734,115,328 bytes |

Chrome sampling observed 12 processes. Its RSS sum counts shared pages repeatedly
and is not comparable to a single WASM allocation or native private footprint.
The raw file also keeps native peak-footprint observations, browser baselines,
sample counts, clock metadata, heartbeats and phase timestamps.

The existing 192 MiB logical admission budget and 256 MiB WASM linear cap admitted
all six trials without changes. The observed WASM high-water was 129.44 MiB; this
does not cap the browser host. Complete proof times ranged from
20.66–36.92 s native and
29.33–37.61 s Chrome.
The 180-second profile watchdog leaves about 4.8 times the slowest observed proof;
it remains a bounded test allowance, not a promise for arbitrary hardware or input.
