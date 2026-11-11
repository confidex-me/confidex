# Import pipeline

This module builds a local plan. It has no storage, network, filesystem or UI
access. The host runs it on a native blocking worker or a dedicated browser
worker. The host must cancel and discard the plan on lock, close or session
change. A callback that returns false cancels at the next bounded checkpoint.
A synchronous function alone does not move work off the UI thread.

Each format owns `formats/<format>.rs`, its optional child modules, and its own
fixtures/tests. Its entry point is `parse(&[u8], &mut Context) -> Result<(), Error>`.
Unimplemented adapters explicitly refuse input. The host owns registration;
there is no dynamic plugin loader. `prepare` accepts a registered parser.

Adapters add `Item { source, record, source_attributes, status, diagnostics }`
with `Context::push`. `record` is the existing core Record, with ordered entries,
unchanged names and typed binary values. `source_attributes` is a core Mapping,
not a disposable UI summary. `Context::set_container_attributes` retains shared
root/group metadata once; `Plan::container_attributes` retrieves it even with no
selected items. Setting it twice fails. Apply must persist this payload or report
that it cannot; an empty selection does not make it safe to discard.
`Context::container_diagnostic(status, diagnostic)` reports shared unsupported
content through `Plan.container_status` and `container_diagnostics`. Review needs
a plan-level acknowledgement; Blocked forbids the entire apply. Item selection
cannot bypass a container problem, and a later diagnostic cannot lower a block.
The bounded list is reserved up front; identical diagnostics are coalesced.

Unknown source data needs a protected Original data
field and a review diagnostic, or a blocked item. An invalid core value fails.
Source field protection must never be lowered by a mapper.

The Plan owns canonical zeroizing core MessagePack, not ten thousand live Record
objects. Decode one item at a time with `PlannedItem::record` and
`source_attributes`, within the host's working-memory budget. The plan's format
plus source instance/account/vault/item form its source identity. Locator is only
a diagnostic position. The caller supplies a stable source instance; filenames,
URLs, titles and random values are not identity scopes. Missing scope requires
review. Apply owns encrypted provenance placement, conflict decisions, final
Record validation (including provenance), encryption and atomic storage commit.
After parsing, the host must drop its input buffer and credential options.
`Plan::memory()` retains the accounting for headers, item and container payloads;
apply must charge its encrypted batch and current decoded Record against the
remaining budget. Read-only `record_bytes`, `source_attributes_bytes` and optional
`container_attributes_bytes` borrow canonical payloads for fingerprints without
decoding or cloning; these internal wrappers are not a new export format.
Callbacks may be frequent; the host coalesces progress messages.

Source-only timestamps do not become signed revision history. Nothing applies
just because parsing succeeds; blocked/excluded/review statuses remain explicit.

## Budgets

All limits can be lowered; none can exceed the defaults:

| Resource | Ceiling |
| --- | ---: |
| Input, total declared ZIP output, encoded plan | 64 MiB each |
| Accounted worker memory | 192 MiB |
| Records / fields per record or JSON object | 10,000 / 512 |
| Nesting depth / nodes per document or record | 32 / 1,000,000 |
| String / name | 16 MiB / 4 KiB |
| ZIP entries / central directory | 20,003 / 8 MiB |
| ZIP member expansion | compressed bytes × 1,000 + 1 MiB |
| Core compressed Record | 4,000,000 bytes, zlib level 6 |

Input, plan headers, encoded items, ZIP metadata/output, JSON validation and owned
item DOMs share memory reservations. ZIP codec scratch and Record compression
scratch each reserve 1 MiB while in use. Adapters must reserve working memory **before**
allocating owned values (`reserve_work` or the bounded JSON helpers). Reservations
are conservative admission estimates, not a replacement for allocator profiling.
A 10,000 × 10-entry synthetic sample used about 104 MiB as live core objects and
13.2 MiB encoded; a 4.6 MiB JSON source used about 79 MiB as a full DOM. This is why
JSON is validated without a whole-file DOM and one source item is mapped at a time.
The field ceiling is the application's existing limit. Two attachment slots per
item plus container entries bound ZIP count. Input/plan/decompressed ceilings
leave space for one mapped item and parser scratch inside the shared budget.
The worker budget leaves headroom under the browser's 256 MiB profile; platform
integration still needs an end-to-end peak measurement.

`json::Document` checks syntax, depth, node/string limits and decoded duplicate
object keys. Arrays borrow RawValue slices; `json::owned` admits and wipes one
owned item. `Owned` also permits mutation under its cleanup guard. Preserve
unknown Original data from `RawValue::get()`: a Value-to-JSON round trip can round
numbers outside the owned numeric representation. Do not parse the entire source
into `serde_json::Value`. Keys that
repeat as separate ordered fields are valid; duplicate JSON object keys are not.

`archive::Archive` checks central records before the ZIP library allocates
metadata. It accepts bounded single-disk ZIP32/ZIP64, UTF-8 relative paths,
stored/deflated members and empty directory entries. It rejects duplicate or
aliased file/directory paths, traversal, symlinks/special files, overlapping
members, encryption and unsupported compression. Declared output and expansion
are checked before allocation. Reads use exact-size zeroizing buffers and verify
EOF and CRC. `Buffer::into_parts` transfers its zeroizing bytes and reservation
together; move bytes into a core binary value while keeping the reservation
until encoding, without cloning the plaintext. No member is extracted to disk. The separate encrypted backup reader
is unchanged.

Owned source identifiers, options, core values, source attributes, encoded plan
and unpacked buffers are wiped on drop. Diagnostics contain only fixed codes and
numeric positions; do not add raw values, names or parser error text. Library
scratch allocations and OS/browser copies are outside these ownership guarantees.
The host must not log input or send it to a server or fetch imported URLs/icons.

Source metadata retained for future exports must not resurrect deleted fields or
old passwords. A writer needs its own compatibility/loss preview and independent
reader checks; retaining provenance does not promise lossless conversion.

The ZIP preflight follows [PKWARE APPNOTE 6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT).
KDBX detection uses the two signatures in the [KeePass specification](https://keepass.info/help/kb/kdbx.html); it does not authenticate or decrypt a database.

## Checks

`cargo test -p confidex-app --test import_pipeline` checks the golden core plans,
source/container retention, protection and binary values, cancellation/accounting,
JSON limits/duplicate keys, ZIP32/ZIP64/path/overlap/CRC/resource checks, and every
truncation/single-byte mutation of a small synthetic ZIP.

The same suite runs in WASM without a browser or network:

```sh
CARGO_TARGET_WASM32_WASIP1_RUNNER="node crates/confidex-app/tests/run-wasi.mjs" cargo test -p confidex-app --test import_pipeline --target wasm32-wasip1 -- --test-threads=1
```

Add `--ignored --exact ten_thousand_items_use_a_bounded_encoded_plan --nocapture`
after `--` to run the separate 10,000-item calibration. The runner reports the
linear-memory high-water mark and enforces 256 MiB. Also check the actual browser
target with `cargo check -p confidex-app --lib --target wasm32-unknown-unknown`.
WASI parity is a parser check; it does not replace real browser worker/UI,
lock/session and atomic apply checks in the host integration.
