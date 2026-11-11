# Import identity and provenance

The Engine owns a common import Plan between review and application. It seals
selected records through the normal core API and publishes one storage batch.
`origin.rs` and `matching.rs` implement its encrypted provenance and matching.

Call `Engine::begin_import` before parsing a new file. It requires an unlocked
vault and releases the previous Plan, search index and history cache. Drop the
input buffer and credential options after parsing, then pass the Plan and explicit
target vault to `review_import`. Its token identifies this exact preview.
`import_plan` borrows it for bounded item previews; `import_candidates` returns at
most 64 candidates per page. Release decoded preview values before continuing.

`apply_import` takes a Selection with one Choice per item and an independent
container acknowledgement. A blocked container forbids application even when
every item is skipped; a Review container requires `container_reviewed`.
Create is allowed only for a new
item; Copy and Update require explicit review. Update replaces a complete Record
and retains its signed history; it does not merge fields by their names. Review
statuses require acknowledgement, while blocked and excluded items can only be
skipped. Repeated IDs/content require Skip or explicit Copy. There is no default
overwrite. All application errors consume the preview and require a fresh review.
Wrong tokens leave the active preview intact. Lock, vault/session changes,
removal and backup inspection discard the Plan.

An async Control checkpoint lets a browser host yield to its Worker event loop
and read cancellation messages between bounded records. A synchronous FnMut also
implements Control for native callers. It does not by itself yield a browser
worker. Cancellation remains available through the Commit checkpoint; after that,
the storage transaction owns completion. All current heads are compared inside
that transaction, including concurrent additions. A successful commit discards
derived search/history caches; rebuilding search cannot turn a committed import
into a failed import or create duplicate records on retry.

The Plan's shared memory counter also admits the catalog (100,000 authenticated
heads/ancestry visits), resident decoded values, metadata and staging. Staging is
limited to 10,000 records and 32 MiB sealed bytes, with additional reservations
for Rust/JS/IndexedDB copies and tags. Actual admission depends on retained data;
these ceilings do not guarantee that all maxima fit simultaneously. This is a
conservative admission profile, not an allocator peak measurement.

The optional encrypted root property `confidex.import.origin` has version 1:

- `format`: the stable import format name.
- `source`: instance, account, vault, item, and a diagnostic locator. Optional
  identifiers are strings or nil; the locator is not an identity.
- `original`: a domain-separated SHA-256 of length-framed canonical mapped
  content, source attributes, and the optional shared container digest.
- `content`: a separately domain-separated fingerprint of canonical local
  content without this root property. Local edits keep the stored baseline.
- `attributes`: the original item metadata mapping, including binary values.
- `container`: an empty map, a carrier `{digest, attributes}`, or a reference
  `{digest, record, revision}` to an immutable signed carrier revision.

All this metadata is inside the encrypted Record. Fingerprints are never sent to
search or logs. Owned fingerprints and temporary metadata are wiped on drop.
Unknown versions, duplicate keys, malformed identifiers, and malformed references
are refused, so an update cannot silently discard unsupported provenance.

A source identity requires a caller-supplied nonempty instance and item ID. It
also includes the format, account, and vault, with distinct nil and empty values.
Do not derive the instance from a filename, title, URL, or random identifier.
Different scoped IDs remain separate even when their content is identical.
Without scoped identity, matching checks current content and imported baselines;
this also finds locally edited records. Deleted matches always require an
explicit decision. An exact live copy allows an identical reimport to be skipped;
all matching copies remain available for explicit conflict resolution.

Repeated source IDs and repeated unscoped content inside one Plan are reported
by their first position. The host must handle this result before catalog lookup,
so repeated groups do not cause quadratic comparisons or automatic overwrites.
Candidate lists are indexed once; the host must page results and enforce its
catalog limit instead of expanding all candidates into every preview row.

The first record actually selected for publication carries the shared attributes.
It is sealed first, then other selected records reference its immutable signed
revision. The full core Record limit includes provenance. During review, a
reference must resolve to an authenticated content revision in the same vault,
with the exact record/revision IDs and carrier digest. The digest uses the common
`import::attribute_record` canonical envelope. Verified immutable references are
cached within the review session; large metadata is not opened for every item.
The incoming container is hashed once and its digest is reused for every item.
Missing references, chains, wrong scope and bad digests fail review. Deletion or
editing of the carrier's current head retains the referenced old revision.
Retaining metadata does not promise lossless export and must never restore
removed fields or old passwords during a later export.

## Checks

`cargo test -p confidex-app --test import_origin --test import_apply` exercises
the provenance/matching contract and encrypted SQLite application, reopening,
search, repetition, local/source edits, selected carriers, deletion ancestry,
explicit restoration, cancellation, stale tokens, another writer, injected late
storage failure and the final core Record limit including metadata.

The browser probe parses synthetic Bitwarden JSON with the real adapter, then
runs the Engine, BrowserStore bridge and IndexedDB in a dedicated Worker.
It checks quota rollback/retry, reimport, search protection, concurrent writes,
reopening and cancellation sent from the page during sealing. The page must keep
running while the worker is busy. No test exports are in a normal client build.

Build the client WASM with `--features import-check`, the normal 256 MiB memory
cap and wasm-bindgen 0.2.130, then run:

```sh
node apps/confidex/web/import-check.mjs /path/to/playwright-core/index.mjs /path/to/chrome /path/to/wasm-bundle
```

The probe is not an official vendor export capture or an application UI test.
Full format coverage, application UI and the complete 10,000-record pipeline
measurements require their separate integration checks.
