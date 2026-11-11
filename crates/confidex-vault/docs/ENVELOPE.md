# Encrypted revision API

`envelope::seal(&record, &keys, options, memory_budget)` returns one complete v2
envelope. Options supply vault/record IDs, parents, epoch in Unix milliseconds,
and the content/deletion kind. Tags come from encrypted `Record.tags`. The writer
sorts parents and tags and rejects
duplicates. It derives value sizes from the actual encoded content, compresses
the whole map once, creates a fresh HPKE context, and signs the original H/C bytes.
Deletion requires nonempty parents and empty entries. IDs and times are supplied
by the application; these calls do not choose a storage backend or read a clock.

`envelope::verify(wire, &anchor, expected_id, memory_budget)` bounds and checks
the complete envelope/header schema and trusted signature. It optionally matches
an expected revision ID and returns `VerifiedRevision`. It never decrypts content.
Its header exposes epoch, positional value sizes, IDs, parents, and kind; tags
are only available after opening. The verified revision retains the original
header/ciphertext slices; the input must remain alive and unchanged.
There is no unverified metadata result that can be confused with this result.

`VerifiedRevision::open(&keys, memory_budget)` authenticates HPKE with the original
H, decompresses one bounded zlib stream, decodes Record content, and matches every
original value-map span to the declared sizes. The returned Record owns its data.
`envelope::open` combines verification and opening and returns both results.
Unsupported schemas, invalid signatures, wrong recipients, changed AAD, bad zlib,
and wrong sizes return errors without changing caller data. Type validation is
explicit; files, images, and timestamps in ext values are not decoded here.

Pass at most `resources::MAX_OPEN_MEMORY` (192 MiB). Each operation admits a fixed
24 MiB allowance for wire, signature framing, HPKE/compression copies, bounded
header parsing, and bookkeeping. Opening reserves at most 64 MiB for raw content,
or half the remaining budget when lower. It charges retained capacity before
calling the Record decoder, whose admission includes the raw and owned model.
Writers use the same content limits and admission before compression. A small
caller budget may reject otherwise valid data. Caller-built Records with excessive
spare capacity, retained results, and concurrent operations remain the caller's
responsibility. The budget bounds controlled live memory, not allocator retention,
WASM linear-memory high-water usage, or all opaque dependency allocations.

Sealing obtains a fresh 32-byte seed through `entropy::fill_random` and uses the
standard RustCrypto ChaCha20Rng with zeroization enabled for HPKE's infallible RNG
interface. Entropy errors return before encryption, with no fallback or panic
adapter. Browser builds opt into the core's `browser` feature. Seed and compressed
buffers are cleared on drop; this does not claim erasure of all compiler or codec
temporaries. Low-level `crypto` functions remain available for construction tests
but do not independently enforce this full wire contract.

These calls check one revision. Parent existence, cross-record parent scope,
cycles, retained deletions, and batch transactions belong to graph/storage
integration. Authentication does not prove server freshness or completeness.
Synchronization and conflict UI live in the separate
[application layer](../../../apps/confidexsyncd/docs/SYNC.md); they do not change this per-revision API.
