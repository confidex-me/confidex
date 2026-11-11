# Resource profile v1

These limits apply equally to native and WASM readers and writers. They bound
work independently of public metadata. A trusted caller can lower a budget,
but cannot raise a format ceiling. Exceeding a caller budget is a resource error,
not proof that the object is corrupt. All byte limits are inclusive.

## Per-revision limits

| Quantity | Maximum |
| --- | ---: |
| Serialized compressed content | 4,000,000 bytes |
| HPKE packet | 4,000,048 bytes |
| Header bytes | 65,536 bytes |
| Entire encoded envelope | 4,065,668 bytes |
| Decompressed serialized content | 67,108,864 bytes (64 MiB) |
| Header MessagePack depth / nodes | 4 / 8,192 |
| Content MessagePack depth / nodes | 64 / 65,536 |
| Header string / bin payload | 256 / 32 bytes |
| Content string / bin or ext payload | 1 MiB / 64 MiB |
| Header / content map key | 32 / 1,024 UTF-8 bytes |
| Entries and corresponding value sizes | 4,096 |
| Parents | 1,024 |
| Encrypted content tags | 256, each at most 256 UTF-8 bytes |

The envelope ceiling includes the widest allowed array/bin length prefixes:
5 + 3*5 + 65,536 + 4,000,048 + 64. The fixed schema still requires exactly three
fields and a 64-byte signature. A large byte allowance cannot authorize a
different schema. The HPKE packet needs at least its 48 bytes of overhead.

Depth is the number of edges from the root value, whose depth is zero. Every
scalar, map, array, map key, and map value is one node. Declared container counts
must fit the remaining node budget before traversal or allocation. Node limits
also bound container element counts. Map keys count toward string/node/byte
limits. Ext payload limits exclude its one-byte type tag; total input limits
include all markers, lengths, tags, and payloads. No arithmetic may wrap.

All limits apply together. A bin payload cannot occupy all 64 MiB of content
because its prefix and enclosing Record also consume bytes. The per-value size
vector is an authenticated assertion to check, never allocation permission.
Entry names, types, and unknown field values receive the same string limits.

## Required processing order

1. Bound the received envelope before buffering it. Extract its three original
   bin slices with checked offsets/lengths and no recursive materialization.
   Require full consumption. Scan H under the header limits and validate its
   fixed schema, supported version, field counts, IDs, parents, and metadata.
2. Select an existing trusted vault key and verify the signature over the exact
   framed H/C bytes. Check any explicitly expected revision ID. An unknown key,
   wrong vault, invalid signature, or mismatched ID stops processing here.
3. Open HPKE with H as AAD. Fail on authentication error. Enforce the compressed
   byte ceiling before decompression; do not act on unauthenticated plaintext.
4. Decompress one zlib stream into a bounded buffer. Require the checksum,
   StreamEnd, no dictionary, no concatenated stream, and no trailing input.
   Stop when another output byte would exceed the budget, without appending it.
5. Scan raw content under the content limits before building owned values.
   Reject invalid markers, UTF-8, duplicate/non-string map keys, truncation,
   invalid structural types, and trailing data. Then check the Record and
   entry schemas, entry count, encrypted tag bounds/order, and deletion-specific rules.
6. Match the number of value sizes and every actual original value-map byte
   span with metadata. Return content only after all checks succeed.

The external scan is necessarily before signature verification because it
extracts the signed ranges and signature. It must remain bounded. Content
decoding, decompression, and type decoders must not run during that scan.
Writers enforce the same content limits before compression/encryption, even
when highly repetitive content would fit the compressed ceiling.

## Memory and work budgets

The core operation budget is **192 MiB of live buffers and model/index storage**.
Account for capacities, not only lengths, including buffers retained for results
and temporary copies. Check before allocations; use fallible reservation where
available. Do not use a large declared length as a capacity without first
checking the relevant ceiling and the remaining operation budget. A failed
operation must not partially replace accepted storage state.

The opening implementation has the following allocation allowances. These are
ceilings, not a requirement to allocate all of them:

| Allocation group | Allowance |
| --- | ---: |
| Input, signature framing, encrypted/compressed working copies | 24 MiB |
| Decompressed raw content buffer | 64 MiB |
| Owned decoded strings/bin/ext and container storage | 80 MiB |
| Parser, decompressor, and operation bookkeeping | 8 MiB |
| Spare capacity for overlapping stages | 16 MiB |

Keep raw data and owned decoded copies within those allowances; release buffers
when their stage ends. The parser borrows map key bytes. A shared key-slot budget
bounds all simultaneously reserved map-key vectors to nodes/2, including malformed
nested maps whose remaining entries never arrive. With 16-byte string slices on
64-bit native this is at most 512 KiB; 32-bit WASM uses less. Depth is independently
bounded. Sorting bounded borrowed key lists does not duplicate their contents.

Decompression first measures and validates the complete zlib stream with a
64 KiB zeroizing scratch buffer. It then reserves the measured output size once
and inflates the same immutable input into that zeroizing buffer. No plaintext
buffer grows or moves during inflation. Both passes enforce the output bound,
checksum, stream end, and complete input consumption. Small records therefore
do not allocate or clear the full 64 MiB ceiling. Admission still charges input
bytes + `output_limit` + a 256 KiB decompressor/scratch allowance against the
supplied memory budget before either pass; a smaller result does not relax it.
This does not certify the entire opening pipeline: its other stages must charge
their allocations too. The generic scanner does not allocate a decoded model.

No wall-clock deadline is a format rule. Work is bounded by compressed/decompressed
bytes, depth, nodes, key lengths, and object counts. Each inflate iteration must
consume input or produce output, or return an error; it cannot retry forever.
An application can cancel processing or impose a shorter deadline. No timeout
may weaken authentication or silently return a truncated successful result.

These budgets describe core-controlled allocations, not total process RSS, JS
heap usage, allocator bookkeeping, or a guaranteed response time. Process-wide
memory exhaustion and opaque dependency allocations remain platform limitations.
The integration must account for dependency scratch space, avoid concurrent
operations that exceed its available memory, and return resource errors for
failures it can observe. Do not claim that a wasm trap or OS termination can
always be converted to a Rust error.

## Lists, graphs, and explicit type validation

A records-list reader must stream bounded envelopes; it must not first decode
an unbounded array of Records. Per import/export operation, cap consumed wire
bytes at 512 MiB, envelopes at 10,000, and graph edges at 100,000. Count duplicate
deliveries too. Process at most one plaintext Record at a time. The same 192 MiB
live memory budget bounds accumulated IDs/graph/index state. If a requested batch
does not fit, return a resource error without silently dropping objects. These
are operation budgets, not a claim that the complete vault has at most 10,000
revisions. Persistent storage and application concurrency remain external.

Extracting a value returns data without decoding its type. Explicit image/file
validation or conversion uses the same 192 MiB operation ceiling, checked input
lengths and output limits. A decoder-specific profile must additionally cap
dimensions, pixels, frames, and intermediate allocations before decoding. A
codec that cannot enforce the required limits must not be exposed as a bounded
operation. Image codecs and their concrete geometry rules are specified with
the image implementation. Nested archive expansion or opening a stored file is
an application decision; reading a Record never invokes it automatically.

## Checks and integration boundary

`tests/resources.rs` covers 64 MiB minus one, equal, and plus one output; smaller
caller budgets; 64 KiB output chunk boundaries; memory admission; input cap;
every truncation of a small zlib fixture; checksum/header/dictionary/trailing
stream failures; depth/node/string/key/total-byte limits; ext/bin limits;
oversized declared lengths; and nested map reservations. Existing format tests
cover the exact 4,000,000-byte compressed boundary.

Schema integration cases must include 4,095/4,096/4,097 entries and size items,
1,023/1,024/1,025 parents, and 255/256/257 tags. Keep other fields small so their
limits do not mask the tested boundary. A declared size vector that understates
or overstates an actual value must fail after decompression; a vector claiming
more than the content cap must never increase that cap. List integration cases
must exercise the byte, envelope-count, and edge-count budgets independently,
including duplicate envelopes and an error without a partial storage update.

The core now reuses the scanner and bounded zlib step in its Record, envelope,
lock, and streaming records-list APIs. They add schema checks, stage order,
value-span matching, owned-model admission, and per-list counters. List reading
does not automatically open content; callers explicitly open each revision and
stage it before committing external storage. The separate
[graph API](../REVISIONS.md) and explicit typed-value APIs
add their own validation and resource admission. Their integration tests exercise
these boundaries; an isolated scanner test alone does not verify those APIs or
an application's storage transaction.
