# Record format profile v2

This profile specifies the content/container boundary, size metric, and compression.
The [leakage profile](LEAKAGE.md) describes what those
public fields and compressed lengths reveal.
The encoding/signature and revision-identity profiles complete its wire rules.
The accompanying tests are construction examples, not an untrusted-data parser.

## Logical and encoded objects

A Record is a logical list of entries plus preserved extension fields. Its
encrypted content is one MessagePack map with `entries` and `tags` arrays. Each entry is a
map with `name` (UTF-8 str), `type` (nonempty UTF-8 str), and `value` (map).
Unknown Record/entry/value fields stay in those maps. Binary values use bin,
not arrays of integers or base64 strings. Field maps have unique UTF-8 keys.
Encrypted extensions cannot replace reserved fields.

Serialize the entire content map once, compress it once, then encrypt it. Do not
compress each value separately. The input to compression includes entry names,
types, values, tags, and encrypted extensions. It excludes all open envelope fields.
URLs are value fields and stay inside this content.

An encoded revision has the following envelope layout:

```text
Envelope = [header_bytes: bin, ciphertext: bin, signature: bin[64]]
Header = [format_version: uint(2), vault_id: bin[16], record_id: bin[16],
          parents: array<bin[32]>, metadata: map, event_kind: uint]
metadata = {"epoch": uint, "value_sizes": array<uint>}
```

`header_bytes` contains one encoded Header array. Keeping these bytes intact
allows signature checking and AAD use without reserializing it. Version 2 fixes
the HPKE and compression suites described here and in the cryptographic profile;
unsupported versions fail. The version therefore also authenticates suite choice.
`vault_id` and `record_id` are opaque 16-byte identifiers, not text or timestamps.
Generate them randomly; the storage/application layer must reject an accidental
collision rather than join two objects. Parents are revision references, not
record IDs. The [revision profile](REVISIONS.md) defines
their order and hash algorithm. The logical `revision_id` is computed from
the original header/ciphertext bytes and is not stored in this envelope.

`event_kind=0` is content; `event_kind=1` is a deletion event. Deletion identifies
the same record and affected revisions through `record_id` and `parents`, has
an empty `entries` array and empty `value_sizes`, and still has authenticated
encrypted content and a signature. Its graph/conflict rules belong to the
revision profile. No other event kind is accepted in version 2.

The metadata map has exactly the two defined fields. `epoch` is the revision's
modification time in Unix milliseconds, an integer in `0..=u64::MAX`. Applications
supply it for content and deletion events. Reject missing, negative, float, or
non-integer values. It is covered by H's signature and AAD. It is not a logical
counter or proof of clock accuracy; equal or decreasing times are valid. Branch
resolution uses a separate policy and does not alter existing signed objects.
Tags are encrypted UTF-8 labels in `Record.tags`, case-sensitive and unnormalized.
At most 256 unique tags of at most 256 UTF-8 bytes each are accepted. The writer
sorts them in UTF-8 byte order; the reader rejects unsorted or duplicate tags.
An empty array is valid; absent content tags decode as empty. Writers always emit
the field. Unknown extensions cannot replace `entries` or `tags`. Tags count
against the same whole-content limits, not `value_sizes`. Additional public
metadata requires a format decision. Names/types/URLs must not be copied into
metadata. Revision IDs, parents, epoch and value sizes remain public.

An authorized client derives a plaintext local tag → record ID search index.
It discloses labels/associations to readers of the client database, not encrypted
values or keys. Tags may themselves be sensitive; see the
[leakage profile](LEAKAGE.md). This index is never synced.

`ciphertext` is the HPKE inner packet: ephemeral public `enc[32]`, followed by
encrypted compressed bytes and a 16-byte tag. It does not contain the hidden
recipient public key. The signature profile defines the exact signed input;
the field-binding profile defines use of Header bytes as AAD.

## Exact public size metric

For entry at index `i`, `metadata.value_sizes[i]` is the byte length of that
entry's complete encoded `value` map in the decompressed content. Include its
map marker/count, all field names, nested values, length markers, and binary
bytes. Exclude the surrounding entry map, entry name/type, and `value` field name.
This measures encoded bytes, not heap usage, characters, image pixels, extracted
file size, or the compressed contribution of an individual entry.

The same metric applies to every type. For example, with shortest MessagePack
encodings, `{"data": "a"}` is 8 bytes; `{"data": "é"}` is 9 bytes;
`{"data": bin[01,02,03,04]}` is 12 bytes; an empty map is 1 byte. Map keys and
length markers contribute to the total. The encoding profile determines allowed
alternative encodings; readers count the actual original value span, not the
length of an arbitrary reserialization.

There must be exactly as many sizes as entries. After authenticated decryption
and bounded decompression/parsing, compare every original span length with its
declared value. Any mismatch rejects the record. Sizes do not authorize memory
allocation and do not replace parser/decompression budgets.

Positions refer only to this revision. Reordering `[A, B]` to `[B, A]` swaps the
sizes; deleting B removes its size. Recompute the entire vector on every edit.
Repeated entry names do not affect association. Renaming an entry without
changing its value does not change that value's size. No persistent entry ID is
introduced or disclosed.

## Compression profile 1

Use one RFC 1950 zlib stream containing RFC 1951 DEFLATE. No preset dictionary,
no concatenated streams, and no trailing bytes are allowed. Accept valid zlib
window sizes up to 32 KiB and verify the Adler-32 checksum. The writer uses
level 6 and a 32 KiB window, through the pure Rust `miniz_oxide` backend of
`flate2`. Compression levels are encoder choices; they do not change decoding.
Compatible writers need not produce identical DEFLATE bytes. Identity/signature
checks cover the actual resulting bytes. Never recompress received bytes to
verify an identifier or signature.

The compressed serialized content, including the zlib header and checksum, must
be **at most 4,000,000 bytes**. This is decimal 4 MB, not 4 MiB. Equality is valid;
4,000,001 is invalid. The bound is checked before encryption and again on the
decrypted compressed input before decompression. Neither HPKE's extra 48 bytes
nor the envelope/signature are charged against this bound. Thus the HPKE packet
can be at most 4,000,048 bytes; the wire parser has its own envelope budget.

The limit applies to the whole content even if a single attachment dominates
it. Uncompressed content has a separate hard output limit. Parsing depth, element
counts, and allocations are independently bounded by the resource profile.

The boundary test constructs valid zlib streams of exactly 3,999,999, 4,000,000,
and 4,000,001 bytes using stored DEFLATE blocks, so compressor heuristics cannot
move the tested boundary. These are compression-layer inputs, not full records.
The integration tests must apply the same limits to encrypted Record objects.

Sources: [MessagePack](https://github.com/msgpack/msgpack/blob/master/spec.md),
[zlib](https://www.rfc-editor.org/rfc/rfc1950.html),
[flate2](https://docs.rs/flate2/1.1.11/flate2/).
