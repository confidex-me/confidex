# Envelope authentication and encoding profile v1

Use the envelope/header layout in [the format profile](RECORD.md).
Let `H` be the exact bytes inside `Envelope.header_bytes` and `C` the exact bytes
inside `Envelope.ciphertext`. Retain these original byte slices during parsing.

## Binding to encrypted content

Pass `H` unchanged as the HPKE AAD. The fixed HPKE `info` domain and the version
in H bind the chosen suite. The AEAD tag therefore binds the compressed plaintext
to every header byte: format version, vault ID, record ID, parents, event kind,
epoch, value sizes, and their encoding. There are no additional unauthenticated
header fields. A valid signature does not bypass the AEAD check.

The self-computed revision ID and signature are outside H. The ID depends on the
resulting ciphertext; including it in AAD would make encryption circular. The
revision profile supplies its independent computation/check. Neither the hidden
recipient public key nor any secret is copied into H.

The negative fixture gives an attacker the ability to request signatures under
the accepted signing key while holding the old ciphertext fixed. It changes each
header field and obtains a valid new outer signature. HPKE opening still fails.
This isolates the binding guarantee. In v1 the full stored private material also
allows decryption: this test does not claim to stop a fully compromised client
from decrypting, modifying, and encrypting new content.

Do not add a second copy of header fields to the plaintext merely for this
binding. The AEAD check supplies it directly. Exact value-size and content-kind
checks still run after bounded decompression and parsing.

## Signature input

Use pure Ed25519, not Ed25519ph or Ed25519ctx. Sign exactly:

```text
ASCII("confidex/record/sign/v1") || U64BE(len(H)) || H || U64BE(len(C)) || C
```

There is no NUL terminator. Lengths are unsigned 8-byte big-endian byte counts.
The length prefixes prevent ambiguous concatenation. The signature is exactly
64 bytes and is excluded from its own input. Array/bin framing around H, C, and
the signature is parsed strictly but is not signed separately: it must yield
exactly those three fields and consume the whole envelope. Never verify a
reserialized Header or a recompressed ciphertext. Do not sign only metadata or
only a caller-supplied revision ID.

Only a trusted vault Ed25519 key may verify a Record; see [trust](TRUST.md). The
vault ID parsed from H must equal the anchor's ID. The bounded external parser
must extract and structurally check the signed slices before verification. Type
decoding/decryption/decompression occurs only after trusted signature validation.

## MessagePack acceptance

One object must consume its whole declared byte range. Reject truncation, the
reserved marker `c1`, invalid UTF-8 strings, unexpected wire types, duplicate map
keys, non-string map keys, and unsupported versions/schema fields. Check maps
recursively, including unknown encrypted extension values, before constructing
keyed containers. Different integer/string/bin width encodings must not hide
duplicate decoded keys. String comparison is exact UTF-8; no normalization.

Do not require one unique encoding for a semantic value. Standard MessagePack
integer widths and map orders are accepted when they satisfy the schema and
limits. Writers use shortest integer/length encodings and UTF-8 key order. Tags
are unique and sorted as defined in the format profile; entry order is preserved.
An alternative accepted encoding has different signed bytes and can have a
different revision identity. Semantic equivalence does not permit signature
substitution or deduplication of separately signed byte objects.

Nested values may contain nil, bool, MessagePack integers, f32/f64, valid UTF-8
strings, bin, arrays, maps, and ext. Ext payloads are opaque bytes; no automatic
timestamp/image/file decoder runs. Float bit patterns are retained; explicit type
validators may reject non-finite numbers. Keys at all map levels remain unique
UTF-8 strings. Unknown encrypted fields are preserved, not interpreted. Outer
Header and metadata schemas are closed in revision format v2. The resource profile applies
before recursive materialization. The bounded scanner checks raw markers,
UTF-8, map keys, and complete consumption within caller-supplied depth/node
limits. The [resource profile](RESOURCES.md) supplies their ceilings and stage
order. The scanner does not replace schema checks or the full opening pipeline.

In `rmpv` 1.3.1, `read_value` maps the reserved marker `c1` to `Value::Nil`.
Validate the original bytes before using that decoder. A byte `c1` inside a
bin/ext payload is valid data and must remain unchanged.

## Ed25519 strict profile

Use `ed25519-dalek` 3.0.0 `verify_strict`, with no batch or non-strict fallback.
Public keys must decode, be canonically encoded, and not have small order. Pins
are checked by decompressing/recompressing and comparing original bytes, plus
`is_weak`. Keys derived locally already have canonical encodings.

Signature S must satisfy `0 <= S < L`, the prime subgroup order. R must decode,
must not have small order, and must match the canonical compressed result of the
strict verification equation. Reject all decoding or equation failures. This
profile deliberately follows the selected strict implementation rather than
claiming equivalence with every Ed25519 consensus or batch-verification profile.
All dalek verify variants already check scalar range; strict mode adds point and
equation checks. The fixture pins wrong message/key/signature, S=L, S overflow,
small-order R, invalid/noncanonical R, and noncanonical/weak pin behavior.

Sources: [MessagePack](https://github.com/msgpack/msgpack/blob/master/spec.md),
[Ed25519 strict verification](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict),
[HPKE](https://www.rfc-editor.org/rfc/rfc9180.html).
