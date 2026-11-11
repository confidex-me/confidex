# Confidex portable format

The current pre-release format uses **lock version 1** and **revision/records-list
version 2**. Version 2 moves tags into encrypted Record content; version 1
revisions/lists are rejected without migration or fallback. Existing data is test
data. The profiles below define the cryptographic/resource rules. All lengths
are byte lengths. The `confidex/` magic and cryptographic `/v1` suite domains stay
unchanged; the authenticated header version distinguishes the new schema.

## Current vault model

The lock protects one canonical 32-byte X25519 private material plus a derivation
version byte. Its X25519 public key is the client-held `secret_key`, used both as
an HPKE recipient and as an input to password-based lock protection. A separate
HKDF domain derives the Ed25519 signing seed from the private material. The
Ed25519 public key is in the public lock header; `secret_key` is not.

The random wire `vault_id` is a 16-byte scope, not the sync address. The
[sync protocol](../../../apps/confidexsyncd/docs/SYNC-API.md) computes its public UUIDv5 address from the existing
Ed25519 public key. The current client accepts only the
[77-symbol transfer code](TRANSFER-CODE.md), containing
`secret_key[32] || public_UUID[16]` with a four-bit checksum. Text representation
and sync addressing do not change the three wire objects below. The older
32-byte-only text codec remains a low-level fixture utility, not a client
fallback. Local SQLite/IndexedDB stores individual locks/revisions and indexes;
it does not require a monolithic records-list for each save or sync operation.

## Objects and encoding

There are three separate wire objects: a lock, one immutable Record revision,
and a records-list. Encode each as one MessagePack value, consuming its entire
byte range. Binary fields use bin, text uses valid UTF-8 str, and unsigned fields
are nonnegative integers within the specified range. Arrays have exact arity.
Reject unsupported versions, extra positional fields, duplicate map keys, and
wrong wire types. Preserve unknown encrypted fields, as described in the
[Record profile](spec/RECORD.md).

Apply the [encoding/signature profile](spec/ENVELOPE.md):
accepted nonminimal widths/map orders do not authorize reserialization of signed
bytes. Writers use shortest integers/lengths and UTF-8 map-key order. A signature
or content ID covers H/C, not the outer array/bin markers. Never treat semantic
equality as signed-byte equality. Limits and staged parsing come from the
[resource profile](spec/RESOURCES.md).

## Lock

```text
Lock = [header_bytes: bin, packet: bin[73]]
LockHeader = [format_version: uint(1), vault_id: bin[16],
              verifying_key: bin[32], kdf: Kdf]
Kdf = [algorithm: uint(2), version: uint(19), memory_kib: uint(65536),
       passes: uint(3), lanes: uint(4), output_bytes: uint(32), salt: bin[16]]
```

`header_bytes` is the exact encoded LockHeader. It is public but untrusted until
lock authentication succeeds. The lock header is at most 256 bytes, depth 2,
and 16 MessagePack nodes. Its bin payloads are at most 32 bytes; it has no str or
map fields. The whole lock is at most 344 bytes, including the widest accepted
array/bin framing. Check the exact KDF tuple and budgets before doing KDF work.

P is the raw output of the [Argon2id profile](spec/KDF.md).
The decoded secret_key is the 32-byte hidden X25519 public key. Combine them using
the [lock HKDF construction](spec/CONSTRUCTION.md), not a PHC
password verifier. Use XChaCha20-Poly1305 with AAD equal to the exact lock AAD
domain followed by `header_bytes`. The packet is nonce[24] || ciphertext[33] ||
tag[16]. Plaintext is derivation_version[1]=01 followed by canonical clamped
X25519 private material[32]. The format version fixes this derivation and suite.

After AEAD verification, reject unsupported derivation versions/noncanonical
material. Recover both key pairs, compare the derived secret_key with the input
in constant time, and compare the derived Ed25519 public key with the authenticated
header value. Establish trust only through this successful opening or an existing
local pin; follow the [trust profile](spec/TRUST.md).
Never let an advertised server key alone create or replace trust.

Salt and nonce are fresh on creation and rewrapping. Each new wrapper protects
the same private material, secret_key, and Ed25519 key. It creates no Record event
and changes no revision, parents, signature, or records-list bytes. Core returns
a new wrapper; the application owns persistence/distribution. Failure preserves
the old wrapper. A saved old wrapper still works with its old credentials; a new
wrapper does not revoke old copies or compromised keys. V1 has only one allowed
KDF tuple, so it cannot demonstrate a change to an unsupported parameter profile.
Future readable-profile additions must preserve the same rewrapping semantics.

## Record revisions

```text
Envelope = [header_bytes: bin, ciphertext: bin, signature: bin[64]]
Header = [format_version: uint(2), vault_id: bin[16], record_id: bin[16],
          parents: array<bin[32]>, metadata: map, event_kind: uint(0|1)]
metadata = {"epoch": uint, "value_sizes": array<uint>}
```

The [Record profile](spec/RECORD.md) defines entries, unknown
fields, encrypted tags, exact value sizes, and one whole-content zlib stream.
Names, types, values, tags and URLs are encrypted. The compressed-content limit is 4,000,000 bytes inclusive;
the 48-byte HPKE overhead is additional. H is the original header byte string;
C is enc[32] || encrypted_compressed_content || AEAD_tag[16].

`epoch` is the revision modification time in Unix milliseconds, in `0..=u64::MAX`.
It is public and authenticated with H. Applications supply this time; it is not a
logical counter or proof of clock accuracy. Equal or decreasing times are valid.

Pass H as HPKE AAD. Sign the exact domain-separated, length-framed H/C input in
the [authentication profile](spec/ENVELOPE.md). Use
strict Ed25519 verification with an accepted vault anchor. Compute revision_id
from H/C using the [revision profile](spec/REVISIONS.md);
it is not a wire field and creates no encryption/hash self-reference.

Parents are unique, sorted raw IDs of revisions in the same vault/record.
Keep all independent branches. Missing referenced objects mean an incomplete
set; authenticated wrong IDs/scopes or known cycles are errors. A deletion is a
signed encrypted node with nonempty parents and empty entries/value_sizes.
It retains history; conflict resolution, restore, and physical GC are separate.

Opening order is bounded outer/header parsing, trusted signature and any expected
ID, HPKE/AAD authentication, bounded decompression/content parsing, structural
validation, then matching every original value span to public sizes. Do not
automatically run type/image/file decoders. See the resource profile for ceilings
and the required schema-boundary cases.

## Records-list

```text
RecordsList = [magic: str("confidex/records"), format_version: uint(2),
               vault_id: bin[16], revisions: array<bin(Envelope)>]
```

The lock is separate. Each revisions item contains one complete serialized
Envelope, retaining its original H/C bytes. An empty list is valid. The list has
no signature or completeness claim of its own. Its vault ID must match the
expected local vault and each authenticated revision header. Reject trailing
bytes, extra fields, unknown versions, malformed items, or a wrong vault.

List order is transport order, not revision chronology. Parents can arrive after
children. Validate each received signature even for duplicate delivery, then
deduplicate by computed ID and exact H/C identity without losing branches.
Outer reordering/framing does not alter a revision's identity. A list is not an
authenticated manifest; withholding an unreferenced branch cannot be detected.

Readers process this outer array incrementally, with the per-envelope limits,
512 MiB consumed-wire budget, 10,000-item budget (including duplicates), and
100,000-edge budget per operation. Do not decode an unbounded outer Value first.
Check a candidate update before committing storage state. Missing parents may
be retained as incomplete history and checked when they arrive. Application
storage/indexes and concurrent import transactions are outside the wire format.

## Security and compatibility

The [platform profile](spec/PLATFORM.md) supplies entropy,
owned-secret cleanup, constant-time scope, and platform limitations. The
[transfer-code profile](TRANSFER-CODE.md) fixes client
Base32 input; the [raw-key text profile](spec/SECRET_KEY.md)
documents only the low-level codec used by older construction fixtures.
The [leakage model](spec/LEAKAGE.md)
describes public exact lengths/counts, supplied history, conditional compression
attacks, and the plaintext local tag index. Tags are encrypted on the wire but an
authorized client stores tag → record ID locally for search. That index exposes
labels/associations, not encrypted values; labels can themselves be sensitive.
Locking does not erase this index. It is never sent to the server.

The separate [sync protocol and application](../../../apps/confidexsyncd/docs/SYNC.md) add server cursors, CAS,
local checkpoints and conflict UI; those are not fields or guarantees of these
wire objects. This format has no key recovery, key commitment, device registry
or authenticated freshness manifest. Do not infer completeness or freshness
from signatures, cursors or successful lock opening. All used HKDF outputs
use their specified Expand domain; no unused future subkeys are reserved.

## Compatible vectors

The [integrated fixture catalog](spec/VECTORS.md) defines
complete lock, revision, and records-list bytes, their positive/negative cases,
and native/WASM reproduction commands. Supplying profile tests cover additional
boundary cases. The main implementation must consume these unchanged vectors;
the fixture checker is not that production implementation.
