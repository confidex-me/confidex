# Public data and residual leakage

This profile describes the existing format. It retains whole-content zlib
compression and exact public per-value sizes. Encryption authenticates public
fields but does not hide them. It does not promise metadata confidentiality,
traffic-analysis resistance, or protection against every compression side channel.

## Observation model

A passive observer has exported envelopes or a storage dump, including their
open headers, ciphertext, signatures, and advertised vault verification key.
An observer of successive versions can compare them. A transport/storage observer
can additionally know arrival times, access patterns, object counts, and transport
sizes from that environment; access logs are not Record fields. The public
`epoch` field separately discloses the client-supplied modification time in Unix
milliseconds. It does not prove when the modification actually occurred.
Neither observer is assumed to know the private vault material or secret_key.
The separate key-construction profile describes password-guessing assumptions.

| Directly observable | Consequence |
| --- | --- |
| Version, vault ID, record ID | Suite choice and linkage of revisions to a vault/record |
| Parent IDs and revision IDs | The supplied history graph, branches and merges; equality of byte objects |
| Event kind | Which supplied events are deletions |
| Epoch | Client-supplied modification time with millisecond precision, including time differences between revisions |
| Ordered value-size vector | Exact encoded byte length of each value map and its position in this revision |
| Length of that vector | Exact entry count, including increases/decreases between observed revisions |
| Ciphertext length | Exact compressed-content length after subtracting the fixed 48-byte HPKE overhead |
| Repeated observations | Which public fields, sizes, counts, and ciphertext bytes changed |

Tags, entry names, type identifiers, URLs, and value bytes remain encrypted. A deletion has
empty entries/sizes under the format and does not erase earlier observations.
Its ancestors remain stored until a separate reclamation policy removes them;
removal cannot erase copies already held by an observer.

The vector exposes positions, not stable entry IDs. Equal sizes or repeated
positions across revisions do not prove that the same logical entry persisted.
Reordering or independent edits can give the same vector. A changed ciphertext
does not alone prove a changed plaintext: fresh randomized encryption can change
the bytes of identical content. Revision IDs identify authenticated byte objects,
not deterministic plaintext fingerprints. The graph does not prove freshness or
completeness of a server response.

## Local tag-index disclosure

An authorized client decrypts verified records and writes a **plaintext local
index of tag → record ID** to SQLite or IndexedDB for indexing and search.
Reading that database, a backup, or an exported browser profile can reveal tag
names, record associations, and grouping, including indexed historical revisions.
Tag names can themselves contain sensitive information. This index alone does
not disclose encrypted record values or supply decryption/signing keys.

The index is derived client data; it is never sent to the sync server. Encrypting
tags in revision content protects the wire/server copy, not the authorized
client's index. Locking the UI clears its decrypted session but does not erase
the persistent index or copies of it. Previously published public tags cannot
be made unknown retroactively.

## Inference and limits

Sizes, update patterns, and compressibility may support guesses
about record types or candidate contents, especially with outside knowledge.
They do not reliably classify every password, card, document, or photo. A small
candidate set or known schema can make inference much stronger than an isolated
size measurement. Direct disclosure of a count/length must not be confused with
recovery of secret values or a proof that encryption has failed.

Let S be the sum of public value sizes and Z = ciphertext length minus 48.
S omits entry wrappers, names, types, the Record map, and encrypted extension
fields outside values. Thus S/Z is not the exact compression ratio of the whole
content and cannot isolate the compressed contribution of one value. Compression
can match across values and other content. Already compressed media may have
limited further savings; that is not a universal zero-savings guarantee.

Exact encoded lengths also depend on UTF-8 and MessagePack length markers and
accepted width encodings, not just the number of user-visible characters.

## Adaptive compression attacks

An adaptive attacker needs a path that repeatedly causes chosen probe bytes to
be compressed in a shared context with a target secret, observes corresponding
output lengths with enough precision, and adjusts the next probe from previous
results. A reasonably stable target/context and enough queries can make this a
secret-recovery channel. A static dump alone does not supply that chosen-input
oracle. A single attacker-controlled field alone does not prove an exploitable
recovery attack either; reachability and useful feedback must be established.

Possible paths include repeated imports or application-driven updates that copy
untrusted data into a Record containing secrets, followed by observable exports
or storage writes. Such paths can exist without synchronization. An attacker
who can only replace ciphertext cannot bypass trusted signatures and HPKE AAD to
insert probes into existing plaintext; the application must legitimately create
the revised encrypted objects for the oracle to operate. An unlocked-client
compromise that already reads secrets is a broader threat.

Fresh HPKE encapsulation, a new nonce, and a new signature do not hide length.
Public value sizes give additional observations but are not required for a
compression-length oracle. This is an application of the attack class described
in [RFC 7457 section 2.6](https://www.rfc-editor.org/rfc/rfc7457.html#section-2.6)
and the authors' [BREACH description](https://www.breachattack.com/); it is not a
claim that this prototype reproduces their HTTP exploit or query counts.

## Possible measures and their costs

| Measure | Benefit and limits | Cost / compatibility |
| --- | --- | --- |
| Restrict automatic updates/imports from untrusted sources | Reduces chosen-probe paths; cannot remove passive size leakage or guarantee safety of all caller workflows | Application policy and interaction cost; compatible with the current wire format |
| Put untrusted inputs in a separate Record | Separates compression contexts across those Records; public sizes/history still leak and later recombination restores the risk | Application data-model change; no change to compression within each Record |
| Rate-limit or require explicit approval for repeated transformations | Raises the cost of an adaptive oracle; repeated legitimate operations and passive observations remain possible | Application UX/state; no cryptographic guarantee |
| Pad after compression to buckets | Coarsens ciphertext lengths within buckets; boundaries, public exact sizes, and adaptive probing still leak | More bytes and new authenticated padding/framing rules; format decision required |
| Random padding | Adds measurement noise; repeated observations can reduce its benefit | Bandwidth/storage and authenticated framing changes; not a complete defense |
| Disable or partition compression within a Record | Removes or separates the shared compression context; direct exact-size metadata remains public | Lost compression savings and changed compression/layout rules; format decision required |
| Replace exact public sizes/counts with hidden or coarser metadata | Reduces direct metadata leakage; ciphertext/history still need separate treatment | Changes an accepted public-size requirement and consumer behavior; user decision required |

No such size-hiding measure is silently enabled. Padding before
compression can itself be compressed and does not automatically hide length.
An application must not advertise that encrypting these records hides entry
counts, exact value lengths, or the supplied revision graph.
