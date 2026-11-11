# Vault signature trust

Each vault has one Ed25519 signing pair derived from its stored X25519 material.
Every accepted Record signature must verify under that vault's trusted public
key. There is no device-key registry, delegation, or device revocation in v1.
A verification key downloaded from a server or included with an object is only
an untrusted claim. A valid self-signature does not make the claim trusted.

## Establishing initial trust

At vault creation, derive the Ed25519 key from newly generated private material
and associate it with the newly generated vault ID. This is a local root.

At unlock, the user supplies password and client-held `secret_key`. Authenticate
the complete lock and its exact header with those inputs, validate the material,
and check the recomputed X25519 public key. Then derive the Ed25519 public key
from the recovered material and require exact equality with the public key in
the authenticated lock header. Only after all checks succeed may the application
record `(vault_id, Ed25519 public key)` as a trust anchor. The vault ID must come
from that same authenticated header. Never expose a partially verified anchor.

The integrated lock API parses the header and uses those exact fields for its
post-decryption checks. Some isolated construction tests supply header fields
separately; they exercise primitives, not an alternative application lock parser.

## Checking records without opening the lock

The caller supplies a previously established local pin, or a public key and vault
ID authenticated through an independent trusted channel. The core does not fetch,
trust-on-first-use, replace, or persist pins. Missing pins return an unknown-key
error, even if a server-supplied key verifies the signature. A changed advertised
key must not replace the pin automatically. A pin for another vault is rejected.

Pinned public-key bytes must decode as an accepted Ed25519 key, and weak keys are
rejected. Record verification uses the pinned key and the strict signature
profile. The signature covers the exact received signed bytes. The record's vault
ID is compared with the anchor's ID; it must also be part of those signed bytes.
The application supplies pins from its own trusted storage, not from the current
untrusted records-list or lock download. During new-device bootstrap the transfer
code supplies the expected public address. The application checks the downloaded
lock's address/signature and then opens it with password plus `secret_key`,
checking the recovered identity before trusting record signatures. A sync server
pins a lock's full public key/scope for write verification; this server-side
registration does not establish client-side trust in downloaded content.

No private key, password, or `secret_key` is needed for this public verification.
Successful public verification proves authorization by the pinned vault signing
key. It does not decrypt the record, prove plaintext validity, establish freshness,
or guarantee a complete server response. Without a pin and without unlocking,
the core can report parse results but cannot report a trusted signature.

The key is stable throughout a vault's life. Replacing the lock does not rotate
it. Imported pins and recovered material that disagree fail explicitly; there is
no silent key migration or server-driven reset. Revocation of disclosed material
requires a separate future operation.

Tests cover initial unlock, verification after discarding private material,
unknown keys, attacker signatures under another valid key, wrong vault IDs,
weak pins, changed advertised keys, and authenticated lock headers inconsistent
with the restored material. The full wire adapter must preserve this contract.
