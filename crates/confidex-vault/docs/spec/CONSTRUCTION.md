# Cryptographic construction v1

This profile fixes the cryptographic inputs and outputs used by the current
[portable format](../FORMAT.md). The shared core implements these primitives.
See the [envelope profile](ENVELOPE.md) for binding, signed bytes, and encoding,
the [trust profile](TRUST.md) for trusted verification keys, and the
[revision profile](REVISIONS.md) for IDs and graph rules. The
[Argon2id profile](KDF.md) supplies the production KDF parameters;
the [core APIs](../../README.md) implement the integrated
wire paths. The [resource profile](RESOURCES.md)
defines bounded parsing and decompression requirements.
Use synthetic data.

The [sync identity](../../../../apps/confidexsyncd/docs/SYNC-IDENTITY.md) uses the existing Ed25519 public key. It
adds no key and does not change this construction. The application transfer
code includes the original secret and that public address.

All labels below are ASCII bytes without a terminating NUL. `||` means byte
concatenation. HKDF uses SHA-256, both Extract and Expand, and a 32-byte output.
All lengths are bytes unless stated otherwise.

## Design rationale

The general idea of combining a password with a client-held secret was inspired
by [1Password](https://support.1password.com/secret-key-security/). The construction
specified here uses that second secret as an X25519 recipient key and derives a
separate Ed25519 signing seed from the private material. This describes the
project's design choices; it is not a claim of cryptographic novelty or an
independent security assessment.

```text
material --X25519--> secret_key ---------> HPKE encryption of records
secret_key + Argon2id(password, salt) --HKDF--> K_wrap
K_wrap + (version || material) --XChaCha20-Poly1305--> lock

material --HKDF, signing domain--> Ed25519 seed
seed --> signing key --> revision signatures
seed --> verification key --UUIDv5--> vault address
```

| Choice | Purpose | Consequence and limit |
| --- | --- | --- |
| Hidden X25519 public key as `secret_key` | Reuse the HPKE recipient key as the second lock input, without another random unlock secret. | It permits encryption, not decryption or signing. Disclosing it enables offline password guessing against a saved lock. Treat it as a client secret despite its mathematical public-key role. |
| Ed25519 seed derived through a separate HKDF domain | Publish a verification key for authorization without directly converting or publishing the X25519 recipient key. | Possessing `secret_key` does not authorize a revision. Verification still requires a trusted key established by opening the lock or an existing pin. |
| Replaceable lock around stable private material | Change password protection without rewriting records, signatures or the vault address. | Old locks remain usable. Rewrapping cannot revoke private material or provide forward secrecy. |
| Signatures on immutable revisions and their parent references | Let storage verify writes and clients verify supplied history without user accounts. | Signatures do not establish the freshness or completeness of server responses. IP addresses, timing and public metadata can still support correlation. |

The algorithms, domain labels and authenticated bytes below define the protocol.
These design reasons do not add guarantees beyond the
[security boundary](#security-boundary), [trust](TRUST.md) and
[leakage](LEAKAGE.md) profiles. In particular, keeping a recipient key out of
serialized objects is not a general HPKE anonymity proof.

### Connected checks during exchange

The client starts with its password, hidden `secret_key` and the expected
address from the transfer code. Opening authenticates the lock's exact header
and recovers material that must reproduce the supplied X25519 recipient key
and the header's Ed25519 verification key. The latter also determines the
expected sync address. A mismatch at any of these checks rejects the lock.

```text
password + secret_key --> authenticated lock opening --> material
material --X25519--> must match supplied secret_key
material --HKDF, Ed25519--> must match authenticated header key
header key --UUIDv5--> must match expected sync address
trusted key --> verifies signed lock updates and record revisions
revision signatures --> bind ciphertext, header and parent references
```

This connects local opening, public identity and object authorization. The
server pins the public verification key and vault scope; it can then verify
writes without the password, hidden recipient key or private material. Those
secrets stay on clients. The exchange uses encrypted objects, signatures and
public metadata, rather than transferring secrets to authorize requests.

The checks are not a circular proof of identity: the client's root of trust is
successful opening with its own secrets, or an existing authenticated pin. An
attacker's self-consistent key, address and signatures do not replace that root.
Server-side pinning does not establish client-side trust. These links prove
neither the freshness nor the completeness of the supplied revision history;
the [trust profile](TRUST.md) defines those boundaries.

## Vault material and signing key

Generate 32 bytes from a platform CSPRNG. Fail if entropy is unavailable. Clamp
once before storage: `material[0] &= 248` and
`material[31] = (material[31] & 127) | 64`. Store exactly these 32 bytes. Import
requires length 32 and those bit constraints; it rejects noncanonical material
instead of silently changing the input to the signing KDF.

Derivation version is the byte `01`. The lock plaintext is exactly
`01 || material`, length 33. Unsupported versions fail without a fallback.

```text
secret_key = X25519(material, basepoint=9)
signing_prk = HKDF-Extract("confidex/vault/extract/v1", material)
ed25519_seed = HKDF-Expand(signing_prk, "confidex/vault/ed25519/v1", 32)
```

`secret_key` is the canonical 32-byte little-endian X25519 public encoding. It
stays client-side. The [transfer-code profile](../TRANSFER-CODE.md)
defines current client display and normalization; the [raw codec](SECRET_KEY.md)
is retained for construction fixtures. KDF inputs use only the decoded 32-byte
secret, not UUID/checksum/text bytes. The Ed25519 signing key is constructed
from `ed25519_seed`. Its verification
key is public. Neither a converted curve point, the X25519 scalar as an Ed25519
scalar, nor a DH shared secret is used as the signing seed.

The clamped material is the only stored private key material. The original
unclamped entropy is discarded. Reopening the same material reconstructs both
pairs. The Ed25519 seed has a separate derivation domain; it is not another
interpretation of the X25519 scalar.

## Record encryption

Use RFC 9180 HPKE Base mode (`00`), with this fixed suite:

| Component | Algorithm | ID |
| --- | --- | --- |
| KEM | DHKEM(X25519, HKDF-SHA256) | `0020` |
| KDF | HKDF-SHA256 | `0001` |
| AEAD | ChaCha20Poly1305 | `0003` |

`info = "confidex/record/hpke/v1"`. There is no PSK and no HPKE sender identity.
The separate Ed25519 signature supplies authenticity under the signature
and trust profiles; HPKE Base alone does not identify the author.

The input plaintext is the already compressed whole Record content. The caller
provides exact authenticated envelope bytes as AAD. The field-binding and wire
profiles define these bytes unambiguously, including relevant identifiers,
parents, suite selection, and public metadata. Do not include a ciphertext hash
that depends on this same encryption. AAD never contains the hidden recipient
public key or other client secrets. AAD is authenticated as opaque bytes.

For each encryption, create a new ephemeral key pair and a fresh HPKE context.
Encrypt exactly one message at sequence number zero, then discard the context.
The chosen implementation draws 32 fresh entropy bytes and applies HPKE
`DeriveKeyPair` for the ephemeral pair. RFC 9180 defines the DH extraction, labeled
KDF, and 12-byte base nonce; the sequence-zero nonce is that base nonce. There is
no caller-supplied Record nonce. Never reuse an ephemeral input, including after
a failed write, process restart, retry, or revision edit.

The inner ciphertext packet is exactly `enc || ciphertext_and_tag`:

- `enc` is the 32-byte ephemeral X25519 public key.
- The ciphertext has the plaintext length followed by a 16-byte AEAD tag.
- Minimum packet length is 48. There is no recipient public key, separate nonce,
  or private material in the packet. The enclosing version selects this suite.

The HPKE library checks for an all-zero DH result and fails, on both encryption
and decryption. It implements RFC 7748 public-input decoding. Do not treat
alternative encodings of an ephemeral point as different cryptographic keys;
the signature/identity layer covers the exact received packet bytes.
Wrong AAD, wrong recipient, ciphertext/tag changes, and truncated packets fail.

HPKE was selected because it specifies the full hybrid composition and supports
AAD. There is no custom DH-to-AEAD key schedule. Algorithm substitution requires
a new suite/version, not an automatic fallback.

## Lock protection

First compute `P = Argon2id(password_bytes, salt, profile, output_length=32)`
with Argon2 version `0x13`, no optional secret and no optional associated data.
Use the raw key-derivation API, not a PHC password verifier. Passwords are exact
bytes; the core performs no trimming, case folding, or Unicode normalization.
Generate a fresh 16-byte public salt for each new wrapper. The production
creation profile and accepted limits are fixed by the linked Argon2id profile;
reject unsupported or over-budget parameters before starting Argon2.

```text
lock_prk = HKDF-Extract("confidex/lock/extract/v1", secret_key || P)
K_wrap = HKDF-Expand(lock_prk, "confidex/lock/wrap/v1", 32)
lock_aad = "confidex/lock/aad/v1" || exact_lock_header_bytes
```

Both KDF inputs are exactly 32 bytes, so the concatenation is unambiguous.
The constant salt is public domain separation, not another random secret.
Only the wrapping key is derived; unused authentication/tag keys are not reserved.

Encrypt the 33-byte lock plaintext with XChaCha20-Poly1305, a fresh random 24-byte
nonce, and `lock_aad`. Generate a fresh nonce on every wrap. The inner lock packet
is exactly `nonce[24] || ciphertext[33] || tag[16]`, length 73. Reject any other
length. The enclosing header must bind the vault identity, lock/suite version,
Argon2 version/profile/salt, and public verification key as exact AAD bytes. Their
field encoding is defined in [FORMAT.md](../FORMAT.md). Changing any header byte
invalidates the tag.

Opening authenticates the entire plaintext before parsing it, checks derivation
version and canonical material, then recomputes X25519 public and compares it
with the supplied `secret_key` in constant time. A valid AEAD tag alone does not
skip this correspondence check. The integrated lock implementation also compares the
derived Ed25519 public key with its authenticated header value. No key is returned
on any failure. Do not expose detailed unlock failure reasons to an untrusted
caller as an oracle.

Replacing the password/profile/salt/nonce changes only this wrapper. Both key
pairs and all existing Record packets stay unchanged. An old wrapper remains
usable with its old inputs; rewrapping is not revocation or rollback protection.

## Security boundary

The public transcript consists of headers, the two inner packets, public
verification keys, and signatures. It must never include `secret_key`, stored
material, signing seed, `P`, or `K_wrap`. In particular, do not copy the HPKE
recipient key into diagnostics, routing headers, AAD, or key identifiers.

With a server dump and a known password, an attacker can compute `P` but still
needs the hidden `secret_key` to derive `K_wrap`. A public Ed25519 verification
key does not provide the X25519 public key by curve conversion because its seed
comes from a separate HKDF derivation. This reasoning assumes the chosen
primitives and composition remain secure; passing vectors is not a proof of
recipient-key secrecy. No general HPKE anonymity guarantee is claimed.

With `secret_key` and the dump, password guesses can be tested offline against
the lock. There must be no separate password-only verifier or wrapper. Sharing
the X25519 recipient key with a sender also shares this second unlock factor;
it must not be treated as a publicly distributable address. Private-material
disclosure exposes all Records; this construction does not provide forward
secrecy. Ed25519 signatures alone do not establish which verification key to trust.

Key commitment, recovery wrappers, multi-party access, and server freshness are
outside this construction. XChaCha20-Poly1305 is not claimed to be key-committing.
Introducing multiple independent unwrap paths requires a separate review.

The low-level construction calls accept caller-provided entropy/nonce/KDF output.
They do not independently provide fallible platform CSPRNG integration, Argon2
budget checks or bounded wire parsing. The core's lock/envelope APIs add those
checks; use them for application wire objects. Neither layer promises end-to-end
erasure of every secret copy. The infallible HPKE
RNG trait must not be connected to an OS RNG by an adapter that panics on failure.
The envelope integration obtains entropy fallibly before entering that API.
`Zeroizing` protects owned buffers where used; it does not promise to erase all
compiler copies, dependency buffers, or browser memory. The test entropy source
and low-cost password profile must never be used for a real vault.

## Verification

Run `cargo test --locked -p confidex-vault` from the repository root. The tests
exercise lock authentication, signed envelopes, revisions, bounded parsing and
failure handling. [Public golden vectors](VECTORS.md) check wire compatibility.
This is not an independent cryptographic audit.

## References

- [RFC 7748: X25519](https://www.rfc-editor.org/rfc/rfc7748.html)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)
- [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)
- [Rust HPKE](https://docs.rs/hpke/0.15.1/hpke/)
- [RustCrypto Argon2](https://docs.rs/argon2/0.6.0/argon2/)
- [RustCrypto XChaCha20-Poly1305](https://docs.rs/chacha20poly1305/0.11.0/chacha20poly1305/)
- [Ed25519 Dalek](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/)
