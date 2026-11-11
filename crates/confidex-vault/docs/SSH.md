# SSH key values

`ssh/v1` stores `private_key: bin`, containing the unencrypted binary OpenSSH
private-key format inside the encrypted Record. Unknown value fields survive
edits. `Entry::validate_value` checks binary storage shape and the 65,536-byte
ceiling only. Call `ssh::Key::from_value(value, budget)` to validate the key;
Record reading never imports, decrypts, or signs with an SSH key automatically.

`Key::import(pem_bytes, passphrase, budget)` accepts OpenSSH PEM for Ed25519 and
ECDSA P-256, and unencrypted Ed25519 PKCS#8 PEM. PKCS#8 decoding uses the existing
RustCrypto ed25519-dalek parser and normalizes to the same binary OpenSSH identity.
The pinned pure Rust ssh-key 0.7.0-rc.11 parser handles OpenSSH framing,
padding and key material; no custom PEM parser is used. RSA, encrypted PKCS#8,
PKCS#8 for other algorithms, FIDO keys and other curves are outside this profile. RSA cryptography is disabled
in this initial algorithm profile. The newer
[rsa 0.10.0-rc.22 release](https://github.com/RustCrypto/RSA/blob/v0.10.0-rc.22/README.md)
reports side-channel fixes and a separate opt-in warning for PKCS#1 v1.5;
older advisories must not be used to claim that every published version lacks fixes.
Unsupported key material can still be retained as opaque encrypted file data.

Encrypted imports support AES-256-CTR with bcrypt-pbkdf, salt 1–64 bytes and
rounds 1–64. The key algorithm and KDF limits are checked before deriving an
import key. Missing/wrong passphrases produce explicit errors. Passphrases are
borrowed, capped at 4,096 bytes, and not stored. `to_value` writes an unencrypted
binary key for protection by Record encryption; it does not preserve the source
passphrase wrapper or write a plaintext file. Import and stored-key loading require
8 MiB of admitted working memory within the core's 192 MiB maximum. Input caps
bound parser allocations, including prefixed data; no RSA big-integer work occurs.

Validation signs and verifies a fixed domain-specific challenge to check that the
public and private components match. `public_blob()` and `fingerprint()` expose
the SSH public key and SHA-256 fingerprint. `sign(message)` accepts at most
32,768 bytes and returns the SSH algorithm-prefixed signature blob, verifying it
against the public key before returning. `verify` checks bounded key/signature
blobs, exact signature consumption and the same algorithm profile. These are raw
SSH signatures, independently of the vault's Ed25519 signing key and wire format.

Key omits Debug/Clone; dependency private components clear on drop. Encoded key
and signature buffers use zeroizing wrappers. Callers own any values they copy,
input PEM, passphrases, and the lifetime of decrypted Records. These guarantees
do not remove all compiler/dependency copies, pin all pages, or prevent process
memory inspection. Import validation alone does not grant permission to use a
key through an agent. The separate [native agent](../../confidex-ssh-agent/README.md)
requires an explicit approval callback for every signing request.
