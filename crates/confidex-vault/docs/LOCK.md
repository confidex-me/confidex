# Vault lock API

`lock::create(password_bytes, memory_budget)` generates fresh private material,
vault ID, salt, and nonce. It returns `CreatedVault { lock, vault }`. Save the
public lock separately from the records-list. Obtain the client-held secret_key
through `vault.keys().secret_key()` and use `transfer_code::encode(secret, public_key)`
for its Base32 display with the public sync address. Keep that code outside server objects; it is required even when
the password is known. The application must reject an accidental vault-ID
collision rather than combine unrelated vaults.

`lock::open(wire, password_bytes, decoded_secret_key, memory_budget)` accepts a
decoded 32-byte secret_key. Decode client input with `transfer_code::decode` and
pass its `secret` field. Check its public `id` against the authenticated Ed25519
key after opening. The client accepts only the new transfer-code format.
Passwords are raw bytes with no normalization, including empty passwords and
embedded NUL. The application chooses its password policy. The fixed format
ceiling is 4,096 password bytes.

Opening bounds the complete lock (344 bytes) and Header (256 bytes), validates
the exact schema, version, and fixed KDF tuple, then admits and runs Argon2id.
It authenticates the original header as AAD, checks the private-material version
and clamping, and compares the derived X25519 public key with secret_key in
constant time. The recovered Ed25519 public key must match the authenticated
header before `OpenedVault` and its trust anchor are returned. An advertised
server key alone cannot construct this context. Use `vault.keys()` and
`vault.anchor()` with the envelope API.

The required Argon2 budget is `kdf::REQUIRED_MEMORY` (68 MiB); lock calls reject
budgets above the common 192 MiB operation ceiling. Unsupported or oversized KDF
requests and insufficient budgets fail before KDF allocation. Entropy failure
stops creation without a fallback. All inputs are borrowed; failure does not
replace stored data. Persistence, concurrency, secret-key caching, and automatic
locking belong to the application. The context omits Debug/Clone; dropping it
clears the private key material through its zeroizing owners. Password and key
buffers supplied by the caller remain the caller's responsibility. No claim is
made about all compiler/dependency copies or physical erasure of persisted data.

`vault.rewrap(new_password_bytes, memory_budget)` returns a fresh lock around the
same private material, vault ID, Ed25519 pair and secret_key. It admits password
length/KDF budget before requesting fresh salt and nonce, then uses the current
creation KDF profile. The fixed version-one profile has one admitted KDF tuple;
other settings require an explicitly supported profile migration, not arbitrary
caller-supplied work factors. Rewrapping borrows the context and never changes
an existing lock, Record, revision ID, signature, parents or records-list.

Save the new lock atomically at the application boundary after success. Errors
leave the original context and any old wrapper usable. Old copies remain valid
with their old password and secret_key; a client need not fetch a new wrapper
to read or create Records. This operation does not revoke compromised keys or
previously disclosed data. Reauthentication and confirmation are application
policy: the API already holds an authenticated, opened vault.

The [format specification](FORMAT.md) and [two-secret construction](spec/CONSTRUCTION.md)
remain authoritative. These calls neither publish secret_key nor create a
password-only verifier. Recovery remains deferred;
changing a wrapper cannot revoke existing copies or compromised vault keys.
