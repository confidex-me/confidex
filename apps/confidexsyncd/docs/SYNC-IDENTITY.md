# Vault sync identity

The production identity and transfer code are specified in
[TRANSFER-CODE.md](../../../crates/confidex-vault/docs/TRANSFER-CODE.md).
The server derives UUIDv5 from the existing Ed25519 public key, not from
secret_key. The transfer code contains the original 32-byte secret and public
UUID, with a four-bit checksum in place of the UUID version nibble.

The executable checks in [transfer-code tests](../../../crates/confidex-vault/tests/transfer_code.rs)
compare the shared implementation with the standard UUID implementation and
check the existing lock-signature transcript. No registration key is added.
