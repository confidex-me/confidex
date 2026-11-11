# Integrated format vectors

These synthetic vectors implement the [integrated specification](../FORMAT.md)
using the already selected profiles. Every key, password, nonce, and private
material in this directory is a public fixture. Never use it for a real vault.

`vectors.hex` is a sorted list of `name=lowercase_hex` byte strings. It includes:

| Names | Meaning |
| --- | --- |
| `lock_plaintext`, `secret_key`, `signing_seed`, `verifying_key`, `secret_key_text` | Private-material payload and derived/displayed keys |
| `password_0/1`, `p_0/1`, `lock_0/1` | Original and replacement protection of the same vault keys |
| `revision_0/1/2/3/4` | First content, left edit, independent right edit, merge, deletion |
| `revision_id_0/1/2/3/4` | SHA-256 references computed from those original H/C bytes |
| `records_list` | The five complete serialized envelopes in one transfer container |
| `empty_list` | Valid empty container |
| `negative_list_version` | Unsupported list version |
| `negative_record_version`, `negative_lock_version`, `negative_kdf` | Unsupported Record/lock versions and overflow-sized KDF request |
| `negative_signature` | One changed signature byte |
| `negative_resigned_header` | Changed epoch with a valid new Ed25519 signature and unchanged ciphertext; HPKE fails |
| `negative_sizes` | Valid signature and AEAD, but public value sizes overstate actual spans; the final size check fails |

`secret_key_text` is the raw 32-byte construction-fixture codec. It is not the
application's current [transfer code](../TRANSFER-CODE.md),
which also contains the public sync UUID and checksum. Retaining these primitive
fixtures does not enable the old text format in client create/unlock/import.

The canonical material comes from bytes 0 through 31 followed by clamping. Salts
are repeated bytes 10/11; lock nonces are repeated bytes 20/21. HPKE fixtures use
one known 32-byte entropy block filled with 30 through 34, and 35 for the invalid
size fixture. These are deterministic test inputs, not a random generator.
Each revision's public epoch is 1,794,096,000,000 plus its entropy byte, in Unix
milliseconds. Revision/list format v2 moves `fixture` tags into encrypted content;
public metadata has only epoch and value sizes. Negative record/list version
fixtures now contain the rejected old version 1. Lock format/key fixtures stay
unchanged. Revisions, IDs, signatures and list fixtures change with the new
schema and encrypted content. There is no legacy revision fallback.
The Record content has repeated names, UTF-8 text, binary bytes, an opaque ext
payload, and an unknown Record field. Entry schemas are explicitly example types;
this fixture does not choose the application's standard type schemas.

## Run the checks

The golden data is in [`tests/fixtures/vectors.hex`](../../../../tests/fixtures/vectors.hex)
at the repository root. Core integration tests read the lock, envelope, revision
and list fixtures; sync server tests use the same signed objects.

```sh
cargo test --locked -p confidex-vault
cargo test --locked -p confidexsyncd
```

Never replace golden bytes automatically when a test fails. Review the cause
and format compatibility first. The vectors are public test data, not secrets
or an independent proof of cryptographic correctness.
