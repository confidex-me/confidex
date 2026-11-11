# Transfer code

The cryptographic `secret_key` remains the hidden 32-byte X25519 public key.
The client displays a transfer code containing the original secret bytes followed
by the public UUID's 16 bytes in network byte order. The secret's X25519 encoding
is not converted:

```
secret_key[32] || UUIDv5(NAMESPACE_OID, Ed25519_public_key[32])[16]
```

The namespace is `6ba7b812-9dad-11d1-80b4-00c04fd430c8`. The Ed25519 key already
exists in the open lock header. No new key is generated. The server computes
this ID from the header, verifies the existing detached lock signature, and
pins the complete key and wire scope. See [the HTTP contract](../../../apps/confidexsyncd/docs/SYNC-API.md).

Before encoding, compute SHA-256 over
`ASCII("confidex/transfer-code/checksum/v1") || 00 || canonical_code[48]`.
The canonical bytes contain an ordinary version-5 UUID. Replace the high nibble
of code byte 38 (UUID byte 6, normally `5`) with the high nibble of the hash.
The decoder extracts that checksum, restores `5`, and hashes the canonical bytes
again. A four-bit checksum detects some typing errors; about 1 in 16 random
errors can pass. It provides no authorization or authentication.

Encode these 48 bytes with RFC 4648 Base32, without `=` padding: 77 symbols,
formatted as 11 groups of 7, separated by 10 dashes. The last symbol contains
four data bits and one zero padding bit. Reject a nonzero padding bit, an invalid
UUID variant, malformed separators, wrong lengths, or checksum mismatch.
Input is ASCII case-insensitive and can omit every dash. Only outer ASCII
whitespace is trimmed. Input over 128 bytes is rejected before decoding.
The client has no fallback for the previous 52-symbol secret encoding.

For the synthetic inputs secret=`00` repeated 32 times and Ed25519 public bytes
`01` repeated 32 times, the UUID is `0d24b0ab-60ef-5dc2-841b-19bf1696615d` and
the code is:

```
AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAA2JFQ-VNQO6TO-CQQNRTP-YWSZQV2
```

Bootstrap extracts the public UUID locally, fetches the signed encrypted lock,
checks its ID and signature, then opens it with the password and original secret.
The recovered Ed25519 key must give the same UUID. A public header alone cannot
establish trust. Password changes preserve the key, UUID, and transfer code.

Never transmit the secret, full transfer code, password, or plaintext to the
server, external services, logs, telemetry, or diagnostics. Only the restored
public UUID, public protocol metadata and encrypted, signed objects cross the
sync boundary. Possession
of a code permits fetching encrypted data and offline password guessing; it
does not permit decrypting or signing changes without opening the lock.
