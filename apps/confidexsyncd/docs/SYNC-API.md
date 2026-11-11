# Synchronization REST API

`confidexsyncd` stores client-created encrypted locks and signed record revisions.
It accepts a lock before any records and pins its public Ed25519 verification key.
Passwords, `secret_key`, private keys and plaintext records stay on clients.
The same protocol runs as a native Rust binary and a Cloudflare Worker.
See [SYNC.md](SYNC.md) for the client/server flow, implementation map, exact
server data model and backup/restore procedure. This document defines the wire
API; the [client guide](../../confidex/README.md#synchronization) defines current
UI and scheduling behavior.

GET and HEAD `/` return an empty `404` with `Cache-Control: no-store`, without
a `Location` header or storage access. The daemon does not prescribe an app
hostname. A deployment can serve the app at `/` on the same origin by routing
`/v1` and its children to syncd and other paths to the app host.

GET `/v1` serves Swagger UI. GET `/v1/openapi.json` serves the OpenAPI 3.1
specification. Both routes support HEAD and work without an available index
or object backend. Swagger UI assets are embedded and served from the same
origin. External validation is disabled, and the page's content policy blocks
connections to other origins.

The HTTP API permits cross-origin requests from any origin. All response
headers are exposed, including `ETag` and `Sync-Max-Body-Bytes`. OPTIONS returns
204 before accessing the index or objects and permits GET, HEAD, POST, PUT,
PATCH, DELETE and OPTIONS with any request headers, including Authorization.
Unsupported API methods still return 405. Clients use requests without cookies
or credentialed CORS. Signatures and all protocol checks remain required.

## Identity and routes

The server computes `id = UUIDv5(NAMESPACE_OID, public_key_bytes)`, using the
32 raw Ed25519 public-key bytes as the name. The namespace is
`6ba7b812-9dad-11d1-80b4-00c04fd430c8`. A changed password preserves the key and
this identifier. UUIDv5 is the namespace/name algorithm; UUIDv7 includes time.
See [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html#section-5.5).

The existing random `vault_id` in the encrypted-object format is a separate
scope field. It does not determine server identity. Each received revision must
match the scope of the accepted lock. A stored key cannot be replaced by a
different key that claims the same UUID.

| Method | Path | Operation |
| --- | --- | --- |
| POST | `/v1/sync` | Accept a signed lock and return its computed ID |
| GET | `/v1/sync/{id}` | Read the lock and its signature |
| HEAD | `/v1/sync/{id}` | Check the history cursor and lock digest without reading S3 |
| PUT | `/v1/sync/{id}` | Replace the lock under the same pinned key |
| POST | `/v1/sync/{id}/records` | Append a batch of signed revisions |
| GET | `/v1/sync/{id}/records?after={cursor}` | Read a page of revision history |

There is no operation that generates a vault on the server. Reads return
encrypted objects without a password challenge. Clients still authenticate and
decrypt the objects with their own trusted keys; an ID is not a secret.

HEAD returns an empty body, the lock's current `ETag`, and `Sync-Cursor` as a
decimal string, with `Cache-Control: no-store`. It needs one indexed lookup and
does not read an object backend. Polling must compare both values: the lock
ETag alone does not change when records are appended. These headers are advisory;
clients never advance a local cursor or publish heads from them. Changed data
still goes through the full signature, scope and history checks. A checkpoint
does not prove freshness against a server or network that hides updates.

## Lock upload

POST accepts `multipart/form-data` with exactly two binary parts:

| Name | Bytes |
| --- | --- |
| `lock` | The complete existing wire lock |
| `signature` | A detached 64-byte Ed25519 signature |

The signature covers this concatenation, where lengths are unsigned 64-bit
integers in network byte order:

```text
ASCII("confidex/sync/lock/v1") || 0x00
|| length(previous) || previous
|| length(lock) || lock
```

For POST, `previous` is empty. The lock's original bytes are signed, including
the public header and encrypted packet. No field is reserialized. This detached
transport signature does not change the existing lock format in [FORMAT.md](../../../crates/confidex-vault/docs/FORMAT.md).

The server checks the lock framing and supported KDF profile without running
Argon2, rejects invalid or weak verification keys, and verifies the signature.
It then writes every object replica before inserting the pinned key and object
reference into the index. A successful first upload returns `201`:

```json
{"id":"b20ee961-bda5-59e8-a3bd-8a4def1d14f8"}
```

The response includes a strong `ETag`: the quoted lowercase SHA-256 hex digest
of the wire lock. An identical POST is an idempotent `200`. A different lock
under an existing identity returns `409`; use PUT to replace it.

GET returns multipart parts `lock`, `signature` and `base`, plus the current
`ETag`. `base` contains the `previous` bytes used for the stored signature.

## Lock replacement

PUT accepts the same two upload parts and requires `If-Match` with the current
lock ETag. The signature's `previous` is that ETag's 64 hexadecimal characters,
without quotes. This binds the replacement to the version it replaces and
prevents replay of an earlier signed lock against a newer version.

The verification key and wire `vault_id` must remain equal to the pinned values.
All replicas are written before an atomic index update compares the old digest.
Success returns `200`, the ID and the new ETag. A missing or stale `If-Match`
returns `412`. The record history and cursor do not change. Conditional request
semantics follow [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.1).

## Record batches

POST accepts ordinary [multipart/form-data](https://www.rfc-editor.org/rfc/rfc7578.html):

| Name | Content |
| --- | --- |
| `base` | One decimal server cursor, starting at `0` |
| `record` | Repeated binary parts, each an unchanged signed wire revision |

The complete upload body, including multipart boundaries and part headers, is
limited to **8,000,000 bytes by default**. Set `limits.body_bytes` in TOML or
`LIMITS_BODY_BYTES` in the environment to a value from 1 to 8,000,000 bytes.
An oversized upload returns `413` with `Sync-Max-Body-Bytes` containing the
configured decimal byte limit. A client can split the batch and retry; a single
record must fit with its multipart framing. The maximum wire record is
4,065,668 bytes, so a lower upload limit can exclude otherwise valid records.
The receiver counts actual bytes and does not
trust `Content-Length`. Content encodings are not accepted. There may be up to
256 revisions and 256 parent references in one request. These bounds also keep
the number of index operations finite in Workers.

The lock must already exist. Each revision is checked with its pinned key using
the existing strict verifier and format limits. Its vault scope must match.
Parents must already exist or precede their children in the same batch, and must
belong to the same record. Duplicate revisions are rejected. Signed deletions
are normal revisions and do not remove stored history.

Parallel branches of one record are valid, including branches uploaded in
separate batches. Parents need not be current heads. The service stores and
returns every accepted revision without selecting a winning branch or requiring
a merge. After a stale base, pull history and retry only missing revisions with
the updated cursor. The legacy `merge_required` error code does not require
creating a merge revision. Clients must support multiple heads to read these
histories; older clients may reject them.

After all revisions pass verification, the service writes their replicas. One
index transaction then compares `base`, appends all history references, and
advances the cursor. Another writer cannot publish against the same stale base.
A failed check or transaction never publishes a partial batch.

```json
{"cursor":"42","accepted":3}
```

The cursor is a per-lock server sequence, independent of revision IDs and client
timestamps. An outdated base returns `409`. After a lost response, read history
and compare revision IDs before retrying; a repeated batch does not append
duplicates. There is no separate request-id cache.

GET reads after the given cursor; omitting it is equivalent to `after=0`.
Each page contains at most 16 revisions to bound object-store subrequests on
Workers Free. Bundled clients use upload batches of at most eight revisions;
the protocol upload ceiling remains 256.
The response is multipart: first `meta`, containing JSON, then repeated binary
`record` parts. Download pages fit within 8,000,000 bytes. The configurable
upload limit does not reduce download pages.

```json
{"cursor":"42","has_more":true}
```

Use the returned cursor for the next page. Record bytes and signatures are
preserved exactly. The client checks them independently. Server cursors and
valid signatures do not prove freshness or rule out a complete server rollback.

## Errors and persistence

Shared protocol errors have JSON bodies such as `{"error":"merge_required"}`.
The native HTTP adapter can return plain text for admission rejection (`busy`)
or a request-body timeout (`request_timeout`); clients must also handle errors
from the deployment proxy without depending on a JSON body.

| Status | Meaning |
| --- | --- |
| 400 | Invalid multipart, cursor, fields or content encoding |
| 403 | Invalid lock signature or attempted key/scope replacement |
| 404 | Unknown route or lock |
| 405 | Unsupported method |
| 408 | Native request-body deadline exceeded |
| 409 | Stale push base, duplicate revision or conflicting initial lock |
| 412 | Missing or stale lock replacement condition |
| 413 | Body, part count or parent count exceeds its limit |
| 422 | Invalid lock profile, revision, signature, scope or parent reference |
| 503 | Index or object destination is unavailable, or native admission is full |

Object destinations store immutable objects addressed by the SHA-256 digest of
their exact bytes. Native deployments can mirror any number and combination of
POSIX filesystem, Git and S3 destinations. Workers can mirror several S3
destinations. Reads try available copies and check their digest. Writes require
all configured copies before publishing in the index.

SQLite or PostgreSQL supplies the native index. Cloudflare D1 supplies the
Worker index. The index stores public keys, lock references and signatures,
history references, and the CAS cursor. D1 publishes each batch in one atomic
batch transaction. A commit token gates each inserted history row on the
successful cursor update.

An interrupted write or failed CAS can leave unreferenced objects in destinations.
Garbage collection and automatic replica repair are not implemented. Preserve
the index separately for server restoration; replication of object bytes does
not back up the index. Setup and configuration are in the
[daemon guide](../README.md).

Record envelopes and transfer lists use format v2; old public-tag revisions are
rejected. Tags are encrypted content and never enter the server index. Public
revision metadata contains exactly `epoch` and `value_sizes`; IDs, parents and
event kind also remain public. Lock format and sync addressing stay unchanged.
The client's plaintext tag index and its local disclosure risk are described in
[the sync design](SYNC.md#client-tag-index-and-disclosure).
