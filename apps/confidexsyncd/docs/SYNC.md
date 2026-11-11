# Synchronization architecture and recovery

This guide describes the implemented native/browser client and `confidexsyncd`.
The [REST contract](SYNC-API.md) owns wire formats, signatures, status codes and
request limits. The [client guide](../../confidex/README.md) owns
UI behavior and timers; the [daemon guide](../README.md) owns
configuration and deployment.

Syncd does not redirect `/` to an application hostname. The app can share its
origin with the API through deployment routing: send `/v1` and its children to
syncd, and the remaining app/assets paths to the app host. Standalone syncd
returns an empty 404 at `/`. See the daemon guide's
[shared-origin setup](CONFIGURATION.md#sharing-an-origin-with-the-app).

## Boundaries and identity

Clients create vaults, open locks, decrypt records and resolve conflicts. The
server stores encrypted objects, verifies signatures and orders accepted
revisions. It does not receive passwords, `secret_key`, complete transfer codes,
decrypted private keys or record plaintext. Backend S3 credentials are separate
operator credentials, not vault keys.

The public server address is UUIDv5 of the existing Ed25519 public key, as
specified in [the API](SYNC-API.md#identity-and-routes). The random wire
`vault_id` is a separate cryptographic scope. The server pins the full public
key and scope; matching only a UUID never authorizes replacing either one.
Changing a password preserves the keys, scope and public address.

The transfer code contains the client-held 32-byte secret and the public UUID,
with a checksum in the UUID version bits. Only the restored public UUID is
sent during bootstrap. See [TRANSFER-CODE.md](../../../crates/confidex-vault/docs/TRANSFER-CODE.md).
The secret's existing encryption and lock-protection roles do not change.

Reads need no password challenge or cookie. Knowing a UUID permits downloading
encrypted data, not decrypting it or signing writes. Public identifiers,
sizes, modification times and history links remain visible in object headers.
HTTP and HTTPS sync endpoints use the same object authentication; a network
observer cannot forge revisions or recover secret plaintext from sync traffic.
HTTP does expose traffic and public metadata and permits blocking, replay or
withholding. Neither transport nor signatures prove that a server supplied the
latest complete history. Browsers also enforce their own mixed-content rules.

## Implementation map

| File | Responsibility |
| --- | --- |
| [sync.rs](../../../crates/confidex-app/src/sync.rs) | Client bootstrap, lock checks, pull, branch reconciliation and push. |
| [vault.rs](../../../crates/confidex-ui/src/vault.rs) | Shared sync scheduling, progress, errors and explicit revision selection. |
| [storage contract](../../../crates/confidex-storage/README.md) | Atomic local objects, heads and sync checkpoint publication; native SQLite and browser IndexedDB adapters implement it. |
| [sync_transport.rs](../../confidex/src/sync_transport.rs), [storage.js](../../confidex/web/storage.js) | Native HTTP transport and browser Fetch transport. |
| [syncd lib.rs](../src/lib.rs) | Shared routing, framing, signature/scope/parent checks, API limits and responses. |
| [syncd storage.rs](../src/storage.rs) | Index/Blobs contracts, mirror policy, lock operations, cursor CAS and ordered pages. |
| [syncd native.rs](../src/native.rs) | SQLite/PostgreSQL index, POSIX/Git/S3 objects and bounded native HTTP dispatch. |
| [syncd cloudflare.rs](../src/cloudflare.rs) | Worker HTTP adapter, D1 primary-anchored sessions and S3 Fetch adapter. |
| [syncd s3.rs](../src/s3.rs) | S3 object paths and signed backend requests. |
| [config.rs](../src/config.rs), [main.rs](../src/main.rs) | Native configuration and process startup. |

Native starts one index and the configured object destinations. Worker requests
construct adapters from D1 bindings and configured S3 destinations. Both enter
the same protocol handler; the core crypto library has no server/storage or UI
dependency. There is no independent sync daemon required on the client device.

## What the server stores

The [SQL schema](../schema.sql) has two tables. Identifiers,
digests, keys and signatures are stored as text: UUIDs are canonical strings,
and binary fields use lowercase hexadecimal.

| Table / columns | Meaning |
| --- | --- |
| `sync_locks.id` | Public server UUID, primary key. |
| `vault_id`, `public_key` | Pinned 16-byte wire scope and 32-byte Ed25519 verification key. |
| `blob`, `signature`, `previous` | SHA-256 of the current wire lock, its detached sync signature and the previous digest covered by that signature; `previous` is empty for registration. |
| `cursor` | Number of accepted revisions for this vault, initially zero. |
| `commit_token` | Internal batch guard; allows history inserts only after their matching cursor CAS succeeds. It is not a client secret or authentication token. |
| `sync_records.lock_id` | Owning public server UUID, referencing `sync_locks.id`. |
| `sequence` | Per-vault contiguous server order, starting at one. |
| `revision`, `record_id` | 32-byte revision ID and 16-byte logical record ID. |
| `blob`, `size` | SHA-256 and byte length of the exact signed wire revision. |

History is unique on `(lock_id, revision)` and `(lock_id, sequence)`. There is
one index row per accepted revision, including edits and deletion events, not
one row per current logical record. Revision IDs and wire-object digests have
different hash inputs; do not substitute one for the other.

Object destinations store exact encrypted wire locks and signed encrypted
revisions. They do not store plaintext, client preferences or local head tables.
The detached lock signature and its `previous` context live in the SQL index,
not in the `.sealed` object. Old immutable lock objects can remain after a
replacement, but the index points only to the current lock.

For S3/R2, let `u` be the canonical UUID, `h` its hexadecimal text without
dashes and `d` the SHA-256 hex digest of the exact object bytes:

```text
h[0..2]/h[2..4]/u/locks/d.sealed              wire lock
h[0..2]/h[2..4]/u/d[0..2]/d[2..4]/d[4..]    wire revision
```

POSIX uses the digest as a filename; Git uses `refs/confidexsyncd/<digest>` to
retain a Git blob. Normal sync uses indexed keys, never an S3 LIST. The prefix
layout helps operators browse objects; it does not shard the SQL index.

## Server publication and failures

For registration, the server inspects the lock without running Argon2, verifies
its detached signature, computes the UUID and writes the lock to every object
destination. Only then can an index insert pin the identity. An identical
registration is idempotent; different data at that identity requires the signed
replacement operation.

For a record push, the server checks the supplied `base`, all signatures,
scope, duplicate IDs and parents. Parents must already exist or appear earlier
in that batch, and belong to the same logical record. It then stores every
object replica. One index transaction compares the cursor, appends all sequence
rows and advances the cursor. The commit token gates the inserts on the winning
CAS. Concurrent writers cannot publish against the same base.

SQLite uses an IMMEDIATE transaction, PostgreSQL a transaction, and D1 an atomic
batch. These transactions cover the index, not S3/POSIX/Git. A failed object
write prevents index publication. A failed CAS can leave unreferenced encrypted
objects; it does not publish part of the batch. A lost HTTP response leaves the
client uncertain, so the client reads history before another push.

Reads try configured mirrors in order and verify the returned digest, falling
back when a copy is missing or corrupt. Writes require every configured mirror,
not a majority. An unavailable mirror can therefore block writes while reads
continue from another copy. Acknowledged writes depend on the index and object
providers retaining their committed data.

HEAD needs one indexed lock lookup and no object read. Lock GET reads the current
index reference, then the immutable lock object. History GET captures the
vault's indexed cursor, selects sequence rows after the requested cursor up to
that bound, and reads a bounded page of referenced objects. Concurrent appends
appear on a later page/check; a response never substitutes bucket listing for
the accepted index order.

Lock replacement similarly writes all copies before comparing the old digest
in SQL. The detached signature covers the exact new lock and its previous
digest; the full pinned key and scope cannot change. Records and their cursor
are unaffected. This API is implemented, but the application does not yet have
a password-change command/UI or automatically replace its saved local wrapper
during record sync. An already unlocked client retains its keys; bootstrap on
a new device opens the server's current wrapper. Password changes do not revoke
old wrappers or stolen unlocked keys.

## Client synchronization cycle

The client keeps full encrypted reachable history locally in SQLite or
IndexedDB. Its public sync checkpoint contains the normalized server origin,
enabled flag, verified history cursor, remote heads and checked lock digest.
Local heads include unsent edits and can differ from those remote heads.

1. **Bootstrap a new device.** Validate the transfer code locally, GET the lock
   by its public UUID, verify the digest/signature/address, and open it with the
   password and secret. Check the recovered identity before creating a local
   vault. Then enable sync and pull history. No key/code/password is uploaded.
2. **Check for changes.** Automatic checks can use HEAD once a checked lock
   digest is cached. If both cursor and digest match, and local heads equal
   remote heads, return unchanged. A lower cursor is an integrity error. HEAD
   never advances a local cursor or publishes heads; it cannot prove freshness.
   Manual sync uses the full flow. See the client guide for scheduling/backoff.
3. **Authenticate the lock.** GET the current signed wrapper. For a local vault
   absent on the server, sign and POST its saved lock, then GET it again. Verify
   exact bytes, address, signature, pinned key and scope. Do not replace local
   keys with a server-supplied identity.
4. **Pull before pushing.** GET pages after the saved cursor. Verify framing,
   cursor increment, signatures, scope and all parents before accepting each
   page. Atomically commit its exact objects with the new checkpoint. Keep
   local heads unchanged until pagination is complete. An interrupted pull can
   resume from the last committed page; it is not a completed sync.
5. **Reconcile tips.** Select the maximal tips in the union of verified local
   and remote histories. Retire ancestors only; keep independent branches even
   when their content and dates match. Distinct signed revision IDs remain
   distinct. Publish tip changes with expected-tip and checkpoint comparisons,
   so another PID or browser transaction cannot silently overwrite a newer edit.
   Branching neither stops sync nor requires a new signature or a merge.
6. **Push missing history.** Walk local revisions absent from the remote graph
   with parents before children. Send bounded batches with the saved server
   cursor as `base`. On 409, pull again. On 413, split a batch using the reported
   limit; one revision must still fit. Network failures retain local changes.
7. **Confirm by pulling.** Check the acknowledgment's count and cursor, but do
   not publish the acknowledgment as a new local checkpoint. The next step
   pulls the accepted revisions and authenticates them. Continue while the
   report indicates more work; finish only after reconciliation and upload
   converge. A retry after a lost response discovers accepted revision IDs
   through this same pull, avoiding duplicate publication.

The client lists every non-deleted tip as a separate row and opens, searches,
edits, deletes and exports a specific `(record,revision)`. Editing an older open
draft after sync creates a child of its original revision and retains peer
branches. Deletion consumes only the selected current tip. A later independent
child remains a separate branch; a deletion does not erase its signed history.
Incoming sync preserves an open viewer or draft and reports changed revisions.
Cancel restores the editor's original content without replacing stored tips.

The protocol uses server sequence cursors for concurrency and client `epoch`
only for modification dates. It does not choose winners using device clocks.
Known parents and a contiguous cursor detect several incomplete/invalid
responses, but cannot establish unseen updates or rule out every valid rollback.

## Native directory adapter

`confidex_app::local_sync` exchanges signed objects through an existing directory
managed by the operating system. The local SQLite database stays on local disk;
the adapter does not put SQLite, plaintext records, passwords or secret keys in
the shared directory. WASM does not compile the filesystem adapter.

The directory format is versioned independently of the encrypted wire format:

```text
confidex-sync-v1/<public-sync-uuid-hex>/locks/<sha256>.<length>.lock
confidex-sync-v1/<public-sync-uuid-hex>/records/<sha256>.<length>.record
```

A record file is the exact signed encrypted wire revision. A lock file contains
the exact encrypted wrapper followed by its 64-byte Ed25519 sync signature with
an empty previous-digest context. Its SHA-256 and length cover that complete
file. Reading wrappers checks their signatures and public address before
returning encrypted locks for the application to open.

Writes use a new temporary file in the destination directory, synchronize its
contents, then rename it to the content-addressed name. Readers ignore temporary
files. A file shorter than its declared length is pending delivery; a complete
file with a bad digest or signature is an integrity error. Neither case replaces
local tips. Missing parents also defer incoming tip publication until a later
pass. Complete incoming history is authenticated before objects are staged and
tips are published with the same branch rules as HTTP sync. Existing signed
bytes remain unchanged, including equal-content branches and deletion events.

Each directory scan admits at most 100,000 entries; bootstrap accepts at most
16 lock wrappers, with the existing core graph and per-object limits. The adapter
checks cancellation between file and publication operations. Unavailable roots are reported without
creating a replacement directory. Filesystem calls still depend on the mounted
provider; completing a local copy does not prove delivery to another device or
the freshness of a new device's view. Directory permissions and the provider's
durability remain operating-system concerns.

In the native client, choose the folder in the vault settings. To connect another
device, choose **Open from folder** on the vault catalog, then enter the transfer
code and password. The client verifies signed wrappers before opening them and
preserves an existing local vault and its history. A folder may contain several
vaults, separated by their public sync addresses. The chosen root path is local
SQLite metadata; it is not uploaded or included in a portable vault backup.
Disabling the folder does not delete either local or shared data and works even
when the directory is unavailable.

An unlocked native vault uses the same foreground/background schedule and manual
sync action for both transports. A combined cycle copies the folder first, runs
HTTP sync to completion, then copies server changes back to the folder. Thus a
folder-only device can receive and send server history through a native bridge.
A failed transport does not disable the other one. Automatic availability failures
are quiet; manual failures and integrity/storage failures remain visible. Missing
parents or partly delivered files show a waiting state and are checked on the
next scheduled pass, without a busy retry loop. Incoming data does not replace
an open viewer or draft.

Cancel or lock requests stop queued work and are checked between file operations
and local publications. A filesystem call already waiting on an OS mount cannot
be interrupted by this cooperative cancellation. Completed immutable writes or
verified staged objects can remain after cancellation; retry completes the exchange.
A local success does not confirm that Dropbox, iCloud Drive, OneDrive or an SMB
peer has delivered every file. The protocol cannot detect files not yet visible,
prove global completeness or freshness, or exclude a rollback to valid old data.
Old authenticated lock wrappers can remain; folder sync does not implement
password changes or revocation of previously shared keys.

The directory protocol does not require a sync server, cloud-provider SDK or
technical merge revisions. It remains available in a native build with
`--no-default-features`; browser builds have no folder picker or filesystem adapter.

## Backup and restore

Object mirroring is not an index backup. Preserve both tables, including key
pins, detached lock signatures, previous digests, cursors and commit tokens,
together with all objects referenced by that index snapshot. A bucket alone
cannot reconstruct the accepted order and current signed lock response. The
daemon has no automatic index rebuild, backup scheduler, restore command,
garbage collector or replica repair loop.

### Create a recovery set

1. Fence writes on **every** entrypoint/instance using this index and drain
   in-flight requests. The daemon has no maintenance-mode setting; use the
   deployment's routing/process controls. Do not run concurrent cleanup or
   object lifecycle deletion during the backup.
2. Take a consistent index snapshot including schema and data. For SQLite use
   the [backup API](https://www.sqlite.org/backup.html) or a complete stopped
   database snapshot; copying only a live main file can omit WAL data. For
   PostgreSQL use its backup tooling, for example a consistent
   [pg_dump export](https://www.postgresql.org/docs/current/app-pgdump.html),
   including the required role/configuration recovery information separately.
   For D1 use a [remote SQL export](https://developers.cloudflare.com/d1/best-practices/import-export-data/)
   or supported platform recovery point. D1 recovery alone does not back up R2.
3. From that snapshot enumerate `sync_locks(id, blob)` and
   `sync_records(lock_id, blob, size)`. Derive keys with the current backend
   layout and copy all referenced encrypted objects to independent backup
   storage. At least one complete verified object set is needed. Retain old
   objects unless a separate retention policy authorizes their removal.
4. Re-read the backup objects and check SHA-256 against `blob`, and revision
   lengths against `size`. Record snapshot time, per-vault cursors, row/object
   counts, hashes, schema/release version and backend layout with the recovery
   set. Save deployment configuration and protected operator credential
   recovery separately; vault secrets are neither needed nor included.
5. Verify the index copy and its reference coverage, then remove the write
   fence. Keep backups independent of source deletion and credentials.

This is the conservative maintenance-window procedure. Immutable objects also
permit an online design: take a consistent index snapshot first, retain every
object it references, then copy and verify that set. Such orchestration is not
provided by syncd. Unrelated S3 and SQL snapshots taken at different times are
not automatically a complete recovery set.

### Restore and verify before cutover

1. Keep the live service fenced if it cannot safely serve writes. Restore into
   a **new isolated index and object destinations**, not over the only existing
   copy. Use the schema/layout version recorded with the backup. Do not reset
   UUIDs, key pins, sequences or cursors to make an import succeed.
2. Restore the index and objects, then populate and verify **every** configured
   mirror before enabling writes. A valid fallback copy alone does not repair
   missing mirrors. Preserve Git refs when recovering a Git destination.
3. Check database integrity/constraints and contiguous per-vault sequence rows.
   The following query must return no rows; run it in the isolated restore,
   where scanning the history cannot compete with production traffic:

   ```sql
   SELECT l.id
   FROM sync_locks l
   LEFT JOIN sync_records r ON r.lock_id = l.id
   GROUP BY l.id, l.cursor
   HAVING COUNT(r.sequence) <> l.cursor
      OR (l.cursor > 0 AND (MIN(r.sequence) <> 1 OR MAX(r.sequence) <> l.cursor));
   ```

4. Check all indexed objects' digests/lengths, not just a sample. Verify each
   current lock's address, scope and detached signature with `previous`; verify
   record signatures, IDs, scope and parent availability in sequence order.
   Public verification does not require decrypting records. The API can serve
   checked bytes, but there is no built-in full-store scrub command.
5. Test HEAD, lock GET and paginated history against the restored service. On a
   disposable copy, test independent client restore, push, stale-base rejection
   and independent branches using synthetic data. Test tooling can create vaults;
   do not point write tests at user data or the only recovery copy.
6. Compare recovery cursors with any surviving index/client checkpoints. A
   backup older than acknowledged writes is a rollback, even if all signatures
   verify. Preserve newer sources and recover their missing history through a
   separate recovery plan; do not silently clear client checkpoints or claim
   the backup is current. Fresh clients cannot independently prove freshness.
7. Switch routing only after verification and fence the previous writer before
   allowing new writes. Retain the previous data/configuration. Once new writes
   are accepted, switching back to an older index is another rollback, not a
   safe configuration-only undo.

The restore procedure is an operator runbook, not evidence that a production
restore drill has been performed. Rehearse it on disposable infrastructure and
measure recovery time before relying on it for a service-level objective.

## Maintenance and future sharding

Keep schema, object-layout and application deployments coordinated. The daemon
creates missing tables on native startup; that is not a general schema migration
framework. Existing object-layout migration steps are in the daemon guide.
Track history growth, index size, query latency, failed mirror writes, orphaned
objects, and backup/restore duration. Full history grows with revisions even
when the current record count is unchanged.

Future sharding is planned by backend/destination, including
another `confidexsyncd` as a destination with its own index and object storage.
Keep a whole vault in one shard to preserve cursor CAS and lock publication.
Distributing vaults among shards differs from mirroring objects within a shard.
The routing/expansion algorithm and migration protocol remain to be designed;
neither remote-syncd destinations nor shard routing are current configuration
options. Avoid forwarding cycles when designing remote destinations. No client
secret or additional crypto key is needed for this placement decision.

## Client tag index and disclosure

Revision/list format v2 stores tags inside encrypted Record content. The server
verifies public headers/signatures and cannot read or index tags. On pull the
unlocked client also authenticates/decompresses/decodes every revision and checks
value sizes before extracting tags. `sync_commit` publishes the derived index,
objects, heads and checkpoint in one transaction. A failure publishes none of
them. Deletion heads have no searchable tags; queries join revision-scoped tag
rows to current heads, so discarded conflict branches cannot become results.
Rebased local content keeps its encrypted tags. Identical-content comparison
includes tags; a tag-only change therefore remains a real conflict.

SQLite/IndexedDB keep a **plaintext tag → record ID index**. Local database/profile
or backup access reveals labels, links and indexed historical associations, not
record secret values or keys by itself. Labels may be sensitive. The index is
never uploaded; locking the UI does not erase it. Older public-tag revisions are
unsupported without migration; old disclosures/copies cannot be undone.
