# Vault ZIP backups

Vault settings offer **Back up vault**. Before export, choose **Sync and back up**
or **Back up offline**. Sync must finish all pages before export. A network error
leaves the offline action available. Conflicts use the existing resolution flow.
A backup includes all locally stored encrypted revisions, including deletion events,
old revisions and retained branches. It cannot include data that this device has
never downloaded. Saving the ZIP is a separate explicit action. Native saves use
an atomic file replacement; browsers report that a download has started, because
they cannot confirm that the file reached disk.

On the vault selection screen, **Open a vault from the server** and **Import vault
from ZIP** share an adaptive grid below **Create vault**. ZIP import works without
a server. The first step reads ZIP metadata and extracts only the encrypted lock.
The password and complete `secret_key` transfer code are then required. Only after
the lock opens does the client extract and authenticate the remaining content.
No archive paths are extracted to the filesystem.

Every revision must pass its blob hash, signature, vault scope, decryption,
content limits and parent graph checks. The signed manifest fixes archive
membership and selected record heads. Import commits the vault, all objects,
heads and derived tag index in one SQLite or IndexedDB transaction. Any failure
rolls back that transaction. A vault already present on the device is rejected
without replacement or merging. A restored vault starts with sync disabled;
sync can be configured later in vault settings. The code can be remembered only
after the import commits.

## Contents

The lock and record files use the same paths and exact opaque bytes as the sync
server's S3/R2 blob store. Let `ID` be the canonical UUIDv5 derived from the
existing Ed25519 public key, and `HEX` its 32 hexadecimal digits without hyphens.
Let `SHA` be lowercase SHA-256 of the complete blob bytes:

```text
HEX[0:2]/HEX[2:4]/ID/locks/SHA.sealed
HEX[0:2]/HEX[2:4]/ID/SHA[0:2]/SHA[2:4]/SHA[4:]
backup.json
backup.sig
```

The blob hash differs from the core revision ID. Exactly one lock is present.
`backup.json` is a UTF-8 JSON object with `version: 1`, `lock` (lock SHA-256),
`blobs` (sorted unique record blob hashes) and `heads` (record and core revision
ID byte arrays). `backup.sig` contains the 64-byte Ed25519 signature over
`b"confidex/backup/v1\0" || exact_backup_json_bytes`, using the existing vault
signing key. Imported manifest bytes are verified without re-serialization.
Selected local heads are retained even when other branches exist. Downloaded
records with no local head get their unique graph head; an ambiguous new record
cannot be exported until its conflict is resolved.

The ZIP contains no password, `secret_key`, transfer code, device key cache,
plaintext values, plaintext tags, local vault name or sync checkpoint. Tag indexes
are rebuilt from authenticated records on import. Record IDs, revision links,
counts and blob lengths remain visible, as they are on the server. A valid
signature proves the snapshot's integrity, not that it is the latest snapshot.
Keep the transfer code separately and keep the password for this lock version.

## Limits

The current implementation uses memory: at most 64 MiB of ZIP input/output,
48 MiB of encrypted record data, 10,000 revisions and an 8,000,000-byte manifest.
It rejects the complete operation on overflow; it never produces a truncated
backup. Export writes ZIP entries without compression because the encrypted
blobs do not benefit from compression. Import accepts Stored and Deflate entries
with bounded reads, and rejects duplicate paths, invalid paths, directories,
symlinks, encrypted ZIP entries, multi-volume archives and ZIP64. Core resource
limits also apply. Larger vaults need streaming support before these limits can
be raised.
