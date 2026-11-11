# Revision identity and graph profile v1

Use the [format](RECORD.md) and [authentication](ENVELOPE.md)
profiles. A revision belongs to one `(vault_id, record_id)` pair. The record ID
is stable across edits; each revision identifies one immutable byte object.

## Revision ID

Let H and C be the original header and ciphertext bytes. Compute:

```text
revision_id = SHA-256(
    ASCII("confidex/revision/id/v1") || U64BE(len(H)) || H || U64BE(len(C)) || C
)
```

There is no NUL terminator. The result is 32 raw bytes. The ID is computed on
read and is not a fourth envelope field. It excludes itself, the signature,
and the outer array/bin framing. H contains only earlier parent IDs, never its
own ID. Encryption can therefore finish before ID computation without a cycle.

The signature is independently required, even when the hash matches an expected
ID. Hash equality is not proof of authorship. Signatures cannot create different
IDs for the same H/C. Strict envelope framing must still consume the full object.
Changing an accepted encoding of H changes its identity. Fresh encryption of
the same plaintext normally gives another ID; plaintext deduplication is not
provided. Never reserialize H or recompress content to compute an ID.

A storage key, filename, requested ID, or parent reference is an external
expectation, not an additional trusted wire field. Compare it with the computed
ID before accepting the object under that reference. A different validly signed
object is still a mismatch. An unavailable object is missing, not a mismatch.
Repeated delivery of the same authenticated H/C is idempotent. If an existing ID
ever has different H/C, reject the conflicting object; never overwrite it.

The short hash fixture uses H=`91 cc 01` and C=ASCII(`ciphertext`). Its ID is
`6d116a1b92bbac60c32554157a1758e5cdd21ebbfd08da0ae540576d531a1b7b`.
This checks framing only; those bytes are not a complete valid Record.

## Parents and graph checks

Parents are raw 32-byte revision IDs, unique and sorted in unsigned byte order.
Reject duplicates and unsorted lists. Each present parent must belong to the
same vault and record as its child. Reject a self-reference or any cycle among
known nodes. Check cycles iteratively so history length does not consume call
stack depth. Resource budgets apply to nodes, edges, and bytes before insertion.

The first content revision has no parents. A normal edit names its predecessor.
A merge names all branches it actually incorporates; it may have several
parents. Reading does not require a single root, a single head, an increasing epoch,
or a counter. Multiple roots/heads for one record remain visible as branches.
The writer must not reuse a record ID for an unrelated new record.

Only authenticated, structurally valid revisions enter this graph. Build a
candidate update and check it before changing accepted state. Do not discard
existing revisions when ingesting an incomplete incoming batch. Pending links
must be checked when their targets arrive, including scope and cycle checks.
An invalid later object must not replace an accepted one.

Return separately:

- Known heads: present nodes with no present child referencing them. Group them
  by vault and record. Preserve all heads; do not select one by arrival order.
- Missing IDs: absent parent targets and absent explicit expected references.
  If nonempty, the graph is incomplete and its heads are provisional.
- Known deletion events: all accepted deletion IDs, including non-head events.

Reject proven violations even if other links are missing. Otherwise absence is
an incomplete result, not a claim of corruption. If the missing set is empty,
the result is complete only with respect to those supplied links/expectations.
An entirely withheld branch with no expected reference cannot be detected.

## Deletion and conflicts

A deletion has `event_kind=1`, the same record ID, at least one affected parent,
empty entries/value_sizes, encrypted content, and a trusted signature. It is a
new graph node. It never erases its ancestors or another branch. It must not
have an empty parent list because it would identify no affected revision.

Keep the deletion event when an old revision is received again. A concurrent
edit and deletion remain separate heads; report both and the known deletion.
Even content descended from a deletion does not silently clear the deletion
history. This profile does not resolve delete/edit conflicts or authorize a
restore operation. Such policies and physical garbage collection are separate.

## Prototype coverage and limits

`tests/revisions.rs` checks exact hash bytes, authenticated object substitution,
first/edit/branch/merge/delete graphs, incomplete references, scope errors,
and cycles. Its graph helper consumes constructed nodes and is not a wire
parser or persistent revision store. Cycle tests inject synthetic IDs: producing
a valid hash-linked cycle is not required to test the graph invariant.

The core [graph API](../REVISIONS.md) implements bounded
candidate updates from verified envelopes, exact H/C duplicate checks against
external originals, pending references, and iterative graph validation. Its tests
also cover unchanged wire vectors, failed updates, other trusted keys/vaults,
deletion retention, and delivery byte/edge/count budgets.

No server freshness, complete rollback protection, vault manifest or
complete-server-history claim follows from these checks. The current
[sync application](../../../../apps/confidexsyncd/docs/SYNC.md) adds cursor/CAS handling and local checkpoints;
those detect some inconsistencies but do not prove that unseen updates or a
valid older snapshot were not withheld.
