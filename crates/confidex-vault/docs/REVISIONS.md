# Revision graph API

`revisions::Graph::new(&anchor)` creates an empty graph for one trusted vault/key.
It retains public revision metadata: IDs, record IDs, parents, epoch, and event
kind. It does not retain ciphertext or decrypted Records and can outlive the
unlocked key context. Persistent object storage remains external.

`graph.begin(delivered_count, memory_budget)` returns a candidate update. Feed
`update.stage(&verified_revision, original)` exactly once per delivered object.
Inputs must come from envelope signature verification under the graph's trusted
key and vault. A different trusted key for the same vault ID is rejected too.
For content validation, explicitly open each Record before staging it and release
it before advancing. Graph checks do not decrypt or validate value types.

Use `update.contains(&id)` to identify duplicates. For a duplicate, load the
original object from accepted or staged storage, verify it with the expected ID,
and pass that `VerifiedRevision` as `original`. The core compares exact original
H/C bytes, excluding outer framing and signatures. Missing originals or conflicting
payloads fail; the core never silently replaces an existing ID. The caller must
supply the actual stored original rather than assert that the new object was
already present. No second hash substitutes for the byte comparison.

`update.finish(expected_ids)` validates the whole candidate and returns a new
Graph. Assign or commit it only after the external storage transaction succeeds.
Dropping or failing an update leaves the previous Graph unchanged. An error while
staging poisons the candidate; skipped deliveries cannot yield a successful
finish. Existing nodes are copied into the candidate, so an incomplete new batch
does not discard older history. Parents may arrive after children; a later parent
must match the referencing child's record scope. Checks reject self/cyclic links
iteratively, including cycles that coexist with other missing objects.

`graph.report()` returns sorted `(record_id, revision_id)` heads and known deletion
events, plus sorted missing IDs. Missing parents and explicit expectations mean
incomplete history. They remain pending across updates until their objects arrive.
Known deletions include non-head events and remain after replay, concurrent edits,
and content descended from a deletion. No timestamp selects a winning head and no
implicit restore occurs. Epoch is retained as data, without requiring increasing
times. Server synchronization and conflict resolution live in the separate
[application layer](../../../apps/confidexsyncd/docs/SYNC.md), which reconciles heads and asks the user
to choose divergent whole-record versions.

Use `reader.declared_items()` for the update count and `update.object_budget()`
for each streaming reader step and explicit Record opening. Admission counts the
old graph, candidate capacities/parents, report and iterative-walk reservations,
and a 24 MiB object-work allowance within the common 192 MiB ceiling. Caller-owned
object buffers, unrelated retained Records, and storage/index staging must also
fit; lower the supplied budget accordingly. Allocation capacities are checked and
observable reservation failures return errors. Opaque allocator bookkeeping and
WASM retained pages are outside this live-memory bound.

Each update caps deliveries at 10,000, summed envelope bytes at 512 MiB, and
delivered parent edges at 100,000, counting duplicates. A records-list reader
separately counts its outer/item framing. These are operation limits; there is no
fixed 10,000-node lifetime limit on a graph. The metadata index is still bounded
by memory. Larger persistent histories may require external storage coordination.
Success is completeness only for supplied links/expectations. It proves neither
server freshness nor absence of withheld branches.
