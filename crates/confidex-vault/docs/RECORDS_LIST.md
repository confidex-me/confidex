# Streaming records-list API

`records_list::Reader::new(reader, &anchor, limits)` checks the outer format,
version, vault ID, and declared item count. It accepts any `std::io::Read`,
including a byte slice or a platform storage/transport stream. `read_next(budget)`
reads and verifies one complete envelope and returns its original wire bytes and
`VerifiedRevision`. Those results borrow a single reusable bounded buffer; drop
them before advancing. It never materializes the whole list or decrypts content
automatically. Call `object.revision.open(&keys, budget)` when full content
validation is required, and release each Record before reading the next one.
An authenticated envelope alone does not prove valid compressed/content bytes.

`Reader::finish()` is required before accepting an import. It requires all items
to have been read and checks EOF, including the empty-list case. Extra bytes,
truncation, malformed objects, wrong vault, unsupported versions, or I/O errors
return errors. After an item-reading error, the reader cannot resume or finish
successfully. Previously yielded objects are a candidate batch until completion.

`Writer::new(writer, &anchor, count, limits)` writes the outer prefix for a known
item count. `push(wire, budget)` verifies every envelope and retains its exact
original bytes in the output. `finish()` requires that count and flushes the
writer, returning the destination. Export to a temporary file or transaction;
an I/O or validation error can leave a partial destination stream, which must
not replace the accepted export. Writing requires no decryption keys.

Limits default to 512 MiB total wire bytes, 10,000 delivered envelopes, and
100,000 parent edges. Lower values are permitted; higher ones fail. Repeated
objects are verified again and count toward every applicable limit. Byte limits
are inclusive and include outer/item framing. The reader checks lengths before
reserving, and buffers at most one envelope (4,065,668 bytes). Per-object budget
arguments enforce the common 192 MiB ceiling and include the fixed envelope work
allowance. Lower the budget by retained graph/index/transaction memory before
each step or opening. Application-supplied buffered readers/writers and retained
objects also consume application memory; the core cannot inspect their capacity.
Use streaming destinations rather than accumulating an entire large export.

Storage is external. Stage verified objects in a transaction, open and validate
content when importing decrypted data, validate the candidate graph, and commit
only after `finish()` succeeds. Abort/discard staged data on any error. A test
demonstrates this pattern with a temporary in-memory candidate and leaves accepted
data unchanged after a bad signature, wrong content sizes, truncation, or trailing
bytes. Real persistent transactions and concurrent import coordination belong to
the application. This API cannot undo arbitrary caller side effects.

Transport order is retained; it is not chronology. Deduplication by revision ID
and exact H/C identity, parent scope/existence, cycles, and deletion history belong
to graph integration. Empty or successfully verified lists prove neither server
freshness nor completeness. The separate lock is never embedded in this format.
