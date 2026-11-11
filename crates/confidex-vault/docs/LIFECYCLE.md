# Core ownership and lifecycle

The library provides vault operations; the application owns sessions, storage and
policy. `lock::create` returns an authenticated `OpenedVault` and a separate
public lock. Save the lock and individual encrypted revisions through the
application's transactional storage; a records-list is a separate portable
container, not the local database layout. Save/display the client-held
[transfer code](TRANSFER-CODE.md) separately; it contains the original 32-byte
secret and the public sync UUID, not private vault material. It is not the old
32-byte-only Base32 presentation. Never include the code, secret_key or
password-derived keys in server objects. Passwords and epoch
timestamps are caller inputs; metadata epoch uses Unix milliseconds.

An `OpenedVault` owns the private vault material and trust anchor. Borrow its
keys/anchor to seal or open a revision. Create a mixed `Record`, retain unknown
fields on edits, then call `envelope::seal` with explicit record ID, parents,
epoch and event kind; tags belong to encrypted `Record.tags`. The application chooses IDs and must reject accidental
collisions. All content is compressed together before encryption; names/types
and tags remain encrypted while epoch/value sizes are open and authenticated.

Opening a revision authenticates the exact bytes and public sizes before returning
owned content. Type-specific validation and photo/SSH decoding are explicit.
Borrow or reveal only the values needed for the current operation, then drop the
opened Record and other secret buffers. Record/Entry, encoded content, imported
keys and decoder outputs have the zeroization guarantees of their API profiles.
Values moved/copied out, input passwords, GUI strings, screenshots, clipboard
contents and source caches belong to the application.

To lock a session, cancel pending access/approval operations and release every
`OpenedVault`, decrypted Record, imported SSH Key, photo/QR/code output and
application copy. The library has no global secret cache or shared unlocked flag.
Dropping one context does not invalidate another context already held elsewhere.
Private contexts omit Debug/Clone and clear owned private material on drop;
the application must coordinate its own workers before declaring a session locked.
Public trust pins, encrypted wire objects and the public revision graph can remain.
This is ownership cleanup, not proof that allocator/compiler/runtime copies or
previously persisted bytes have been physically erased.

Reopen with `lock::open` using password bytes and the separately recovered decoded
secret_key. It establishes an anchor only after checking the authenticated wrapper
and recovered keys. An application may retain its own authenticated public pin for
locked signature verification; a public key supplied by a server cannot establish
trust by itself. The core reads no OS keychain, browser storage or global clock.

For a records-list import, stream one verified envelope at a time into external
staging storage. Create a graph Update with the declared count and pass its
remaining `object_budget()` to per-object operations. Open content explicitly if
the import requires semantic/content validation; signature verification alone does
not validate encrypted content. Stage verified headers in the candidate graph,
and call Reader `finish` to check the complete stream before Update `finish`.
Only then commit staging storage and replace the accepted graph together in the
application's transaction. Failure/drop discards the candidate; the core does not
roll back arbitrary caller storage. Keep original exact H/C bytes for duplicate
identity checks. Missing references are reported, not silently fabricated.

Revision graph metadata preserves independent branches and signed deletion events.
An old revision replay does not remove a known deletion. It does not automatically
select a last-writer winner, resolve update/delete conflicts, restore a record,
erase history, or prove freshness/completeness of a server's response.

`OpenedVault::rewrap` creates a new lock around unchanged keys. Saving and
distributing it is a separate application operation. Existing ciphertext, IDs,
parents, signatures and old wrappers remain valid. A client using an old wrapper
can still sign new records that a newly rewrapped client can open. Password
changes do not revoke leaked keys or historical plaintext.

Native and WASI use system entropy. Browser builds enable `browser` at the
application boundary for Web Crypto; OS-less WASM without it returns an explicit
entropy error and clears the requested output. Native SSH IPC lives in another
crate. Operation budgets bound controlled live allocations, not whole-process RSS
or retained WASM pages. The host budgets concurrent operations and caller-owned
objects separately. Filesystem/indexes, import/approval policy, auto-lock timers,
UI, synchronization, physical GC and recovery are outside this core library.
The implemented [application and sync server](../../../apps/confidexsyncd/docs/SYNC.md) provide local
persistence, authenticated synchronization and whole-record conflict UI; their
transaction/checkpoint rules are separate from the portable format.
