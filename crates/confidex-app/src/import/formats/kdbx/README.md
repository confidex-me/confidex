# Direct KDBX reader

`parse_with` reads the file locally through `keepass::bounded::Raw`. It does not
write an XML export or attachments to disk. Shared KeePass XML helpers own entry,
group, protection, TOTP and unresolved-reference mapping. The KDBX module adds
authenticated decoding, the inner stream and attachment pools.

## Checked inputs

| File | Version | Outer cipher / KDF | Credentials |
| --- | --- | --- | --- |
| Upstream public sample and KeePassXC attachment capture | 3.1 | AES / AES-KDF | Password |
| Actual KeePassXC captures | 4.0 | AES / AES-KDF | Password, raw keyfile, both |
| Additional KeePassXC captures | 4.0 | AES / AES-KDF | Empty password, empty password with raw keyfile |
| Bounded library variants | 4.1 | AES / Argon2d, versions 0x10 and 0x13 | Password |
| Bounded library variant | 4.1 | ChaCha20 / Argon2id 0x13 | Password and XML v2 keyfile, UTF-16LE BOM |
| Bounded library variant | 4.1 | Twofish / AES-KDF, no compression | Raw keyfile |
| Bounded library variant | 4.1 | AES / Argon2id 0x13 | Hex keyfile |

The library variants exercise Salsa20 and ChaCha20 inner streams. See
`vendor/keepass/tests/resources/bounded/CAPTURE.md` for independent-reader evidence
and the KeePassXC 2.8.0 limitation with Argon2 0x10. The matrix is not a claim
about every combination of versions and algorithms. Hardware challenge-response,
OS-bound keys, KDB, prerelease KDBX and unknown algorithms are not accepted.

`parse_with` uses `Option` to distinguish an absent credential from an empty
credential. `parse` uses `Options.password_present` and `keyfile_present` for
the same distinction. An inactive buffer is ignored even if it contains data;
an active empty value is passed to the library. The host must set both flags
from the user's explicit credential choices. No credential mode is guessed and
there is no automatic second attempt with different credentials.

## Retention and protection

All inner-protected nodes are consumed in physical order, including history and
unknown metadata. Bounded, cleared buffers hold replacements. The mapper
materializes one entry or metadata fragment at a time; it never needs a complete
plaintext XML export. The decoded fragment uses `ProtectInMemory=True`, so fields
keep their protection when the shared mapper reads them. Binary protected values
stay base64 in their source representation.

Each current source entry becomes one planned Record. History, plugin data and
unsupported source behaviors remain in protected original data. Source history
is not a sequence of signed Confidex revisions. References and commands are not
executed. The existing recycle-bin exclusion and group-review rules apply.

Current attachments become `file/v1` fields. Encrypted source attributes retain
the entry's `binary_pool` map, including references from nested history. Each
member contains exact bytes and the source memory-protection flag. Equal pool
references keep equal bytes; separate field copies still count against resource
limits. Missing references block the item with `MissingAttachment`.
The same protection flag also marks the current file field as protected. XML pool,
inline and per-reference `ProtectInMemory` markers use this shared mapping.
Only entry and history attachment structures supply pool references. Reference-like
markup in opaque plugin subtrees stays in original data without interpretation.

The shared container retains decoded source metadata and groups, the original
outer header, a version label and `source_format=kdbx`. KDBX4 pool members with
no entry references are kept in `orphan_binaries`; KDBX3 metadata already contains
its whole XML pool. All retained values belong in the encrypted destination.
They are not a promise that a later export can represent every Confidex field.

## Bounds and cancellation

The decoder receives the remaining shared memory budget after input, plan
headers and credentials. A reservation covers its full temporary budget; after
opening, `shrink_to` keeps resident capacities charged without a release/reclaim
gap. Decoded fragments, binary copies and retained source data stay charged until
the plan has encoded them. Input, unpacked data and plan each default to 64 MiB;
shared memory defaults to 192 MiB. Context limits can only be reduced.

The library admits KDF parameters before work: at most 25,000,000 AES rounds,
64 MiB Argon2 memory, 1,024 passes, 16 lanes and 16 GiB memory-times-passes
(256 passes at 64 MiB).
The combined cost and available memory also apply. Header, block, decompression,
depth, node, string and Record limits are enforced by the library and shared
importer. KDBX3 uses its legacy start bytes, hashed blocks and header binding;
it does not have the KDBX4 HMAC construction.

Credential or authentication failure maps to `Checksum`, without returning a
plan or source values in an error. Preparation never mutates storage. The host
must discard the context on an error and apply only a completed plan.
KDF resource failures map to `KdfLimit`; file and payload limits map to `Limit`.

KDF progress is indeterminate; iteration counts are not file-byte progress.
Callbacks check cancellation through decoding and mapping. Argon2 is one
noninterruptible library call. A queued browser Worker message cannot interrupt
running synchronous Rust. The UI can acknowledge cancellation while bounded work
finishes, then discard its result before preview or storage changes. Early CPU
interruption needs an out-of-band signal; terminating a disposable Worker does
not run Rust cleanup. The adapter does not implement the UI cancellation transport.

The [native/browser calibration](check/README.md) runs the real app library on
the checked matrix and a public 10k workload. It compares complete planned content
and diagnostics, measures Rust allocations and process memory, and exercises an
out-of-band cancel flag with normal Rust cleanup. It does not replace the host's
credential-step, storage/apply or UI acceptance checks.

## Encrypted writer

`Writer::new(created_at, export::Options::Password { password, keyfile })` uses
the shared KeePass XML semantic writer and `keepass::bounded::save`. It never
builds a second database model or writes plaintext temporary files. The normal
application catalog is registered separately; this API and its browser proof do
not by themselves enable the export form.

The write profile is KDBX 4.1, AES256, Argon2id version 0x13 with 64 MiB, three passes
and one lane, ChaCha20 inner protection, and no compression. This is a fixed
profile, not a request to copy the source database's cryptographic settings.
Compression remains supported on input. Gzip is not used for output because
its internal plaintext history has no zeroization contract.

Password presence is explicit. An empty active password differs from no password.
Passwords are capped at 4096 UTF-8 bytes and keyfiles at 1 MiB. Active empty keyfiles
are rejected, including with a password; they are never treated as absent keys.
Independent KeePassXC checks cover raw 32-byte, hex 64-character, XML v1, XML v2,
BOM-marked UTF-16LE XML v2 and arbitrary nonempty bare files, each alone and with
a password. Five raw credential modes also run in the browser.

Current fields, TOTP parameters and attachment bytes supply all values. Source
snapshots never restore removed or changed secrets. A matching safe TOTP URI
retains its issuer and label; changed parameters produce a current URI. Group
provenance supplies scoped group hints only. Duplicate keys and unsafe executable
placeholders block writing; field names/types/order, unsupported data, tags,
MIME/EXIF/photo representation and source history use the shared loss report.
Protected strings use the library's sequential inner stream. File fields retain
their in-memory protection bit in the binary pool; the independent reader also
retains protected attachments on a subsequent save.

Output and payload default to 64 MiB, binary pools to 16,384 entries, and the shared
memory budget to 192 MiB. These ceilings can cause a complete operation to fail;
they do not promise that all maximum inputs fit together. Record owners, XML
formatting, library work and output share the same reservations. Charges precede
allocation and follow cleared buffers through growth and cancellation. Argon2
remains one synchronous bounded call. Cancellation and errors discard the entire
unpublished file. The common host owns save, lock and late-callback cleanup.

`tests/export_kdbx.rs` and its shared proof run natively and on WASI. The ignored
independent case needs `CONFIDEX_KEEPASSXC_CLI`; it checks fifteen credential and
keyfile combinations, exact values/files, protection, TOTP, wrong credentials,
terminal MAC tampering and a real reader save. `apps/confidex/web/export-check.mjs`
runs the proof in a browser Worker. `export-kdbx-check.mjs` emits five public
browser-created files for the independent reader and injects entropy failure
both before writer creation and after its UUID namespace is created. It also
requires a successful retry and a live page heartbeat. This is not UI download
acceptance or the separate 10k calibration.
