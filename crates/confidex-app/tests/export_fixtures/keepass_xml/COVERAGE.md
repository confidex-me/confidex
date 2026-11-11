# KeePass XML writer checks

All input values and database passwords in these checks are public fixtures.
The writer takes current Records and an explicit Unix export time. It writes
plaintext XML locally; it does not fetch links, replay source XML, extract a tree
or create Confidex history in the external database. UUIDs use fresh platform
entropy and disjoint group/entry counters. Times use KeePass's eight-byte binary
UTC representation. The file is unencrypted, including protected values.

## Mapping and review

| Current data | Output |
| --- | --- |
| Title | One structural Title String, outside the Record field budget |
| First username/password/URL/note/TOTP | Native UserName/Password/URL/Notes/otp keys; renamed labels have a FieldNames loss |
| Other text/secret fields | Independent String keys, including an empty key and empty values |
| Password, secret, secure note, protected text/username/URL | Plaintext with ProtectInMemory=True; never Protected=True |
| Extra username/URL/note/TOTP | Current values retained where possible; type or functional TOTP loss reported |
| TOTP | Current seed/algorithm/digits/period; original URI only while it matches and contains no unsafe XML or dynamic expression |
| Nonzero TOTP start or unsupported type/value | Located loss; no guessed replacement |
| File/photo | Exact bytes in an uncompressed Meta/Binaries pool and an entry Binary Ref; photo type conversion reported |
| Attachment label | Filename becomes the Binary key; differing labels have a FieldNames loss |
| MIME/EXIF/extra file components | Generic application/octet-stream on import; unsupported components have a value loss |
| Tags | Current tags; delimiters and surrounding whitespace that cannot retain tag identity require consent and are omitted; CR is retained in XML with a normalization warning |
| Native field sections | Loss reported; KeePass String keys cannot retain these sections |
| Source groups | Valid current provenance path components retained; a wrapper combines otherwise separate roots |
| Source history, policies, identifiers, raw snapshots | Not replayed; source-context loss before write |
| Unknown data/metadata | Located loss, default refusal without consent |

Source group identity includes its database scope, parent and source UUID. Same
names from distinct groups/databases do not collapse. Missing scope/IDs cannot
justify merging records into one source group; the grouping change is reported.
No current tag is silently reinterpreted as a source group. One common source
root stays at the XML root, so repeated export/import
does not add another wrapper on every cycle. A Confidex root combines multiple
source roots or holds records without a group hint. Supported provenance
paths have at most 26 components, keeping the output inside the shared XML depth
budget; invalid/opaque paths require a section/source loss instead of replay.

String and attachment keys occupy separate namespaces. Duplicate keys within
either namespace are blocked rather than overwritten or silently renamed.
Reserved TOTP control keys in ordinary fields, literal executable placeholders,
invalid XML characters and CR in keys are blocked. An explicit protected-file
metadata flag is blocked because this profile cannot retain that independent
flag. Loss consent cannot bypass a blocked issue.

The XML keeps current field node order. KeePassXC uses sorted UTF-16 String keys
and a separate attachment map; a different current order gets a record-level
FieldOrder loss. Unprotected CR values get a located value warning: the XML
preserves them with character references, but the tested consumer normalizes
them in its database. Protected CR values stay exact in that database.

## Independent consumer

`independent_keepassxc_reads_actual_xml_values_and_protection` writes real writer
output, imports it into KeePassXC and reads the created database. The tested CLI
is KeePassXC 2.8.0 on Apple Silicon, executable SHA256
`3a738f4bfae8cd00b4561af80055e27711201b8ca8696550105304fb4f3b9b3e`.
The test invokes the CLI only; it does not launch its GUI.

The independent export checks every String value, memory-protection flag, UUID,
tag and the exact export-time instant. It also checks CLI show output and exports
both attachments to fixed temporary paths for exact byte comparison, including
an empty file and a 6145-byte payload spanning Base64 chunks. The created authenticated KDBX is additionally checked through our
existing importer. This last check supports the roundtrip; it does not substitute
for the independent CLI checks.

The consumer preserves protected CR values in KDBX, normalizes unprotected CR,
and normalizes all CR/CRLF in a subsequent plaintext XML export. Its tags use a
supported separator and its XML times use ISO UTC. String order is sorted. These
differences are checked explicitly. A separate public probe found that CR/LF key
collisions can create a database the CLI cannot reopen; the writer blocks CR keys.

XML attachment input was first confirmed against the published KeePass sample
pinned by the import fixture coverage. Our actual pool output was then verified
separately. KeePassXC's subsequent plaintext XML export omits pool bytes; use its
KDBX database when carrying those files onward. The writer does not claim that
every KeePass version or a second XML export retains all data.

Run the optional consumer test with Python and CONFIDEX_KEEPASSXC_CLI pointing to
the CLI. It creates only public temporary fixtures. Normal portable tests need
neither a native application nor network access.

## Resource and platform checks

The common output and snapshot budgets apply. Group/tree/vector headers are
admitted before allocation. File bytes stream through a fixed zeroizing Base64
buffer. TOTP source parsing is charged before allocation. Output errors and
cancellation release the shared memory budget and return no partial artifact.
Chunk boundaries at 3071/3072/3073 and 6144/6145 bytes are checked. A 900000-byte
payload verifies output limits and cancellation during the binary-pool pass.

Portable tests cover exact values/protection/order, empty keys/values/files,
Unicode/XML escaping, CR/LF, multiple URLs, TOTP, distinct source scopes, group
traversal with stable binary bindings, all 512 Record fields plus Title, key and
placeholder refusals, metadata losses, memory admission, output limits and
cancellation. The same public proof runs in an actual browser WASM Worker with
external fetch prohibited. The combined 10,000-record measurements belong to
the shared integration task.

## Shared window

The production export catalog includes this writer. The shared form requires
separate loss and plaintext confirmations and publishes only after Save.
`apps/confidex/web/export-ui-check.mjs` with `keepass-xml` and a production `export-ui-check`
bundle downloads an actual selected-record XML at desktop and narrow widths.
It also checks a blocked duplicate-key report, save failure, Ready cancellation
and vault lock. The test does not silently drop the blocked second record.

`apps/confidex/web/export-ui-reader.py CLI PUBLIC_OUTPUT xml` imports those downloaded XML files
with KeePassXC, then checks its own export and attachment-export. Current Unicode
and multiline password values, protection flags and the exact 600001-byte
attachment are verified independently. The native GUI is not launched. This
does not extend the consumer compatibility claims above to other applications.
