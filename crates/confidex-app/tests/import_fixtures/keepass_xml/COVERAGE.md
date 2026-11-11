# KeePass XML adapter evidence

All values in this directory are public test data. The adapter produces the
shared import Plan. Registry, preview, apply and search integration belong to
the application flow; parser checks do not prove those operations.

## Producer evidence

`database.xml` is the reviewed Confidex schema fixture. It is not a captured
application export. Its expected JSON remains the original reviewed baseline;
the adapter tests also cover source data that the baseline does not enumerate.

`upstream-keepass.xml` is the exact published KeePass XML test database from
[KeePassXC](https://github.com/keepassxreboot/keepassxc/blob/6bcb901aefdd6c7a525466d7dfe099c5ebc13c0e/tests/data/NewDatabase.xml).
SHA-256: `ad2a92168118b5959ac72270c85b983c617ec89d5c2e556047acd35ece8b9766`.
The upstream project provides its licensing in
[COPYING](https://github.com/keepassxreboot/keepassxc/blob/6bcb901aefdd6c7a525466d7dfe099c5ebc13c0e/COPYING).
Its Generator is KeePass. Its pool contains two exact files, `0123456789` and
`abcdefghijk`, and current and historical entries reference those files.

`keepassxc-2.7.11.xml` is an unmodified local CLI export from the official
[KeePassXC 2.7.11 release](https://github.com/keepassxreboot/keepassxc/releases/tag/2.7.11).
The arm64 DMG SHA-256 is
`11c514ed9fcc33b82d2a8e113bfc989b5834335dafd7a5dadd8942410cfbd025`;
the XML SHA-256 is
`772699fb0de190c06dfa20eba517511c847b53e157722368e5645ff2382629d7`.
The capture used only `database.xml` and public fixture bytes:

1. `keepassxc-cli import -q -p -t 100 database.xml public-fixture.kdbx`.
2. Use the public database password `PUBLIC-FIXTURE-DATABASE`.
3. Attach `public.txt` to `Recycle Bin/Deleted` with `attachment-import -q`.
   File bytes are `PUBLIC-FIXTURE-ATTACHMENT` followed by `00 ff 0a`.
4. `keepassxc-cli export -q public-fixture.kdbx` writes the captured XML.

The executable ran from a read-only temporary DMG mount. It was not installed
in Applications. UUIDs, timestamps and random database metadata change on a new
capture. The CLI retains the input Generator string; that string alone is not
evidence of which program wrote a file. The captured exporter also sorts its
String fields and writes binary timestamps. The importer preserves the actual
export order and retains timestamp XML without inventing Confidex history.

The capture proves the attachment limit: one active Binary references pool ID 0,
but the export contains no Binaries pool. Re-including the deleted entry produces
Blocked/MissingAttachment. This agrees with the KeePassXC
[export guide](https://keepassxc.org/docs/KeePassXC_UserGuide#_exporting_databases).
An XML import cannot reconstruct omitted bytes. Use KDBX when files are required.
The older published KeePass sample proves that present pool bytes can be imported.

The pinned [reader](https://github.com/keepassxreboot/keepassxc/blob/6bcb901aefdd6c7a525466d7dfe099c5ebc13c0e/src/format/KdbxXmlReader.cpp)
distinguishes `ProtectInMemory` plaintext from `Protected` inner-stream ciphertext.
The latter needs a stream key and must not become a usable imported password.

## Mapping

| Source | Result |
| --- | --- |
| Entry UUID | Caller-supplied database instance plus source ID; no Confidex ID reuse |
| String order and names | Ordered independent fields, including empty and repeated keys; repeated keys also require review |
| Password | Password field even without a memory-protection marker |
| Protected username / URL / custom value | Preserve protection; no URL fetch or indexing of a protected value |
| Notes | Protected note, including empty values and line breaks |
| Protected title | Neutral display title and protected Original data |
| `Protected=True` | Block the entry; retain ciphertext, never treat it as plaintext |
| Groups | Preserve each path component, UUID, header and properties; no automatic group-to-tag conversion |
| Source tags | Preserve source text and parsed tags; unexpected protection blocks rather than indexes them |
| Recycle bin | Match the group UUID; exclude by default; reparse when inclusion changes |
| Auto-Type, history, plugin and unknown entry data | Protected Original data and review; no execution or invented signed history |
| Field reference / dynamic placeholder | No substitution or execution; unresolved credential values block the entry |
| Binary references / inline binary | Exact bytes in file/v1; no path extraction or image conversion; missing or ambiguous data blocks |
| Meta, headers, group metadata, root extensions | Shared container attributes retained once; plan-level review also covers zero records or partial selection |
| TOTP | Typed binary secret and explicit algorithm/digits/period, with original representation retained |

Container data and source attributes are private import provenance. The apply
layer must retain them inside the encrypted destination and honor container
review. Source UUIDs are not enough to infer the database instance from a file
name, title or URL. Without caller scope, the common plan reports missing scope.
Duplicate entry/group UUIDs and pool IDs are rejected instead of overwritten.

KeePass [field references](https://keepass.info/help/base/fieldrefs.html) can use
search expressions rather than IDs and may select the first matching entry.
[Placeholders](https://keepass.info/help/base/placeholders.html) can depend on
other fields, environment, time or commands. The adapter never executes them.
An exact password `{TIMEOTP}` or `{TOTP}` can be represented by a supported TOTP
field from the same entry; the placeholder itself stays in Original data.

TOTP producer behavior is pinned in
[Totp.cpp](https://github.com/keepassxreboot/keepassxc/blob/6bcb901aefdd6c7a525466d7dfe099c5ebc13c0e/src/core/Totp.cpp)
and [Entry.cpp](https://github.com/keepassxreboot/keepassxc/blob/6bcb901aefdd6c7a525466d7dfe099c5ebc13c0e/src/core/Entry.cpp).
Supported dialects are otpauth TOTP URI, KeeOtp query, legacy TOTP Seed/Settings,
and native TimeOtp fields with UTF-8/hex/base32/base64 seed encodings. Algorithms
are SHA1/SHA256/SHA512, digits 6–8 and period 1–86400 seconds. Conflicting encodings,
unknown settings, Steam and HOTP remain protected source data with review.
They do not become default RFC parameters. A dependent unresolved password blocks.

`keepass_xml::mapping` exposes field and TOTP helpers within import::formats for
future KDBX reuse. They take decoded source names/values, return Core Entry or a
mapping Issue, and do not depend on XML, storage or UI. The XML-specific entry
mapper retains XML spans; KDBX must supply its own source context and admission.

This is semantic import, not byte-for-byte XML roundtrip. Original data is source
context, not an authority for an export after edits. A writer must use current
fields and report losses rather than resurrect deleted or changed secrets.

## Admission and checks

The adapter uses quick-xml 0.41. It scans the bounded input to index spans, then
materializes one entry or pool member at a time. It accepts UTF-8 XML 1.0,
predefined/numeric references, CDATA, CRLF and empty values. DTDs, custom entities,
processing instructions, namespaces, duplicate attributes, malformed structure,
invalid XML characters and unsupported encodings are rejected. Mixed data at
structural roots is rejected; unexpected entry data is retained for review.
Owned decoded source values and binary buffers clear on drop.

A single plain, non-reference Title is a structural header outside the Record
field budget. All 512 Record fields can accompany it; the next field is refused.
Protected, encrypted, hidden-name, dynamic and repeated Title fields do not get
this exemption. Reduced caller field limits retain the same boundary.

Limits come from the shared Limits: input/plan/decoded binary budget 64 MiB each,
192 MiB admitted memory, 10000 records, 512 fields, depth 32, 1000000 semantic
nodes, strings/attributes 16 MiB and names 4096 bytes by default. XML events also
have a ceiling of four times the node budget. At most 512 attributes per element
bound duplicate-attribute comparisons in the XML library. Source spans and node overhead are
admitted before entry trees are built; one tree has an additional ceiling of
`input_bytes / 256` nodes. Lower caller limits remain effective.

Each pool member is validated, including orphans. Base64 size and gzip ISIZE are
checked before output allocation; actual length, CRC, stream end and trailing
bytes are checked afterward. The aggregate decoded budget counts each pool file,
inline files and additional copies from repeated references. The first reference
to a validated pool member does not count its bytes twice. Missing data is not a
successful empty file. The common pipeline checks the whole mapped Record against
the 4000000-byte compressed cap. Import does not split oversized records.

Native private tests cover the reader, mapping, index and binaries. Public
`tests/keepass_xml.rs` exercises prepare → parser → validated encoded Plan:
protection, repeated/empty names, TOTP, references, source history, recycle states,
metadata retention after nested empty elements, attributes, container review,
malformed inputs, reduced budgets, cancellation and compressed record overflow.
The same public tests run under wasm32-wasip1 with the existing run-wasi.mjs.
Canonical record, source, container and diagnostic hashes are compared with native
for all three pinned inputs. The browser wasm32-unknown-unknown library also builds.

The separate ignored 10000-entry calibration includes ten fields per entry,
protected values, source tags, timestamps, Auto-Type, history and shared metadata.
Measured on Apple Silicon with Rust 1.98, native release and WASI debug:

| Measurement | Native | WASI |
| --- | ---: | ---: |
| Input XML bytes | 14982938 | 14982938 |
| Canonical plan bytes | 19363101 | 19363101 |
| Parse/map/plan elapsed | 522 ms | 9590 ms |
| Process peak RSS / WASM linear high-water | 48463872 bytes | 42270720 bytes |

Native peak is measured with `/usr/bin/time -l` on the built test executable,
not Cargo. WASM uses the existing runner's memory check, below its 256 MiB ceiling.
Retained admitted memory is 25841773 native / 23467437 WASI bytes, including plan
capacity. These values describe this parser/plan workload; they are not a promise
about UI latency, apply/search time, total browser process memory or every input.
Full UI/apply/search calibration and live browser screens remain integration work.
