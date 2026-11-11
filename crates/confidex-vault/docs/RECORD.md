# Record content API

`record::Record` owns an ordered `Vec<Entry>`, encrypted `tags: Vec<String>`,
and unknown Record fields in `extra`. Tags are unique, case-sensitive UTF-8 labels;
the writer sorts them. At most 256 tags of 256 UTF-8 bytes each are allowed.
The content reader accepts absent tags as empty; the writer always emits `tags`.
Each Entry has `name`, `type_name`, a `value` mapping, and unknown entry fields in
`extra`. Names may be empty or repeated. Types must be nonempty. Positions identify
entries only within this revision. Edit, reorder, and delete through the vector;
keep `extra` when editing received content. Arbitrary types and nested MessagePack
values are retained, including opaque ext payloads and float bit patterns.

`Record::decode_content(bytes, budget)` checks raw MessagePack and structure before
building owned values. Its result contains the Record and each original encoded
value-map span in `value_sizes`. Alternative integer widths remain valid; sizes
refer to the received bytes. `encode_content(budget)` validates and measures first,
then writes one canonical content map with sorted UTF-8 keys and shortest widths.
It returns zeroizing bytes and sizes for that new encoding. Semantic round trips
preserve values; they need not reproduce a noncanonical original byte encoding.
These functions do not compress, encrypt, parse metadata, or check public sizes.
The full encrypted opening pipeline must perform those operations separately.

Both calls enforce the content limits in the [resource profile](spec/RESOURCES.md),
including 4,096 entries, 64 MiB encoded content, 64 levels, and 65,536 nodes. Pass
an operation budget no greater than `resources::MAX_OPEN_MEMORY` (192 MiB).
Admission charges twice the encoded length, 256 bytes per node, and 2 MiB scratch.
Large payloads use exact reservations. This bounds controlled live allocations;
allocator fragmentation and retained WASM pages can require more linear memory.
Allocation failure returns an error where allocation is fallible. This is not a
guarantee against process-wide allocation failure in dependency/container code.
Caller-built values with spare capacity and other retained Records remain the
caller's responsibility. Calls borrow inputs and do not modify them on failure.

`Entry::validate_value()` is explicit. Reading and writing do not call it. The
current basic schemas require UTF-8 strings:

| Type | Required fields | Optional fields |
| --- | --- | --- |
| `text/v1` | `text` | — |
| `username/v1` | `username` | — |
| `url/v1` | `url` | — |
| `secret/v1` | `secret` | — |
| `login/v1` | `username`, `password` | `url` |
| `password/v1` | `password` | — |
| `api_key/v1` | `secret` | `url` |
| `note/v1` | `text` | — |
| `secure-note/v1` | `text` | — |
| `card/v1` | — | `number`, `holder`, `expiry`, `cvv`, `pin`, `brand` |
| `person/v1` | — | `name`, `birth_date`, `address`, `email`, `phone`, `identifier` |
| `document/v1` | — | `kind`, `number`, `holder`, `issuer`, `country`, `issued`, `expires` |
| `passport/v1` | — | `number`, `holder`, `issuer`, `country`, `nationality`, `issued`, `expires` |

`totp/v1` has a binary secret and numeric parameters; explicit validation and
generation are described by the [TOTP profile](TOTP.md).

`date/v1` uses unsigned integer `year`, `month`, and `day` components.
`month-year/v1` uses only `year` and `month`; it does not create a day.
If all known components are absent, the value is empty. Otherwise all known
components are required. Explicit validation accepts years 1–9999, months 1–12,
and valid Gregorian days, including leap years. These values have no time zone.
The UI uses DD/MM/YYYY or MM/YYYY for input; those strings are not timestamps.
Extra mapping keys are preserved when a date is edited or cleared.

`location/v1` permits `name: str` and a numeric `latitude`/`longitude` pair in
degrees. Both coordinates may be absent; one coordinate alone is invalid.
Explicit validation requires finite latitude within −90…90 and longitude within
−180…180. The editor accepts a decimal comma. The stored coordinates are numbers.
No map, device-position request, or external geocoding is part of this type.

`wifi/v1` stores credentials with explicit [Wi-Fi validation and QR generation](WIFI.md).
`ssh/v1` stores a binary OpenSSH private key; explicit import, validation, signing
and native-agent integration are described by the [SSH profile](SSH.md).

`photo/v1` requires `data: bin` and permits optional `mime: str`; this validates
the storage shape. Explicit [photo validation/conversion](PHOTO.md) has separate
decoder limits. Reading the Record never decodes the image.

`file/v1` requires `data: bin` and permits optional `filename: str` and `mime: str`.
Empty files and labels are valid. These labels are untrusted hints, never paths
to open or write. Reading returns opaque bytes: nested archives, executable
content, or embedded MessagePack are not decoded. Applications decide how to
reveal or export them. File names and MIME hints remain encrypted.

File bytes have no separate 4 MB cap. The entire serialized content is compressed
together by `envelope::seal`, with an inclusive 4,000,000-byte ceiling before
encryption. A compressible file larger than that may fit; multiple individually
small attachments may exceed the combined limit. Public `value_sizes` measure
each whole encoded mapping, including labels and framing, rather than file bytes
alone. Opening checks those sizes against the original decoded spans.

Extra value fields are preserved; empty strings are valid. Unknown types return
`UnsupportedType` only when explicitly validated. URL navigation and password
strength policies belong to the application. Image/file decoders never run here.

Card/person/document/passport mappings permit empty or partial data. Every
defined field is an optional UTF-8 string; preserve numbers, identifiers, names,
addresses, and date text exactly as entered. Explicit validation checks storage
field types. Formatting and domain-specific checks belong to the application.
All these fields, including their entry labels and type names, stay inside the
encrypted content. Open metadata still contains only epoch and value sizes. Tags stay inside encrypted Record content.

One secret is one Record with independent, ordered fields; a Record has no
Login or Note type. Creation templates only supply starting fields. Login supplies
username, password and URL entries; API key supplies secret and URL entries.
Each field can be renamed, moved or removed independently, with repeated names.
The client retains the older `login/v1` and `api_key/v1` schemas for reading
existing compound entries. It exposes their values as independent fields and
writes atomic entries on explicit save, preserving unknown values and metadata.
Opening or cancelling does not rewrite a signed revision.

Record and Entry omit Debug/Clone and wipe their live owned fields on drop;
encoded output uses `Zeroizing<Vec<u8>>`. Values moved or copied out become the
caller's responsibility. This does not promise removal of all compiler copies,
allocator remnants, dependency temporaries, or previously persisted bytes.

## Encrypted field presentation metadata

`secure-note/v1` contains a `text` string, like `note/v1`. The client always masks
it until reveal and excludes its content from the search index by type,
regardless of absent, false or malformed presentation metadata. Changing a note's
protection explicitly changes its type and creates a normal signed revision.

An entry may also carry an optional `metadata` mapping in its extension fields
(`Entry.extra["metadata"]`). It is part of the encrypted Record content alongside
name, type and value. The client retains unknown attributes. Older `note/v1`
entries with `metadata.protected = true` remain masked and excluded from search;
the editor presents them as secure notes and writes `secure-note/v1` on explicit
save. Other protected entries also stay out of the index. Opening or cancelling
never rewrites history. Removing protection requires an explicit change to
`note/v1`; a false metadata flag alone does not expose a secure note.
