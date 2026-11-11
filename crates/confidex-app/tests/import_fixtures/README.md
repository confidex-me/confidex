# Import fixture contract

Every secret, identity and file in this directory is a public synthetic fixture.
Never use these values for a real account. All hosts use `example.invalid`.
No importer is implemented by this directory.

## Origin and evidence

The original editable inputs are schema-derived. The additional 1Password template
capture is described separately below. `bw`, `op` and `keepassxc-cli` were unavailable on the development
machine. [sources.json](sources.json) distinguishes the documented schemas,
pinned producer code and a published upstream KeePass XML test export. The
published export was independently read to verify protection markers; its digest
allows that check to be repeated without claiming an application roundtrip.
The fixtures cover a small, explicit subset. Format adapters must add captured
synthetic exports for their supported producer versions before claiming coverage.

| Family | Input | Expected result | Origin / version |
| --- | --- | --- | --- |
| Bitwarden | `bitwarden_json/personal.json` | `personal.expected.json` | Plain JSON, explicit `encrypted:false`, folders/items; producer commit is pinned in sources |
| Bitwarden organization | `bitwarden_json/organization.json` | `organization.expected.json` | Collections and organization scope; intentionally reuses a personal item ID |
| 1Password | `onepassword_1pux/account.1pux` | `onepassword_1pux/expected.json` | 1PUX attributes version 3; editable `export/` tree, two vaults and a binary document |
| 1Password templates | `onepassword_1pux/templates.1pux` | `import_onepassword` template tests | Sanitized UI capture: 22 items, 175 section fields; [audit and origin](onepassword_1pux/docs/TEMPLATES.md) |
| KeePass | `keepass_xml/database.xml` | `keepass_xml/expected.json` | Plain KeePass 2 XML with textual dates and `ProtectInMemory` markers |
| Generic CSV | `csv/generic.csv` + `csv/mapping.json` | `csv/expected.json` | UTF-8 BOM, comma, CRLF, quoted multiline text; positional mapping |

The CSV is not a certification of browser/Apple profiles. KDBX, encrypted
Bitwarden, Bitwarden ZIP and additional producer captures belong to their adapters.

## Expected result representation

Expected JSON is a test notation, not a new vault or export format. `schema:1`
contains an ordered `records` array. Each result has:

- `source`: format, caller-supplied stable `instance`, account, vault and item.
- `status`: `ready`, `review`, `blocked` or `excluded`.
- `diagnostics`: semantic codes; UI translates them rather than displaying IDs.
- `record`: existing core entries, tags and encrypted `extra["confidex.title"]`.
- `source_attributes`: source facts to retain in encrypted provenance, not public
  envelope metadata. This sidecar must survive Apply; it is not disposable UI data.

`{"$binary":"00ff"}` denotes MessagePack bin bytes only in expected JSON. All
other objects denote maps. Numbers are integers. Entries use existing core
schemas, including binary TOTP secrets and file data; there is no Record type.
`confidex.import.section`, `.field` and `.totp` in encrypted Entry extra retain
source context without changing a user-visible field name. The shared runtime
contract can use typed wrappers, but must retain the same semantics. Record
source provenance placement is owned by app/storage integration, not this fixture
notation. It must be encrypted and excluded from search.

`review` requires explicit acknowledgement of preserved but unsupported semantics;
it is not an instruction to skip data silently. `blocked` cannot be applied until
the problem is resolved. `excluded` represents an unselected archive/recycle item;
restoring it must be an explicit choice. These states do not write anything.

## Field and protection matrix

| Source data | Conversion | Retention / limits |
| --- | --- | --- |
| Item title | `extra["confidex.title"]` | Preserve source title. Protected titles require a protected fallback and a neutral display title; do not index them as ordinary titles |
| Username | `username/v1` | Do not join separate name components or infer identity from a login |
| Password | `password/v1` | Always secret, even when a vendor memory flag is false or missing |
| Multiple URLs | Separate `url/v1` entries in source order | Retain labels/match modes; no URL normalization, fetching or pattern execution |
| Ordinary custom text | `text/v1` | Names can be empty or repeated; do not key an ordered array by field name |
| Hidden custom text | `secret/v1`, or original typed entry with encrypted `metadata.protected:true` | Never downgrade an unknown/hidden value to indexable text |
| Vendor notes / secure-note item | `secure-note/v1` by default | Retain multiline text and blank lines. Public CSV notes require explicit `note/v1` mapping |
| Bitwarden `fields[].type` | Text 0, Hidden 1, Boolean 2, Linked 3 | Preserve boolean string and source type. Linked/unknown types need protected original data and a diagnostic; never copy the SDK unknown-to-Text fallback |
| 1PUX `value.concealed` | `secret/v1` | Secret even when `guarded:false` |
| 1PUX `guarded:true` on text | `text/v1` with protected metadata | Preserve source value kind and protection independently |
| 1PUX section title / IDs | Encrypted Entry extra | Retain context; do not rename duplicate/empty field titles to force uniqueness |
| KeePass `ProtectInMemory=True` | Plaintext value, with protection retained | Verified against writer, reader and published XML export |
| KeePass `Protected=True` | Block plain XML import without the inner-stream key | This is encrypted base64, not a secret that can be copied as plaintext |
| TOTP seed / `otpauth://totp` | `totp/v1`, binary decoded secret, explicit algorithm/digits/period/t0 | Keep original URI/issuer/label in encrypted extra. Reject or retain unsupported HOTP/Steam/unknown parameters; do not silently choose standard TOTP |
| Files / documents | Independent `file/v1` with exact bytes and filename | Check whole Record limits, declared size, mapping and missing files. No automatic lossy conversion |
| Folders / collections / groups | Previewed tags/group mapping | Keep path and membership provenance; do not imply ACL transfer. A slash inside a name is not proof of a path boundary |
| Dates / IDs / favorites / source category | Encrypted provenance or protected original data | They are not Confidex IDs, signed epochs or Record types |
| Password history / URI matching / Auto-Type / plugin fields / passkeys | Visible `secure-note/v1` Original data and a review diagnostic, or block when no faithful retention is possible | Retaining data does not implement the original runtime behavior or create signed revision history |
| Unknown category/value/key | Protected original data plus review; block unknown encoding/container versions | No silent omission, lossy stringification or assumed unprotected default |
| Source archive / recycle bin | Unselected by default, with a diagnostic | Do not create local signed deletions from source state |

The shared decoder must reject duplicate JSON object keys before parsing loses
one of the values. This is distinct from repeated names in field arrays, which
are valid. CSV columns are addressed by index so duplicate/empty headers survive.
KeePass keys have their own source constraints: do not make a dictionary silently
last-wins for duplicate XML String keys. Unknown or ambiguous source structure
must produce a diagnostic or admission failure.

Known unsupported JSON values are retained in the user-visible `Original data`
secure note as compact JSON. The source path/type must accompany retained fragments
when needed to identify them. Null, missing and empty values remain distinguishable
in provenance; an absent source field must not silently become an asserted empty
source value. Source-only facts can be kept alongside a mapped field. This does
not make the source authorization policy active in Confidex.

## Identity, order and attachments

`source.instance` is a stable, explicit identity provided by the caller for the
source account/database. Bitwarden JSON and generic CSV do not supply a reliable
account/server identity. Do not derive one from a title, filename, URL, username,
new random alias or import timestamp. Source account/vault/item IDs supplement
that scope. The same 1PUX item ID occurs in two vaults; the same Bitwarden item ID
occurs in personal and organization fixtures. They must not overwrite each other.
CSV row numbers are locators, never stable item IDs. A source with insufficient
scope may be previewed but cannot enable automatic identity-based updates.

One source item becomes one ordered mixed Record. Standard source slots use a
documented deterministic order; ordered custom arrays keep their order. A primary
1PUX URL duplicated in its URLs array is represented once, with source context
retained. Empty values survive editing even when normal record viewing hides them.
Groups and tags require an explicit preview; structural group components must
remain distinguishable from a slash in a literal group name.

The 1PUX document path uses its source document ID and the documented triple
underscore separator. The fixture contains NUL and 0xff so a text-only conversion
cannot pass. Never bind an attachment by basename alone. XML binary pools/references
can occur in KeePass XML; evaluate actual input/version instead of inferring that
attachments are always present or always absent from documentation summaries.

## Reverse export boundary

The same format modules can later provide a writer. These expected Records do
not certify lossless reverse export. Retain source type/context, original TOTP
text, null/empty distinctions and unsupported data so the writer can report
precise losses. A target that cannot encode mixed fields, repeated names, files,
protection or source-only behavior needs a preview and explicit decision before
writing. Importing an open export does not authorize exporting a new open copy.

## Reproduce

```sh
python3 crates/confidex-app/tests/import_fixtures/check.py
python3 crates/confidex-app/tests/import_fixtures/pack_1pux.py --check
cargo test -p confidex-app --test import_fixture_contract
```

The Python check compares source sentinels, protection markers, scoped collisions,
CSV columns, TOTP parameters, binary bytes and reviewed SHA-256 digests. It is a
trusted-fixture consistency check, not the production import parser. The Rust test
converts expected values to actual core Records and invokes structural and typed
validators. Neither check proves that an importer works or that a vendor accepts
our future writer. Add the actual adapters and their native/WASM checks separately.

To repeat the independent published-export protection check, download the exact
URL in `sources.json` to a temporary file and pass it as
`check.py --upstream-keepass /path/to/NewDatabase.xml`. Its digest is checked before
reading the sample. The normal test suite needs no network.

`pack_1pux.py` rebuilds the reviewed archive with fixed metadata and stored entries.
Do not refresh golden outputs/digests automatically when a test fails. Review the
source/expected change first. `negative_cases.py NEW_DIRECTORY` separately creates
truncated/unsafe-path archives, entity XML, inner-protected XML, broken CSV and a
JSON file that must not be accepted as a plain export. The production adapters
must assert their own admission errors against these cases; generating them is
not evidence that those errors are handled.
