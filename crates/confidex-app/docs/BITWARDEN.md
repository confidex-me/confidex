# Bitwarden import source review

This records producer evidence and the plaintext JSON adapter's conversion rules.
The shared pipeline owns budgets and plan types. The application owns registration,
preview, encrypted provenance placement and atomic Apply.

## Pinned producer

Reviewed on 2026-11-09 at Bitwarden clients commit
`2ff80e50951792379f970f65cd4fb585fc50bbd5`:

- [Individual exporter](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/tools/export-vault-core/src/services/individual-vault-export.service.ts)
- [Organization exporter](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/tools/export-vault-core/src/services/org-vault-export.service.ts)
- [JSON export variants](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/tools/export-vault-core/src/types/bitwarden-json-export-types.ts)
- [Cipher export](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/common/src/models/export/cipher.export.ts)
- [Custom field types](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/common/src/vault/enums/field-type.enum.ts)
- [Linked field IDs](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/common/src/vault/enums/linked-id-type.enum.ts)
- [Login export](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/common/src/models/export/login.export.ts)
- [URI export](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/common/src/models/export/login-uri.export.ts)

The [official import documentation](https://bitwarden.com/help/condition-bitwarden-import/)
contains manually conditioned examples; these are not evidence that the installed
application produced every illustrated file. Producer source and synthetic
application exports must remain distinguishable in fixture provenance.

## Export boundaries

The individual JSON exporter produces `encrypted: false`, `folders`, and `items`.
The organization variant uses `collections`. The plaintext individual path
excludes organization items, removes the exported cipher key and sets
`collectionIds` to null. Deleted items are filtered before serialization.
Attachments are not members of `CipherExport`; plain JSON cannot prove their
absence from the original vault. The ZIP exporter separately writes `data.json`
and an attachment tree. It has its own sanitization and collision rules.

The adapter must require explicit boolean `encrypted: false`. Upstream's broad
`isUnencrypted` helper also accepts a missing flag; that is not the admission rule
for this adapter. Account-encrypted and password-protected JSON are separate
formats. No decryption or server login belongs to plaintext import.

The root JSON has no account/server identity suitable for a stable source
namespace. The import options must supply that scope. A filename, title, login
username, URL, or new random alias is not a substitute for a stable source
account scope. Organization IDs and source item IDs remain encrypted provenance;
they do not become Confidex Record IDs.

## Semantics that need explicit coverage

| Source | Observed meaning | Required retention boundary |
| --- | --- | --- |
| Item type 1/2/3/4/5 | Login, secure note, card, identity, SSH key | One source item stays one mixed Record; categories do not define Record types |
| Item type 6/7/8 | Bank account, driver's license, passport in this producer | Preserve unknown category content with a protected fallback and report; do not omit it |
| Custom field type 0/1/2/3 | Text, hidden, boolean, linked | Preserve order, empty/repeated names and values; hidden values never become indexable text |
| Unknown custom field type | Future or unsupported semantics | Do not copy the SDK helper's fallback to Text; retain protected source data or block the item |
| `linkedId` | A reference to another cipher property | Retention is not a working linked-field feature; do not substitute a guessed value |
| Login `uris[]` | Ordered URI values with match rules | Keep each URI; retain match metadata without fetching URLs or executing patterns |
| Login `totp` | Source seed/provisioning text | Preserve input; validate algorithm, digits and period before constructing core TOTP; do not treat HOTP or Steam as ordinary numeric TOTP |
| Login `fido2Credentials[]` | Passkey material | Protected retention does not implement passkey use; report this distinction |
| `notes` and type 2 | Item notes and secure-note category | Notes must not lose their protection during conversion or enter search through a fallback |
| Card/identity values | Separate strings, including split names and expiry month/year | Avoid lossy joins; keep the original components for later export |
| `passwordHistory` | Older source passwords and dates | Protected source data, not Confidex signed revision history |
| `creationDate`, `revisionDate`, `archivedDate` | Source timestamps/state | Preserve as provenance; do not forge local epochs or deletion revisions |
| `reprompt` | Source authorization policy | Do not claim this policy was reproduced by copying the property |
| Folders/collections | Source grouping and possible organization membership | Preview group-to-tag mapping; do not claim ACL transfer |

Null and empty are different source states. Missing fields, null values and
unsupported JSON members must not disappear merely because the destination has
a convenient empty string. The original source representation is needed to
explain that distinction and assess future reverse export. No format-wide
lossless reverse conversion is implied.

The shared parser must bound JSON before allocating an unrestricted value tree.
Duplicate object keys need rejection or another explicit lossless policy; last
key wins would silently discard input. This is separate from repeated names in
an ordered custom-field array, which are valid and must survive conversion.

## Implementation handoff

The adapter calls the shared bounded JSON reader and maps one item at a time.
Personal and organization inputs have separate source vault scopes. Duplicate
IDs within one scope are refused; the same ID in different scopes is distinct.
Known card and identity components remain separate fields. Card numbers, CVV and
identity document identifiers are protected; split names and expiry components
are not joined or normalized. Source SSH private keys use the core importer and
remain usable as `ssh/v1`; redundant public strings stay in encrypted provenance.
Mismatched or malformed public strings require protected source retention.

Unsupported items and fields retain the original raw JSON in a protected note,
including integer text that a generic floating-point DOM cannot retain exactly.
Source-only history and URI match modes require review. Original data is a source
snapshot, never authority for the current field values during reverse export.

Document properties and the complete folder/collection table are retained once
under `bitwarden.document.json` in the shared container attributes. Raw JSON
values retain unknown integer text. This plane exists independently of record
selection and an empty item list. Unknown document/group policies require review.

`parse_with` shares the same conversion with archive adapters. A wrapper supplies
extra container attributes and extends each Item before final core validation.
It returns attachment memory reservations to keep their bytes charged until
encoding completes. The Bitwarden document key is reserved. Ordinary JSON and
decrypted JSON use `parse`; archive readers do not copy the semantic mapper.

The synthetic SSH fixture contains a public test key generated with macOS
`ssh-keygen`, not a Bitwarden application capture. Never use it for an account.
The independent golden inputs and the pinned producer capture have separate
provenance, as described in the fixture directory.

The dedicated adapter owns its mapping, tests and format-specific fixtures. It
must consume the common import contract rather than introduce its own UI,
storage, registry, or resource-policy types. ZIP and encrypted JSON must reuse
this semantic mapping after unpacking/decryption; they must not copy its rules.

Before registration, test personal and organization scope, unknown types,
malformed values, hidden fields, non-default TOTP, source-only history, duplicate
names and failed admission on both native and WASM. Parsing must not mutate the
vault or access URLs. Expected Records and diagnostics come from the shared
fixture matrix, not from assertions generated by the adapter under test.
