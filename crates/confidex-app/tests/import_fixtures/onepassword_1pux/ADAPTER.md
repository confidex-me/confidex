# 1PUX v3 adapter coverage

The adapter reads unencrypted 1PUX version 3 through the shared bounded ZIP/JSON
helpers. It never extracts files, fetches URLs/icons, writes storage or asks a
vendor server for data. An encrypted ZIP and an unknown version are refused.
The common import limits apply; large groups can exceed the source/plan/node
budget even when each individual Record fits. Final apply also validates the
whole Record after adding provenance.

Account and vault UUIDs remain separate source scopes. A missing/null item UUID
has no invented replacement: it requires review and cannot enable identity-based
updates. Source locators are diagnostic positions only. Archived items are
Excluded unless explicitly enabled; unsupported fields can still require review.
Source times, favorites and password history do not become local signed history.
Title-only items keep zero fields; missing notes never become an invented empty
note. Standard TOTP parsing uses the shared import helper.

| Source | Result |
| --- | --- |
| loginFields fieldType/type | Both documented spellings; conflicting values stay protected for review |
| Username/password | Independent entries; password type/designation always remains secret |
| Missing loginFields.name | Label from designation, then nonempty HTML id, then field kind; explicit empty names remain empty |
| Text/email/number/phone/checkbox web form strings | Text entries, with protection retained |
| Textarea/notes/multiline text | Secure notes by default |
| URLs | Independent entries in source order; an identical primary URL is represented once; optional labels and string mode hints remain in encrypted provenance |
| Sections | Order, repeated/empty titles and empty groups in canonical current layout; optional source IDs and field context retained |
| string/phone/menu/gender/creditCardType | Scalar text, original source type retained in encrypted provenance |
| concealed/creditCardNumber | Secret regardless of guarded:false; concealed multiline values become secure notes |
| guarded:true | Protected metadata, including URLs |
| TOTP | Valid base32 seed or strict otpauth TOTP URI; binary seed and explicit parameters, original text retained |
| HOTP/Steam/unknown OTP parameters | Protected original fragment and review, no guessed default TOTP |
| email objects | Text email address; provider remains in encrypted source provenance |
| address objects | Multiline note with named street/city/state/zip/country components; protection retained |
| date/monthYear | UTC calendar date and numeric year/month, without an invented day for month precision |
| SSH key objects | Functional ssh/v1 identity; OpenSSH and Ed25519 PKCS#8; conflicting private/public metadata requires protected review |
| Future or malformed values | Protected original fragments and review |
| clipboardFilter | String source hint remains in encrypted provenance; imported values are not filtered or rewritten |
| Unresolved reference field | Blocked with protected original data |
| Unknown item/overview control fields | Blocked; neutral title and protected source data |
| Missing document | Blocked; a declared-size mismatch rejects the input |
| Documents/attachments | Exact file/v1 bytes and filename, including images; no automatic image conversion |
| Section value.file | Independent ordered file/v1 fields, including empty data and repeated labels/filenames; exact document ID, size and section context |
| Unmatched files/custom icons | Retained once in encrypted container context, plan-level review |
| Unknown container attributes/extensions | Retained once with plan-level review |

Protected Original data entries contain only unsupported fragments with JSON Pointer
paths, at the corresponding array position. They do not duplicate already mapped
password fields. A compact raw item snapshot separately preserves original kinds,
flags, null/absence/empty distinctions and source facts in encrypted provenance;
numeric literals do not round through a floating-point DOM serialization.
The container keeps export attributes and account/vault/root context once, with
item arrays excluded. This avoids copying vault metadata into every Record.

Retained source snapshots and original provisioning URIs can contain old values.
The writer takes current values and field presence from the current
Record, reports unsupported semantics, and never replays a snapshot blindly after
an edit or deletion. See the sibling export fixture `COVERAGE.md` for the writer
mapping and independent consumer limits; lossless reverse conversion is not
assumed from successful import.

## Evidence and profiles

- [Official format documentation](https://support.1password.com/1pux-format/)
  describes version 3, export.attributes/export.data/files, account/vault/item
  scopes, concealed values and documentId plus a triple underscore filename.
  The prose says loginFields.type; the example uses fieldType.
- The existing account.1pux/export tree is explicitly schema-derived synthetic
  data. Its four Records exercise two vaults, repeated names, protection, advanced
  TOTP and binary bytes. Its original golden contract remains unchanged; adapter
  checks additionally verify full provenance, per-fragment reports and default
  archived exclusion.
- [Captured template archive](docs/TEMPLATES.md) covers 22 items and 175 section
  fields from a 1Password UI export after sanitization. Every section field maps
  to a normal editable field, with no JSON Original data entries for this capture.
- The published [KeePassXC test export](https://github.com/keepassxreboot/keepassxc/blob/6bcb901aefdd6c7a525466d7dfe099c5ebc13c0e/tests/data/1PasswordExport.1pux)
  has SHA-256 `6b47d336892273870380dac87b63014c0de65f2f4b6bd11c5cba0fd277725b02`.
  It was introduced with [the importer](https://github.com/keepassxreboot/keepassxc/pull/9815)
  and later includes a manually added legacy password item without UUID. It has
  version 3 with a timestamp attribute, two vaults, nine items and an actual
  documentId__filename member. The pinned [reader](https://github.com/keepassxreboot/keepassxc/blob/6bcb901aefdd6c7a525466d7dfe099c5ebc13c0e/src/format/OPUXReader.cpp)
  independently confirms the historical double underscore profile. This is a
  published reader fixture, not a new capture from an installed 1Password client;
  the exact producer application version is unknown.

Both document profiles require the exact full document ID, filename and declared
size. If both paths exist, the item is blocked unless its explicit file.path
selects a matching full path. A basename match or first-file fallback is never
used. The selected path stays in encrypted provenance.

Section file fields use the same exact resolver as the main document. Their
labels and section metadata stay independent from the original filename; each
selected path stays in the field's provenance. File-buffer and reservation-header
charges remain live until the completed Record enters the common plan. The
pinned KeePassXC reader's `value.file` branch independently confirms this binding.
Its destination attachment map can overwrite repeated filenames; that reader
limitation does not change the ordered 1PUX source model.

## Checks

```sh
cargo test -p confidex-app --test import_onepassword
cargo test -p confidex-app --test export_onepassword_1pux
CARGO_TARGET_WASM32_WASIP1_RUNNER="node $PWD/crates/confidex-app/tests/run-wasi.mjs" cargo test -p confidex-app --test import_onepassword --target wasm32-wasip1 -- --test-threads=1
```

The separate ten_thousand_login_items calibration maps 10,000 logins with
username, password and URL; add `--ignored --exact ten_thousand_login_items
--nocapture` after `--`. It measures parsing/mapping/validation/plan, not signing,
atomic apply, indexing or UI responsiveness. Those belong to host integration.

The optional native published_upstream_sample check takes the pinned public ZIP
through CONFIDEX_TEST_1PUX, verifies its digest, and checks all nine items/document
without printing names or values. Normal tests need neither that download nor a
network connection. There is no claim of a fresh vendor UI/CLI roundtrip.
