# Bitwarden JSON writer

This writer provides separate plaintext personal and organization profiles.
Registration and profile selection belong to the host integration. It does not
claim support for every Bitwarden item type or an installed application's import
flow.

`Profile::Personal` emits `folders` and one folder reference per item.
Additional tags require explicit loss consent. `Profile::Organization` emits
`collections` and all current tag memberships. Both profiles deduplicate group
names and use separate output filenames. Synthetic UUIDs only connect objects
inside this plaintext file; they are not Confidex IDs or encryption material.
The organizational profile does not restore ownership, access rules, or an
account-bound export. Bitwarden's pinned importer resets imported account IDs.

Current coverage:

- Each CoreRecord produces one item. Current title and field values are
  authoritative. Import snapshots never restore old or deleted passwords.
- Ordered custom fields retain empty/repeated names, Unicode, multiline text,
  and text/hidden kinds. Imported Boolean fields retain kind2 only while the
  current value is a valid Boolean string. Null linked IDs remain null.
- Native username/password, multiple URIs, one TOTP and one note use Bitwarden's
  standard properties. Changes to field names, ordering and protection appear
  in the review before writing. Further string fields remain custom fields;
  type changes also require loss consent.
- Card and identity components with explicit source group/slot bindings use
  native categories. Their current types must still match the binding; edited
  types and repeated slots become custom fields with a source-context warning.
  The importer and writer share the component table. No record category is
  inferred from editable field names.
- Native SSH uses the core key loader and emits OpenSSH private/public keys and
  a fingerprint. Validation and serialization each reserve the core's 8MiB
  scratch allowance against the shared budget. Invalid keys block the review.
  The independent key fixture exercises Ed25519; other algorithms are governed
  by the existing core loader, not an extension-based compatibility claim.
- TOTP is generated from the current binary seed, SHA1/SHA256/SHA512 algorithm,
  digits and period. Nonzero starting epochs cannot be represented and require
  explicit loss consent. RFC4648 encoding vectors are independent expected data.
- Original TOTP URI/seed text is retained only when it decodes to the current
  parameters. This preserves provider labels without replaying a changed seed
  or old digits/period. Parsing scratch is charged before allocation. Further
  TOTP fields become hidden provisioning-URI custom fields with a type warning.
- Favorite/reprompt and unambiguous URI-match policies are reconciled from
  versioned Bitwarden provenance. Changed or ambiguous URI bindings lose that
  policy only after source-context and protection warnings. Other vendors'
  similarly named attributes are not applied.
- The source reader normalizes blank titles to `--`; this appears in review.
  Missing titles use that placeholder. Blank notes remain custom values because
  the reader removes blank native notes; their type change also appears in review.
- Unsupported structured fields, attachments, additional values, unrepresented
  source context and unknown metadata produce loss issues. The default consent
  refuses any such export. Ciphertext and signatures never become vendor history.
- JSON serialization borrows current values instead of building a JSON tree.
  Group allocations are charged before insertion. The shared Output bounds the
  file, checks cancellation during writes and clears failed output.

Core encoding sorts tags. Roundtrip tests compare their canonical set order;
entry order remains significant and is checked separately.

Unsupported structured fields (including compound `card/v1`), extra SSH keys,
attachments and future categories are not silently converted into a native
category. They require loss consent or another format. Confidex-only provenance,
signatures, history and policy data are never emitted as vendor password history.

The portable tests also run as WASI. The feature-only browser proof executes the
same writer in a real browser worker. It does not register production formats.
Registry, profile selection and real browser publication remain host integration.

`reader.cjs` executes the pinned Bitwarden JSON importer, model `toView` methods,
type guards, base cleanup and whitespace test against actual writer output:
seven public records in each profile. View constructors are property bags and
the log/crypto boundaries are test objects. This proves the read/mapping layer;
it does not exercise UI validation, TOTP generation, encryption, account access
or storage in an installed Bitwarden application.

Fetch the files in the sibling import corpus's `capture-sources.json` and in
`reader-sources.json` from their pinned commit. Save each by basename, except
where a `local` name is specified. The reader verifies every executed file hash.
With Node26.10.0, run from the repository root:

```sh
CONFIDEX_BITWARDEN_SOURCE=/path/to/sources cargo test -p confidex-app --test export_bitwarden_json pinned_independent_reader -- --ignored --nocapture
```

The test uses temporary public files and never reads a user vault or account.

Sources:

- [Bitwarden custom JSON import format](https://bitwarden.com/help/condition-bitwarden-import/).
- [Pinned Bitwarden JSON importer](https://github.com/bitwarden/clients/blob/2ff80e50951792379f970f65cd4fb585fc50bbd5/libs/importer/src/importers/bitwarden/bitwarden-json-importer.ts),
  SHA256 `25f3435d2f1cae713a8109107d2048c800a091604fe8d7ebb4b5a0f9bb0fe844`.
- [Pinned producer and field models](../../import_fixtures/bitwarden_json/CAPTURE.md)
  used by the separate import corpus. Export tests use their own expected values.
