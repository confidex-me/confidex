# Bitwarden individual ZIP writer

The writer emits the individual name-folder profile established by the
[pinned producer corpus](../../import_fixtures/bitwarden_zip/CAPTURE.md):
root `data.json` and `attachments/<sanitized item name>/<filename>`.
It reuses the personal [JSON writer](../bitwarden_json/COVERAGE.md).
This is a plaintext archive, without an organization profile or account binding.
The host registers this writer in the common export form, without an
Organization selector. Both loss consent and plaintext confirmation are required.

Current record values are authoritative. JSON items receive fresh, unique UUIDs;
each attachment directory must identify exactly one of those items by its name.
The official profile has no ID-based attachment manifest. Duplicate item names,
distinct names with equal sanitized forms, and ambiguous numeric suffixes are
rejected before writing any archive bytes. Repeated names without attachments
are valid. No arbitrary suffix, record rename, or guessed owner repairs a collision.

Attachment bytes and safe filenames are preserved, including empty files,
Unicode, multiple dots, and equal filenames in different items. The writer does
not apply the producer's lossy filename cleanup to already safe names.
Empty names, path separators, colons, control characters, dot components,
overlong paths and duplicate member names are blocked. Malformed file values
and explicit protected-file flags are blocked and cannot be overridden by loss
consent. `photo/v1` becomes `file/v1` with a type-loss issue; MIME changes,
different field labels, reordered files, extra values and metadata are reported.
All other field, tag, history and policy losses use the shared JSON review.
Source snapshots never restore a deleted field, old password or old file path.

Files stream from borrowed values to a stored ZIP in bounded chunks. JSON is
serialized directly into the same archive, without a full intermediate JSON
buffer or plaintext extraction directory. Name indexes, item IDs and ZIP
directory scratch are charged before allocation. Entry and central-directory
limits are checked before serialization. The shared output enforces memory,
size and cancellation limits; failure never releases a partial artifact.

## Independent checks

`reader.py` uses Python's standard ZIP reader on actual writer bytes to check
framing, CRC, member uniqueness, permissions, UUIDs and every attachment's exact
name, SHA256 and size. `reader.cjs` runs the hash-pinned upstream Bitwarden JSON
importer on `data.json`. Its source list and test boundaries are shared with the
[JSON reader](../bitwarden_json/COVERAGE.md). It checks current credentials,
URIs, repeated/empty/hidden custom fields, folders and cleanup of account IDs.
Neither reader uses our ZIP parser or JSON semantic mapper.

With Python3, Node26 and the pinned source cache, run from the repository root:

```sh
CONFIDEX_BITWARDEN_SOURCE=/path/to/sources cargo test -p confidex-app --test export_bitwarden_zip -- --include-ignored --nocapture
```

Only synthetic public bytes enter this test, through pipes; no user vault,
account or temporary plaintext file is used. Portable tests run on native and
WASI. The feature-only browser worker runs the same roundtrip, exact binary
comparison, monotonic progress, output limit and cancellation checks through
`apps/confidex/web/export-check.mjs`. Production registry and actual save dialogs
are covered by their shared host integration, not by this container module.

## Limits of compatibility

The shared browser UI check uses the production registry (`export-ui-check`
build feature, `bitwarden-zip` mode in `apps/confidex/web/export-ui-check.mjs`). Desktop and
narrow cases download one selected record or all records only after Save.
Python's ZIP reader verifies the actual files, CRC, unique paths/UUIDs and the
exact 600001-byte attachment. The pinned JSON importer reads current passwords,
empty/repeated/hidden custom fields and folder links. Ready cancellation, save
failure and vault lock publish no extra file. These host checks do not simulate
automatic attachment upload into Bitwarden.

The official ZIP has no complete attachment inventory. A producer can skip a
download without recording that omission in the archive. Our importer therefore
continues to require an independent container review, even for our ZIP output;
it does not claim verified completeness of a source Bitwarden vault.

The [Bitwarden export guide](https://bitwarden.com/help/export-your-data/)
documents individual ZIP exports. The
[import guide](https://bitwarden.com/help/import-data/)
requires attachments to be uploaded separately. The independent check proves
ZIP framing/files and the upstream JSON mapping layer, not automatic attachment
uploading or a full installed Bitwarden import. No account-based UI, Safari,
Firefox, Windows or Linux runtime result is implied. Plaintext files remain
plaintext regardless of whether individual values are hidden in a password UI.
