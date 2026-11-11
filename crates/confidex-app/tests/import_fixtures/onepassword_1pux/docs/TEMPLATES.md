# Captured template fixture

`templates.1pux` is a sanitized derivative of a user-supplied 1Password UI export.
The producer application version was not recorded. The archive uses 1PUX v3.
The archive contains `export.attributes`, `export.data` and two files in `files/`.

The fixture contains 22 items, 21 category IDs, 175 section fields and four login
fields. Login and Password share category `001`. It includes all templates from
this capture, not a claim about every template in every 1Password version.

Account details, source identifiers, timestamps, notes, subtitles, tags, login
values and field contents were replaced with public fixture values. Menu choices,
field identifiers, labels, ordering, value shapes and protection flags remain.
URLs and email addresses use `example.invalid`. The credit card uses the public
test number `4111111111111111`. Never use fixture credentials for a real account.

The SSH item contains a valid Ed25519 PKCS#8 private key made from 32 bytes of
`0x42`, with its derived public key and fingerprint. Both copies of the key were
replaced. This preserves the producer's PKCS#8 profile without publishing the
original generated key.

Both PNG files were inspected: one gradient document and one folder icon. They
contain only IHDR, IDAT and IEND chunks, with no EXIF or text metadata. Their bytes
are unchanged; their source identifiers were replaced. The unmatched icon tests
protected container retention. Finder metadata is excluded.

The ZIP stores the four source files without compression, in sorted path order,
with timestamp `2026-01-01 00:00:00` and Unix mode `100644`.

Run `cargo test -p confidex-app --test import_onepassword templates::` to check
category coverage, source scope, all 175 editable section fields, SSH signing,
protected rejection of malformed values and exact attachment bytes.
