# Public KDBX producer fixtures

`password.kdbx`, `keyfile.kdbx` and `both.kdbx` are actual KeePassXC 2.8.0
CLI outputs. All credentials and content are public synthetic data:

- Password: `PUBLIC-FIXTURE-DATABASE`.
- `public.key`: the 32 bytes from 0 through 31, in order.
- Attachment: `PUBLIC-FIXTURE-ATTACHMENT` followed by `00 ff 0a`.
- A second attachment is empty.

Each file has three current entries, source history, protected fields, TOTP,
custom data, a recycle bin and binary references. The mail and reference entries
have equal attachment names and bytes. The mail also has the empty attachment.
The CLI is used independently to export all three files and compare every byte.
The XML exports are captured separately; they omit the binary pool.

Input comes from the reviewed sibling `keepass_xml/database.xml`, changing the
group name from `Work/メール` to `Work メール` so that the CLI's slash-separated
entry argument can address it. `input.xml` records the exact submitted bytes.
KeePassXC drops the source's title-only empty entry; the captured output, not
the hand-authored input, is the KDBX baseline. Source history is not an extra
current entry. No application account or user vault is accessed.

The executable reports `KeePassXC 2.8.0`. Its SHA-256 and all fixture hashes are
in `manifest.json`. Actual headers show KDBX **4.0**, AES-256, gzip and AES-KDF;
the producer's target of 100 ms selects about 13 million AES rounds. These
fixtures do not establish Argon2, ChaCha20, KDBX 3.1/4.1 or XML keyfile support.
Those require additional independent variants before a support claim.

To verify hashes, credentials and attachment bytes without regeneration:

```
python3 crates/confidex-app/tests/import_fixtures/kdbx/capture.py KEEPASSXC_CLI
```

To create new random database files and replace this synthetic corpus:

```
python3 crates/confidex-app/tests/import_fixtures/kdbx/capture.py KEEPASSXC_CLI --write
```

Only fixture inputs are written in temporary directories. New captures have
different salts, identifiers and timestamps, so their binary hashes change.
The CLI runs from a read-only application mount; no installation or modification
of the application is needed. The production importer must never extract a
user's plaintext XML or files to disk.

## KDBX 3.1 attachment capture

`legacy-attachments.kdbx` starts from the MIT-licensed public
`vendor/keepass/tests/resources/test_db_with_password.kdbx` sample. KeePassXC 2.8.0
adds the same public binary to two entries and an empty attachment to one entry.
The resulting file remains KDBX 3.1, with two XML pool members and three current
file fields. Password: `demopass`. Payload: `PUBLIC-KDBX3-ATTACHMENT` followed by
`00 ff 0a`. All source credentials and existing sample content are public tests.

`legacy-attachments.json` pins source and capture hashes. The XML is an independent
KeePassXC export; it omits the binary pool. To verify hashes, version and all three
exact attachment exports, run:

```
python3 crates/confidex-app/tests/import_fixtures/kdbx/capture_legacy.py KEEPASSXC_CLI
```

Add `--write` to capture a new database with fresh producer randomness. Verification
compares source XML after sorting CustomData maps and ignoring only the runtime
`Meta/CustomData/_LAST_MODIFIED` value, which KeePassXC changes while exporting.
Other values and exact captured file hashes remain checked. The empty XML pool
member has `Compressed=True` and no gzip bytes, as emitted by KeePassXC.

## Explicit credential presence

`empty-password.kdbx` and `empty-password-keyfile.kdbx` are additional KeePassXC
2.8.0 captures from the same `input.xml`, with the same current fields and three
attachments. The first uses an explicitly empty password. The second combines
that password with `public.key`. Neither opens when its password component is
omitted. An empty password is therefore different from keyfile-only mode.

`credentials.json` pins both captures, their actual headers, source inputs and
the producer executable. The script independently reopens each file, rejects
the omitted-password mode and verifies all six exact attachment exports:

```
python3 crates/confidex-app/tests/import_fixtures/kdbx/capture_credentials.py KEEPASSXC_CLI
```

Use `--write` to regenerate these two public fixtures with fresh randomness.
KeePassXC rejects a zero-byte keyfile; these captures do not claim otherwise.
The adapter separately tests that selecting an empty file cannot silently
disable the keyfile component.
