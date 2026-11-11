# Public KDBX source-edit captures

These five files are actual KeePassXC 2.8.0 CLI outputs. Each starts from the
matching [credential fixture](../../../import_fixtures/kdbx/CAPTURE.md). The CLI
edits only the current password of `Work メール/Почта — 東京` to the public test
marker `SOURCE-EDIT-PASSWORD-PRIVATE`. Database credentials remain unchanged.
All data, database passwords and keyfile bytes are synthetic public fixtures.

`capture-kdbx.py` independently exports the original and edited databases into
memory. It verifies the protected current password, stable entry UUIDs, the exact
added history snapshot and every other XML value, including old history. The
comparison permits only the selected entry's modification/access timestamps,
KeePassXC's `_LAST_MODIFIED` runtime CustomData values, its random database padding
`KPXC_RANDOM_SLUG`, CustomData map ordering and XML indentation. It does not
ignore arbitrary unknown fields. Every exact attachment is independently
exported and compared: shared binary twice and an empty file in each mode.
The encryption version, cipher, compression and KDF parameters must remain equal.

`manifest.json` pins the producer executable, capture script, original keyfile,
source file and resulting encrypted file hashes. No plaintext XML is saved.
Only public attachment bytes are written in a scratch directory beside the repo.
The original adapter fixtures are never changed by this script.

From the repo root, verify without regeneration:

```sh
python3 crates/confidex-app/tests/import_integration/capture-kdbx.py /path/to/keepassxc-cli
```

Add `--write` to capture new files with fresh producer randomness. The generated
hashes change. These captures support the shared source/local edit scenario;
they do not prove credential UI behavior or compatibility of a Confidex KDBX
writer.
