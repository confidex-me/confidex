"""Check pristine upstream files and the separately recovered public fixture."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PATCHED = {
    "Cargo.toml", "Cargo.lock", "src/lib.rs", "src/compression.rs", "src/db/mod.rs",
    "src/format/variant_dictionary.rs",
    "src/config.rs", "src/crypt/mod.rs", "src/crypt/kdf.rs", "src/format/kdbx4/mod.rs",
    "src/crypt/ciphers.rs",
    "src/key/mod.rs",
    "src/format/kdbx4/dump.rs",
    "src/format/kdbx4/parse.rs",
    "src/format/hmac_block_stream.rs",
}
manifest = json.loads((ROOT / "UPSTREAM.json").read_text())
for name, expected in manifest["files"].items():
    data = (ROOT / name).read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    assert name in PATCHED or actual == expected, name
for name, source in manifest["extra_files"].items():
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == source["sha256"], name
print("Unmodified upstream files and public test fixture: PASS")
