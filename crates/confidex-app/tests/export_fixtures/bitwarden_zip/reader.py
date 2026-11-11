"""Read synthetic ZIP bytes independently, then execute the pinned JSON consumer."""
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import subprocess
import sys
import uuid
import zipfile

with zipfile.ZipFile(BytesIO(sys.stdin.buffer.read())) as archive:
    assert archive.testzip() is None
    names = archive.namelist()
    expected = {
        "attachments/Почта _ 東京/same.bin": bytes([0, 255, 7]),
        "attachments/Почта _ 東京/empty.bin": b"",
        "attachments/Почта _ 東京/scan.part.txt": b"PUBLIC-DOTS",
        "attachments/Почта _ 東京/公開 café.bin": b"PUBLIC-UNICODE",
        "attachments/Second/same.bin": bytes([42]),
    }
    assert len(names) == len(set(names)) == 9
    assert set(names) == set(expected) | {
        "data.json", "attachments/", "attachments/Почта _ 東京/", "attachments/Second/"
    }
    for info in archive.infolist():
        assert info.compress_type == zipfile.ZIP_STORED
        assert info.flag_bits & 1 == 0
        assert info.external_attr >> 16 & 0o777 == 0o600
    for path, data in expected.items():
        actual = archive.read(path)
        assert len(actual) == len(data)
        assert sha256(actual).digest() == sha256(data).digest()
    data = archive.read("data.json")
    document = json.loads(data)
    assert document["encrypted"] is False and "collections" not in document
    items = document["items"]
    assert [item["name"] for item in items] == ["Почта / 東京", "Second"]
    ids = [uuid.UUID(item["id"]) for item in items]
    assert len(ids) == len(set(ids)) == 2
    assert all(identifier.version == 4 for identifier in ids)
    assert all("attachments" not in item for item in items)

subprocess.run([
    "node", str(Path(__file__).with_name("reader.cjs")), sys.argv[1]
], input=data, check=True)
print("Independent ZIP framing, CRC, filenames, attachment SHA256/size and item IDs: PASS")
