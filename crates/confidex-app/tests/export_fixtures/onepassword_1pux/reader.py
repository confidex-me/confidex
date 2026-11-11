"""Check the public writer ZIP independently, then run the pinned JSON consumer."""
import json
from pathlib import Path
import subprocess
import sys
import zipfile

archive, shared_sources, sources = sys.argv[1:]
with zipfile.ZipFile(archive) as source:
    assert source.testzip() is None
    names = source.namelist()
    assert len(names) == len(set(names)) == 4
    assert set(names[:2]) == {"export.attributes", "export.data"}
    attributes = json.loads(source.read("export.attributes"))
    assert attributes["version"] == 3
    assert attributes["createdAt"] == 1735689600
    data = source.read("export.data")
    document = json.loads(data)
    account = document["accounts"][0]
    vault = account["vaults"][0]
    items = vault["items"]
    assert len(items) == 2
    ids = [account["attrs"]["uuid"], vault["attrs"]["uuid"]]
    payloads = []
    bound_names = []
    for item in items:
        ids.append(item["uuid"])
        assert item["createdAt"] == item["updatedAt"] == 1735689600
        assert item["state"] == "active"
        section_names = [s["name"] for s in item["details"]["sections"]]
        assert len(section_names) == len(set(section_names))
        for section in item["details"]["sections"]:
            for field in section["fields"]:
                if "file" not in field["value"]:
                    continue
                file = field["value"]["file"]
                ids.append(file["documentId"])
                assert file["fileName"] == "same.bin"
                name = "files/" + file["documentId"] + "___" + file["fileName"]
                bound_names.append(name)
                payload = source.read(name)
                assert len(payload) == file["decryptedSize"]
                payloads.append(payload)
    assert len(ids) == len(set(ids))
    assert payloads == [bytes([0, 255, 7]), b""]
    assert sorted(name for name in names if name.startswith("files/")) == sorted(bound_names)

subprocess.run([
    "node", str(Path(__file__).with_name("reader.cjs")), shared_sources, sources
], input=data, check=True)
print("Independent ZIP framing, CRC, unique scopes and exact attachment bindings: PASS")
