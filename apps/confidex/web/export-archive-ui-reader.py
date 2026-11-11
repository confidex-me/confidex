"""Check public UI downloads with Python's independent ZIP reader."""
from hashlib import sha256
import json
import sys
import uuid
import zipfile

kind, filename = sys.argv[1:]
expected = bytes(i % 251 for i in range(600_001))
with zipfile.ZipFile(filename) as archive:
    assert archive.testzip() is None
    names = archive.namelist()
    assert len(names) == len(set(names))
    for info in archive.infolist():
        assert info.compress_type == zipfile.ZIP_STORED
        assert not info.flag_bits & 1
        assert info.external_attr >> 16 & 0o777 == 0o600
    if kind == "bitwarden-zip":
        data = archive.read("data.json").decode("utf8")
        document = json.loads(data)
        items = document["items"]
        assert document["encrypted"] is False and "collections" not in document
        ids = [uuid.UUID(item["id"]) for item in items]
        assert len(ids) == len(set(ids))
        assert all(identifier.version == 4 for identifier in ids)
        assert items[0]["name"] == "公開" * 100
        assert items[0]["login"]["password"] == "current public password\n第二行"
        member = "attachments/" + items[0]["name"] + "/公開.dat"
        files = [name for name in names if name.startswith("attachments/") and not name.endswith("/")]
        assert files == [member]
        assert set(names) == {"data.json", "attachments/", "attachments/" + items[0]["name"] + "/", member}
    else:
        assert kind == "onepassword-1pux"
        attributes = json.loads(archive.read("export.attributes"))
        assert attributes["version"] == 3 and attributes["createdAt"] > 0
        data = archive.read("export.data").decode("utf8")
        account = json.loads(data)["accounts"][0]
        vault = account["vaults"][0]
        items = vault["items"]
        assert items[0]["overview"]["title"] == "公開" * 100
        ids = [account["attrs"]["uuid"], vault["attrs"]["uuid"]]
        files = []
        for item in items:
            ids.append(item["uuid"])
            assert item["createdAt"] == item["updatedAt"] == attributes["createdAt"]
            assert item["state"] == "active"
            for section in item["details"]["sections"]:
                for field in section["fields"]:
                    descriptor = field["value"].get("file")
                    if descriptor is None:
                        continue
                    ids.append(descriptor["documentId"])
                    assert descriptor["fileName"] == "公開.dat"
                    assert descriptor["decryptedSize"] == len(expected)
                    files.append("files/" + descriptor["documentId"] + "___" + descriptor["fileName"])
        assert len(ids) == len(set(ids))
        assert len(files) == 1
        member = files[0]
        assert set(names) == {"export.attributes", "export.data", member}
    assert len(items) in [1, 2]
    payload = archive.read(member)
    assert payload == expected
    assert "old public password" not in data and "deleted public password" not in data
print(json.dumps({"data": data, "records": len(items), "attachmentBytes": len(payload),
                  "attachmentSha256": sha256(payload).hexdigest()}))
