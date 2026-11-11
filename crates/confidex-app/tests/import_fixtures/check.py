"""Check public fixture consistency. This is not an untrusted-file importer."""

import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import zipfile

sys.dont_write_bytecode = True
from pack_1pux import packed

ROOT = Path(__file__).resolve().parent


def load(name):
    return json.loads((ROOT / name).read_text())


def records(name):
    return load(name)["records"]


def scalar(entry):
    values = entry["value"]
    assert len(values) == 1
    return next(iter(values.values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-keepass", type=Path)
    args = parser.parse_args()
    manifest = load("sha256.json")
    assert manifest
    for name, digest in manifest.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    raw = load("bitwarden_json/personal.json")
    expected = records("bitwarden_json/personal.expected.json")
    login = raw["items"][0]
    fields = expected[0]["record"]["entries"]
    assert raw["encrypted"] is False
    assert len(expected) == len(raw["items"]) == 3
    assert scalar(fields[0]) == login["login"]["username"]
    assert scalar(fields[1]) == login["login"]["password"]
    assert [scalar(e) for e in fields[2:4]] == [u["uri"] for u in login["login"]["uris"]]
    assert [scalar(e) for e in fields[6:10]] == [f["value"] for f in login["fields"]]
    assert fields[6]["name"] == fields[7]["name"] == "Repeated"
    assert login["fields"][1]["type"] == 1
    assert fields[7]["type"] == "secret/v1"
    assert fields[7]["extra"]["metadata"]["protected"] is True
    preserved = json.loads(scalar(fields[-1]))
    assert preserved["passwordHistory"] == login["passwordHistory"]
    assert scalar(expected[1]["record"]["entries"][0]) == raw["items"][1]["notes"]
    assert json.loads(scalar(expected[2]["record"]["entries"][0])) == raw["items"][2]
    org = load("bitwarden_json/organization.json")
    org_expected = records("bitwarden_json/organization.expected.json")[0]
    assert org["items"][0]["id"] == login["id"]
    assert org_expected["source"] != expected[0]["source"]
    assert org_expected["record"]["tags"] == [org["collections"][0]["name"]]
    assert (ROOT / "onepassword_1pux/account.1pux").read_bytes() == packed()
    with zipfile.ZipFile(io.BytesIO(packed())) as archive:
        assert archive.testzip() is None
        data = json.loads(archive.read("export.data"))
        assert json.loads(archive.read("export.attributes"))["version"] == 3
        account = data["accounts"][0]
        item, document, future = account["vaults"][0]["items"]
        one_expected = records("onepassword_1pux/expected.json")
        one_fields = one_expected[0]["record"]["entries"]
        section = item["details"]["sections"][0]
        assert section["fields"][0]["guarded"] is False
        assert one_fields[5]["type"] == "secret/v1"
        assert scalar(one_fields[5]) == section["fields"][0]["value"]["concealed"]
        assert section["fields"][2]["guarded"] is True
        assert one_fields[7]["extra"]["metadata"]["protected"] is True
        assert [e["name"] for e in one_fields[5:9]] == [f["title"] for f in section["fields"][:4]]
        assert all(e["extra"]["confidex.import.section"]["title"] == "Security" for e in one_fields[5:10])
        attributes = document["details"]["documentAttributes"]
        files = [name for name in archive.namelist() if name.startswith("files/" + attributes["documentId"] + "___")]
        assert len(files) == 1
        binary = archive.read(files[0])
        assert len(binary) == attributes["decryptedSize"]
        assert one_expected[1]["record"]["entries"][0]["value"]["data"] == {"$binary": binary.hex()}
        assert json.loads(scalar(one_expected[2]["record"]["entries"][0])) == future
        assert one_expected[0]["source"]["item"] == one_expected[3]["source"]["item"]
        assert one_expected[0]["source"]["vault"] != one_expected[3]["source"]["vault"]
    xml = ET.parse(ROOT / "keepass_xml/database.xml")
    entry = xml.find("./Root/Group/Group/Entry")
    strings = {s.findtext("Key"): s.find("Value") for s in entry.findall("String")}
    xml_expected = records("keepass_xml/expected.json")
    xml_fields = xml_expected[0]["record"]["entries"]
    assert strings["Password"].attrib == {"ProtectInMemory": "True"}
    assert scalar(xml_fields[1]) == strings["Password"].text
    assert xml_fields[2]["extra"]["metadata"]["protected"] is True
    assert xml_fields[3]["type"] == "secure-note/v1"
    assert strings["Hidden custom"].attrib == {"ProtectInMemory": "True"}
    assert xml_fields[5]["type"] == "secret/v1"
    assert xml_expected[1]["status"] == "blocked"
    assert xml_expected[2]["status"] == "excluded"
    text = (ROOT / "csv/generic.csv").read_bytes()
    assert text.startswith(b"\xef\xbb\xbf") and b"\r\n" in text
    rows = list(csv.reader(io.StringIO(text.decode("utf-8-sig"), newline=""), strict=True))
    mapping = load("csv/mapping.json")["columns"]
    csv_expected = records("csv/expected.json")
    assert rows[0][5:8] == ["extra", "extra", ""]
    assert len(rows) == 3 and all(len(row) == len(mapping) for row in rows)
    for field, column in zip(csv_expected[0]["record"]["entries"][:7], mapping[1:8]):
        assert scalar(field) == rows[1][column["index"]]
        assert field["name"] == column["name"]
    assert '\n\n' in rows[1][4] and '"hello",' in rows[1][4]
    assert all(r["source"]["item"] is None for r in csv_expected)
    secret_hex = base64.b32decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").hex()
    for family in [expected, one_expected, xml_expected, csv_expected]:
        for record in family:
            for field in record["record"]["entries"]:
                if field["type"] == "totp/v1":
                    assert field["value"] == {"secret": {"$binary": secret_hex}, "algorithm": "SHA256", "digits": 8, "period": 45, "t0": 0}
    if args.upstream_keepass:
        data = args.upstream_keepass.read_bytes()
        evidence = load("sources.json")["keepass_published_export"]
        assert hashlib.sha256(data).hexdigest() == evidence["sha256"]
        upstream = ET.fromstring(data)
        candidates = [s for s in upstream.iter("String") if s.findtext("Key") == "UserName"]
        assert any(s.find("Value").get("ProtectInMemory") == "True" and s.findtext("Value") == "User Name" for s in candidates)
        print("Published upstream XML export: protection marker verified")
    print("Import fixtures: source values, expected core records and archive bytes are consistent")


if __name__ == "__main__":
    main()
