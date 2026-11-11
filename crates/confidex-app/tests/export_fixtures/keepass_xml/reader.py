"""Import actual public writer output with KeePassXC and verify its own export."""
import base64
import hashlib
import re
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

cli, source_path = map(Path, sys.argv[1:])
database = source_path.with_suffix(".kdbx")
password = b"PUBLIC-XML-EXPORT-DATABASE\n"
version = subprocess.check_output([str(cli), "--version"], text=True).strip()
subprocess.run([str(cli), "import", "-q", "-p", "-t", "100", str(source_path), str(database)],
               input=password * 2, capture_output=True, check=True, timeout=30)
output = subprocess.run([str(cli), "export", "-q", str(database)],
                        input=password, capture_output=True, check=True, timeout=30).stdout
source = ET.parse(source_path).find(".//Entry")
actual = ET.fromstring(output).find(".//Entry")
assert source is not None and actual is not None

def fields(entry):
    result = {}
    for field in entry.findall("String"):
        key = field.findtext("Key", "")
        assert key not in result
        value = field.find("Value")
        assert value is not None
        assert value.get("Protected") is None
        result[key] = (value.text or "", value.get("ProtectInMemory", "False").lower() == "true")
    return result

expected = fields(source)
for key, (value, protected) in expected.items():
    if not key:
        continue
    shown = subprocess.run([str(cli), "show", "-q", "-s", "-a", key, str(database), expected["Title"][0]],
                           input=password, capture_output=True, check=True, timeout=30).stdout
    stored_value = value if protected else value.replace("\r\n", "\n").replace("\r", "\n")
    assert shown == stored_value.encode("utf8") + b"\n", (key, "CLI value differs", shown)
observed = fields(actual)
assert list(observed) == sorted(expected, key=lambda key: key.encode("utf-16-be"))
normalized = {key: (value.replace("\r\n", "\n").replace("\r", "\n"), protected)
              for key, (value, protected) in expected.items()}
assert observed == normalized, {key: {"expected": normalized.get(key), "actual": observed.get(key)}
                              for key in expected.keys() | observed.keys()
                              if normalized.get(key) != observed.get(key)}
for key in ["UserName", "Password", "URL", "Notes", "Hidden", "otp"]:
    assert expected[key][1]
assert source.findtext("UUID") == actual.findtext("UUID")
assert [tag.strip() for tag in re.split(r"[,;\t]", actual.findtext("Tags"))] == ["Work", "旅行"]
created = actual.findtext("Times/CreationTime")
assert int.from_bytes(base64.b64decode(source.findtext("Times/CreationTime"), validate=True), "little") == 1735689600 + 62135596800
assert created == "2025-01-01T00:00:00Z", created
root = ET.parse(source_path).getroot()
pool = {int(value.get("ID")): base64.b64decode(value.text or "", validate=True)
        for value in root.findall("Meta/Binaries/Binary")}
payloads = []
for index, binary in enumerate(source.findall("Binary")):
    name = binary.findtext("Key")
    payload = pool[int(binary.find("Value").get("Ref"))]
    target = source_path.with_name("attachment-" + str(index) + ".bin")
    subprocess.run([str(cli), "attachment-export", "-q", str(database), expected["Title"][0], name, str(target)],
                   input=password, capture_output=True, check=True, timeout=30)
    assert target.read_bytes() == payload
    payloads.append(payload)
assert payloads == [bytes(n % 256 for n in range(6145)), b""]
print(version + ": actual XML import/export values, memory protection, UUID, tags and timestamp PASS; declared CR/CRLF normalization")
print("XML binary pool -> actual database -> exact attachment export PASS, including empty file")
print("Reader binary SHA256: " + hashlib.sha256(cli.read_bytes()).hexdigest())
