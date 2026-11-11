"""Read public KDBX downloads or import public XML downloads with KeePassXC."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

cli, root = Path(sys.argv[1]), Path(sys.argv[2])
xml_input = len(sys.argv) > 3 and sys.argv[3] == "xml"
expected = bytes(i % 251 for i in range(600_001))
cases = []
for width in [1320, 390]:
    for mode in (["password"] if xml_input else ["password", "keyfile", "both", "empty-both"]):
        database = root / f"{width}-{mode}.kdbx"
        if xml_input:
            source = root / f"{width}-keepass-xml-selected.xml"
            subprocess.run([str(cli), "import", "-q", "-p", "-t", "100", str(source), str(database)],
                           input=b"PUBLIC-EXPORT\n" * 2, capture_output=True, check=True, timeout=30)
        flags = ["-q"]
        if mode == "keyfile":
            flags += ["--no-password"]
        if mode != "password":
            flags += ["-k", str(root / "public.key")]
        secret = b"" if mode == "keyfile" else (b"\n" if mode == "empty-both" else b"PUBLIC-EXPORT\n")

        def run(command, args=(), stdin=secret):
            return subprocess.run([str(cli), command, *flags, str(database), *args],
                                  input=stdin, capture_output=True, timeout=30)

        result = run("export")
        assert result.returncode == 0, (width, mode, result.stderr)
        xml = ET.fromstring(result.stdout)
        entries = xml.findall(".//Entry")
        assert len(entries) == 1, (width, mode, len(entries))
        entry = entries[0]
        fields = {field.findtext("Key"): field.find("Value") for field in entry.findall("String")}
        assert fields["Title"].text == "公開" * 100
        assert fields["Password"].text == "current public password\n第二行"
        assert fields["Password"].get("ProtectInMemory") == "True"
        assert b"old public password" not in result.stdout and b"deleted public password" not in result.stdout
        assert b"PUBLIC-FIRST" not in result.stdout and b"PUBLIC-SECOND" not in result.stdout

        def entry_path(group, parents=()):
            path = parents + (group.findtext("Name", ""),)
            if entry in list(group):
                return "/".join(path[1:] + (fields["Title"].text,))
            for child in group.findall("Group"):
                found = entry_path(child, path)
                if found is not None:
                    return found

        path = entry_path(xml.find("Root/Group"))
        assert path is not None
        attachment = root / f"{width}-{mode}-public.dat"
        result = run("attachment-export", [path, "公開.dat", str(attachment)])
        assert result.returncode == 0 and attachment.read_bytes() == expected, (width, mode, result.stderr)
        if mode != "keyfile":
            assert run("show", [path], stdin=b"PUBLIC-WRONG\n").returncode != 0
        cases.append({"width": width, "mode": mode, "bytes": database.stat().st_size,
                      "currentValues": True, "attachmentSha256": hashlib.sha256(expected).hexdigest()})
print(json.dumps({"reader": subprocess.check_output([str(cli), "--version"], text=True).strip(),
                  "sha256": hashlib.sha256(cli.read_bytes()).hexdigest(), "cases": cases}))
