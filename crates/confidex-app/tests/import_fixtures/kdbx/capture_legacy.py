"""Capture and verify public KDBX 3.1 attachments with KeePassXC."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = ROOT / "vendor/keepass/tests/resources/test_db_with_password.kdbx"
DATA = b"PUBLIC-KDBX3-ATTACHMENT\x00\xff\n"
FILES = [("Sample Entry", "public.bin", DATA),
         ("General/Sample Entry #2", "shared.bin", DATA),
         ("Sample Entry", "empty.bin", b"")]


def run(cli, *args):
    return subprocess.run([cli, *map(str, args)], input=b"demopass\n",
                          capture_output=True, check=True).stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def xml_facts(data):
    tree = ET.fromstring(data)
    # KeePassXC emits CustomData maps in a process-dependent order.
    for node in tree.iter("CustomData"):
        node[:] = sorted(node, key=lambda item: item.findtext("Key", ""))
    for item in tree.findall("./Meta/CustomData/Item"):
        if item.findtext("Key") == "_LAST_MODIFIED":
            item.find("Value").text = "runtime timestamp"
    for node in tree.iter():
        node.tail = None
        if len(node) and not (node.text or "").strip():
            node.text = None
    return ET.tostring(tree)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    database = HERE / "legacy-attachments.kdbx"
    export = HERE / "legacy-attachments.xml"
    manifest = HERE / "legacy-attachments.json"
    with tempfile.TemporaryDirectory(prefix="confidex-public-kdbx3-", dir=ROOT.parent) as directory:
        work = Path(directory)
        if args.write:
            candidate = work / "legacy.kdbx"
            shutil.copyfile(SOURCE, candidate)
            for index, (entry, name, data) in enumerate(FILES):
                content = work / f"input-{index}"
                content.write_bytes(data)
                run(args.cli, "attachment-import", "-q", candidate, entry, name, content)
            assert struct.unpack("<HH", candidate.read_bytes()[8:12]) == (1, 3)
            shutil.copyfile(candidate, database)
            export.write_bytes(run(args.cli, "export", "-q", database))
            manifest.write_text(json.dumps({
                "producer": run(args.cli, "--version").decode().strip(),
                "producer_executable_sha256": digest(Path(args.cli)),
                "source_sha256": digest(SOURCE),
                "files": {path.name: digest(path) for path in [database, export]},
            }, indent=2) + "\n")
        facts = json.loads(manifest.read_text())
        assert facts["source_sha256"] == digest(SOURCE)
        for path in [database, export]:
            assert facts["files"][path.name] == digest(path)
        assert struct.unpack("<HH", database.read_bytes()[8:12]) == (1, 3)
        for index, (entry, name, expected) in enumerate(FILES):
            output = work / f"output-{index}"
            run(args.cli, "attachment-export", "-q", database, entry, name, output)
            assert output.read_bytes() == expected
        assert xml_facts(run(args.cli, "export", "-q", database)) == xml_facts(export.read_bytes())
    print("Verified KDBX 3.1, source hash, public XML and three exact attachments")


if __name__ == "__main__":
    main()
