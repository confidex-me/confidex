"""Capture public KDBX source-password edits with the real KeePassXC CLI."""
import argparse
from copy import deepcopy
import hashlib
import json
import re
from pathlib import Path
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
INPUT = HERE.parent / "import_fixtures/kdbx"
OUTPUT = HERE / "fixtures/kdbx"
sys.path.insert(0, str(INPUT))
from capture import PASSWORD, PAYLOAD, header, run
from capture_legacy import xml_facts

SOURCE = "SOURCE-EDIT-PASSWORD-PRIVATE"
ENTRY = "Work メール/Почта — 東京"
UUID = "EREREREREREREREREREREQ=="
MODES = [("password", PASSWORD, False), ("keyfile", None, True),
         ("both", PASSWORD, True), ("empty-password", "", False),
         ("empty-password-keyfile", "", True)]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current(tree):
    matches = [entry for group in tree.iter("Group") for entry in group.findall("Entry")
               if entry.findtext("UUID") == UUID]
    assert len(matches) == 1
    return matches[0]


def facts(tree):
    tree = deepcopy(tree)
    # KeePassXC emits runtime timestamps in database and entry CustomData.
    for node in tree.iter("CustomData"):
        for item in node.findall("Item"):
            if item.findtext("Key") == "_LAST_MODIFIED":
                item.find("Value").text = "runtime timestamp"
    return xml_facts(ET.tostring(tree))


def verify_edit(before, after):
    a, b = ET.fromstring(before), ET.fromstring(after)
    original, changed = current(a), current(b)
    passwords = [node.find("Value") for node in original.findall("String")
                 if node.findtext("Key") == "Password"]
    changed_passwords = [node.find("Value") for node in changed.findall("String")
                         if node.findtext("Key") == "Password"]
    assert len(passwords) == len(changed_passwords) == 1
    assert passwords[0].text == "PUBLIC-FIXTURE-PASSWORD"
    assert changed_passwords[0].text == SOURCE
    assert passwords[0].attrib == changed_passwords[0].attrib == {"ProtectInMemory": "True"}
    old_history, new_history = original.find("History"), changed.find("History")
    assert len(new_history) == len(old_history) + 1
    snapshot = deepcopy(original)
    snapshot.remove(snapshot.find("History"))
    assert facts(snapshot) == facts(new_history[-1])
    new_history.remove(new_history[-1])
    passwords[0].text = SOURCE
    for name in ("LastModificationTime", "LastAccessTime"):
        original.find("Times/" + name).text = changed.findtext("Times/" + name)
    # KeePassXC replaces its random padding on each database save.
    def slug(tree):
        matches = [node.find("Value") for node in tree.findall("./Meta/CustomData/Item")
                   if node.findtext("Key") == "KPXC_RANDOM_SLUG"]
        assert len(matches) == 1
        return matches[0]
    old_slug, new_slug = slug(a), slug(b)
    assert re.fullmatch("[0-9a-f]+", old_slug.text)
    assert re.fullmatch("[0-9a-f]+", new_slug.text)
    new_slug.text = old_slug.text
    assert facts(a) == facts(b), "Unrelated XML changed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    manifest_path = OUTPUT / "manifest.json"
    manifest = {"producer": run(args.cli, ["--version"], "").decode().strip(),
                "producer_sha256": digest(args.cli), "capture_sha256": digest(Path(__file__)),
                "keyfile_sha256": digest(INPUT / "public.key"), "files": {}}
    if args.write:
        OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="confidex-public-kdbx-edit-", dir=HERE.parents[4]) as scratch:
        work = Path(scratch)
        for name, password, keyfile in MODES:
            source = INPUT / (name + ".kdbx")
            output = OUTPUT / source.name
            auth = (["--no-password"] if password is None else [])
            if keyfile:
                auth += ["-k", INPUT / "public.key"]
            answer = "" if password is None else password + "\n"
            before = run(args.cli, ["export", "-q", *auth, source], answer)
            candidate = output
            if args.write:
                candidate = work / source.name
                shutil.copyfile(source, candidate)
                run(args.cli, ["edit", "-q", "-p", *auth, candidate, ENTRY], answer + SOURCE + "\n")
            after = run(args.cli, ["export", "-q", *auth, candidate], answer)
            verify_edit(before, after)
            for index, (entry, attachment, expected) in enumerate([
                (ENTRY, "résumé.bin", PAYLOAD),
                ("Work メール/Reference", "résumé.bin", PAYLOAD),
                (ENTRY, "empty.bin", b""),
            ]):
                exported = work / (name + str(index) + ".bin")
                run(args.cli, ["attachment-export", "-q", *auth, candidate,
                               entry, attachment, exported], answer)
                assert exported.read_bytes() == expected
            data = candidate.read_bytes()
            assert data != source.read_bytes()
            assert header(data) == header(source.read_bytes()), "Encryption profile changed"
            manifest["files"][source.name] = {
                "source_sha256": digest(source), "sha256": digest(candidate), **header(data)}
            if args.write:
                shutil.copyfile(candidate, output)
    if args.write:
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    else:
        assert manifest == json.loads(manifest_path.read_text())
    print("Verified five public source edits, unchanged XML and fifteen exact attachments")


if __name__ == "__main__":
    main()
