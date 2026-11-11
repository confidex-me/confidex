"""Verify public variant files with an independent KeePassXC CLI reader."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
CASES = [
    ("argon2d-aes", None, True),
    ("argon2id-chacha", "public-v2.keyx", True),
    ("aes-twofish", "public.raw", False),
    ("argon2id-aes-hex", "public.hex", False),
]


def run(cli, command, name, keyfile, password, *tail):
    options = ["-q"]
    if keyfile:
        options += ["-k", str(ROOT / keyfile)]
    if not password:
        options.append("--no-password")
    result = subprocess.run(
        [str(cli), command, *options, str(ROOT / f"{name}.kdbx"), *tail],
        input=b"PUBLIC-VARIANT-DATABASE\n" if password else b"",
        capture_output=True, check=False, timeout=30,
    )
    assert result.returncode == 0, (name, command, result.stderr.decode(errors="replace"))
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    arguments = parser.parse_args()
    manifest_path = ROOT / "manifest.json"
    if not arguments.write:
        for name, digest in json.loads(manifest_path.read_text())["files"].items():
            assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    for name, keyfile, password in CASES:
        xml = run(arguments.cli, "export", name, keyfile, password)
        entry = ET.fromstring(xml).find(".//Entry")
        assert entry is not None, name
        fields = {item.findtext("Key"): item.findtext("Value") for item in entry.findall("String")}
        assert fields["Title"] == "PUBLIC-VECTOR"
        assert fields["Password"] == "PUBLIC-VARIANT-PASSWORD"
        assert fields["Unknown custom"] == "PUBLIC-VARIANT-CUSTOM"
        assert fields["Unicode"] == "Почта \u2014 東京"
        for filename, expected in [("résumé.bin", b"PUBLIC-KDBX-BINARY\x00\xff\n"), ("empty.bin", b"")]:
            with tempfile.TemporaryDirectory(prefix="confidex-public-fixture-") as temporary:
                destination = Path(temporary) / filename
                run(arguments.cli, "attachment-export", name, keyfile, password,
                    "PUBLIC-VECTOR", filename, str(destination))
                assert destination.read_bytes() == expected, (name, filename)
        if arguments.write:
            (ROOT / f"{name}.xml").write_bytes(xml)
        print(f"{name}: independent fields and exact attachments PASS")
    if arguments.write:
        files = ["generate.rs", "upstream.rs", "capture.py", "public-v2.keyx", "public.raw", "public.hex", "argon2d-aes-v10.kdbx"]
        files += [f"{name}.{extension}" for name, _, _ in CASES for extension in ["kdbx", "xml"]]
        version = subprocess.check_output([str(arguments.cli), "--version"], text=True).strip()
        manifest = {
            "purpose": "Public synthetic data only; no accounts or user vaults",
            "writer": "Local MIT keepass 0.17.0, boundary commit a22c5d067e36fcae7e660ffbaca063b3af7af30b",
            "reader": version,
            "argon2_v10": "KeePassXC 2.8.0 rejects this variant; independent rust-argon2 vectors and registry keepass reader checked separately",
            "reader_binary_sha256": hashlib.sha256(arguments.cli.read_bytes()).hexdigest(),
            "files": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files},
        }
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
