"""Independently read the public 10k workload with KeePassXC, without XML files."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli")
    parser.add_argument("database", type=Path)
    args = parser.parse_args()

    def run(*command):
        return subprocess.run([args.cli, *map(str, command)], input=b"PUBLIC-BENCH-DATABASE\n",
                              capture_output=True, check=True).stdout

    root = ET.fromstring(run("export", "-q", args.database))
    seen = set()
    for entry in root.findall("./Root/Group/Entry"):
        strings = {item.findtext("Key"): item.find("Value") for item in entry.findall("String")}
        index = int(strings["Title"].text.removeprefix("PUBLIC-BENCH-"))
        assert 0 <= index < 10_000 and index not in seen
        seen.add(index)
        for name, text in {
            "Title": f"PUBLIC-BENCH-{index:05}", "UserName": f"public-{index:05}",
            "URL": "https://public.example.invalid/", "Password": "PUBLIC-BENCH-PASSWORD",
            "Custom secret": "PUBLIC-BENCH-SECRET", "Notes": "PUBLIC-BENCH-NOTE\nSecond line",
        }.items():
            assert strings[name].text == text
        for name in ["Password", "Custom secret", "Notes"]:
            assert strings[name].get("ProtectInMemory") == "True"
    assert len(seen) == 10_000
    with tempfile.TemporaryDirectory(prefix="public-kdbx-reader-", dir=args.database.parent) as directory:
        for index in [0, 1000]:
            output = Path(directory) / f"public-{index}.bin"
            run("attachment-export", "-q", args.database, f"PUBLIC-BENCH-{index:05}", "public.bin", output)
            assert output.read_bytes() == b"PUBLIC-BENCH-ATTACHMENT\0\xff"
    print("Verified 10000 public entries, field protection and two exact attachment exports")


if __name__ == "__main__":
    main()
