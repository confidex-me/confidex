"""Build public damaged inputs in a new directory for importer tests."""

import io
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parent


def cases():
    archive = (ROOT / "onepassword_1pux/account.1pux").read_bytes()
    yield "truncated.1pux", archive[:-24]
    for name, path in [("traversal.1pux", "../outside"), ("absolute.1pux", "/outside")]:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as output:
            output.writestr(path, b"PUBLIC FIXTURE")
        yield name, buffer.getvalue()
    yield "entity.xml", b'<!DOCTYPE KeePassFile [<!ENTITY external SYSTEM "file:///PUBLIC-FIXTURE-DO-NOT-OPEN">]><KeePassFile>&external;</KeePassFile>'
    yield "inner-protected.xml", b'<KeePassFile><Meta/><Root><Group><Entry><String><Key>Password</Key><Value Protected="True">UFVCTElDLUZJWFRVUkU=</Value></String></Entry></Group></Root></KeePassFile>'
    yield "duplicate-key.json", b'{"encrypted":false,"items":[],"items":[{"name":"PUBLIC-FIXTURE"}]}'
    yield "quote.csv", b'name,password\r\nfixture,"unterminated'
    value = json.loads((ROOT / "bitwarden_json/personal.json").read_bytes())
    value["encrypted"] = True
    yield "encrypted-bitwarden.json", json.dumps(value).encode()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: negative_cases.py NEW_DIRECTORY")
    target = Path(sys.argv[1])
    target.mkdir(parents=True, exist_ok=False)
    for name, data in cases():
        (target / name).write_bytes(data)
