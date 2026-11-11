"""Build the public 1PUX fixture. This is not a vault exporter."""

import io
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parent / "onepassword_1pux"


def packed():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for source in sorted((ROOT / "export").rglob("*")):
            if source.is_file():
                entry = zipfile.ZipInfo(source.relative_to(ROOT / "export").as_posix())
                entry.create_system = 3
                entry.external_attr = 0o100600 << 16
                archive.writestr(entry, source.read_bytes())
    return output.getvalue()


if __name__ == "__main__":
    target = ROOT / "account.1pux"
    if sys.argv[1:] == ["--check"]:
        if target.read_bytes() != packed():
            raise SystemExit("1PUX fixture differs from its reviewed source files")
    elif not sys.argv[1:]:
        target.write_bytes(packed())
    else:
        raise SystemExit("usage: pack_1pux.py [--check]")
