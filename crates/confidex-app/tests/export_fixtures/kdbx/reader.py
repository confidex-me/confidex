"""Check only the public synthetic KDBX writer corpus with KeePassXC."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET

cli, root = Path(sys.argv[1]), Path(sys.argv[2])
cases = []
inputs = [("password", b"PUBLIC-KDBX-EXPORT", None),
          ("keyfile", None, "public.key"),
          ("both", b"PUBLIC-KDBX-EXPORT", "public.key"),
          ("empty-password", b"", None),
          ("empty-both", b"", "public.key")]
for kind in ["hex", "xml-v1", "xml-v2", "utf16", "bare"]:
    if (root / (kind + ".key")).exists():
        inputs += [("key-" + kind + "-keyfile", None, kind + ".key"),
                   ("key-" + kind + "-both", b"PUBLIC-KDBX-EXPORT", kind + ".key")]
for name, password, keyfile in inputs:
    database = root / (name + ".kdbx")
    flags = ["-q"] + (["--no-password"] if password is None else [])
    if keyfile:
        flags += ["-k", str(root / keyfile)]
    secret = b"" if password is None else password + b"\n"

    def run(command, args=(), stdin=secret, extra=(), path=database):
        return subprocess.run([str(cli), command, *flags, *extra, str(path), *args],
                              input=stdin, capture_output=True, timeout=30)

    for key, expected in [("Password", "PUBLIC-PASSWORD"), ("Notes", "line one\r\n<&>\"'公開")]:
        result = run("show", ["Public KDBX"], extra=["-s", "-a", key])
        assert result.returncode == 0, (name, result.stderr)
        assert result.stdout == (expected + "\n").encode(), (name, key, result.stdout)
    result = run("export")
    assert result.returncode == 0, (name, result.stderr)
    fields = {s.findtext("Key"): s.find("Value") for s in ET.fromstring(result.stdout).findall(".//Entry/String")}
    for key, value in [("UserName", "public-user"), ("URL", "https://one.invalid/?a=1&b=2"),
                       ("Hidden", "PUBLIC-HIDDEN"), ("", "PUBLIC-EMPTY-NAME"),
                       ("Unicode <&>", "\tCR\nLF\n\U0001f642")]:
        assert fields[key].text == value, (name, key)
    assert fields["Empty"].text in (None, "")
    for key in ["UserName", "Password", "URL", "Notes", "Hidden", "otp"]:
        assert fields[key].get("ProtectInMemory") == "True", (name, key)
    otp = urllib.parse.urlsplit(fields["otp"].text)
    parameters = urllib.parse.parse_qs(otp.query)
    assert parameters["secret"] == ["MZXW6YTBOI"]
    assert parameters["issuer"] == ["Provider"] and urllib.parse.unquote(otp.path)=="/Provider:public"
    assert parameters["algorithm"] == ["SHA256"] and parameters["digits"] == ["8"] and parameters["period"] == ["45"]
    for filename, expected in [("sample.bin", bytes([0, 255, 7])), ("empty.bin", b"")]:
        target = root / (name + "-" + filename)
        result = run("attachment-export", ["Public KDBX", filename, str(target)])
        assert result.returncode == 0 and target.read_bytes() == expected, (name, filename, result.stderr)
    if password is not None:
        assert run("show", ["Public KDBX"], stdin=b"PUBLIC-WRONG\n").returncode != 0
    if keyfile:
        wrong = root / "wrong.key"
        wrong.write_bytes(bytes([8]) * 32)
        wrong_flags = ["-q"] + (["--no-password"] if password is None else []) + ["-k", str(wrong)]
        result = subprocess.run([str(cli), "show", *wrong_flags, str(database), "Public KDBX"],
                                input=secret, capture_output=True, timeout=30)
        assert result.returncode != 0
    corrupt = root / (name + "-corrupt.kdbx")
    data = bytearray(database.read_bytes())
    data[-36] ^= 1
    corrupt.write_bytes(data)
    assert run("show", ["Public KDBX"], path=corrupt).returncode != 0
    cases.append({"mode": name, "bytes": database.stat().st_size, "values": True,
                  "protection": True, "totp": True, "attachments": True, "tamper": True})
source = root / "password.kdbx"
target = root / "password-resaved.kdbx"
shutil.copyfile(source, target)
result = subprocess.run([str(cli), "edit", "-q", "-t", "Public KDBX", str(target), "Public KDBX"],
                        input=b"PUBLIC-KDBX-EXPORT\n", capture_output=True, timeout=30)
assert result.returncode == 0, result.stderr
print(json.dumps({"reader": subprocess.check_output([str(cli), "--version"], text=True).strip(),
                  "sha256": hashlib.sha256(cli.read_bytes()).hexdigest(), "cases": cases}))
