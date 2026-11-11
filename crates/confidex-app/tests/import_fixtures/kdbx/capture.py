"""Create public synthetic KDBX files with the real KeePassXC CLI."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
PASSWORD = "PUBLIC-FIXTURE-DATABASE"
PAYLOAD = b"PUBLIC-FIXTURE-ATTACHMENT\x00\xff\n"

def run(cli, args, password):
    result = subprocess.run([str(cli), *map(str, args)], input=password.encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError(f"KeePassXC {args[0]} failed: {result.returncode}")
    return result.stdout

def header(data):
    assert data[:8] == bytes.fromhex("03d9a29a67fb4bb5")
    version = struct.unpack_from("<I", data, 8)[0]
    assert version >> 16 == 4
    offset, fields = 12, {}
    while True:
        kind, size = struct.unpack_from("<BI", data, offset)
        offset += 5
        value = data[offset:offset + size]
        assert len(value) == size and kind not in fields
        fields[kind] = value
        offset += size
        if kind == 0:
            break
    params, pos = {}, 2
    dictionary = fields[11]
    while dictionary[pos] != 0:
        kind = dictionary[pos]
        pos += 1
        size = struct.unpack_from("<I", dictionary, pos)[0]
        pos += 4
        key = dictionary[pos:pos + size].decode("utf8")
        pos += size
        size = struct.unpack_from("<I", dictionary, pos)[0]
        pos += 4
        value = dictionary[pos:pos + size]
        pos += size
        if key == "$UUID":
            params["uuid"] = value.hex()
        elif key in ("M", "I", "P", "V", "R"):
            assert kind in (4, 5)
            params[key] = int.from_bytes(value, "little")
    return {"major": version >> 16, "minor": version & 65535, "kdf": params,
            "cipher_uuid": fields[2].hex(),
            "compression": struct.unpack("<I", fields[3])[0]}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if not args.write:
        manifest = json.loads((HERE / "manifest.json").read_text())
        for name, item in manifest["files"].items():
            assert hashlib.sha256((HERE / name).read_bytes()).hexdigest() == item["sha256"]
        for profile in ("password", "keyfile", "both"):
            auth = ["--no-password"] if profile == "keyfile" else []
            if profile != "password":
                auth += ["-k", HERE / "public.key"]
            run(args.cli, ["db-info", "-q", *auth, HERE / (profile + ".kdbx")], PASSWORD + "\n")
            with tempfile.TemporaryDirectory(prefix="confidex-public-attachment-") as scratch:
                for entry, name, expected in [("Work メール/Почта — 東京", "résumé.bin", PAYLOAD),
                                               ("Work メール/Reference", "résumé.bin", PAYLOAD),
                                               ("Work メール/Почта — 東京", "empty.bin", b"")]:
                    output = Path(scratch) / "output.bin"
                    run(args.cli, ["attachment-export", "-q", *auth, HERE / (profile + ".kdbx"),
                                   entry, name, output], PASSWORD + "\n")
                    assert output.read_bytes() == expected
                    output.unlink()
        print("KDBX capture hashes and independent CLI reopening: PASS")
        return
    source = (HERE.parent / "keepass_xml/database.xml").read_bytes().replace(
        b"Work/", b"Work ")
    (HERE / "input.xml").write_bytes(source)
    (HERE / "public.key").write_bytes(bytes(range(32)))
    manifest = {"producer": run(args.cli, ["--version"], "").decode().strip(),
                "producer_executable_sha256": hashlib.sha256(args.cli.read_bytes()).hexdigest(), "files": {}}
    with tempfile.TemporaryDirectory(prefix="confidex-public-kdbx-") as scratch:
        file = Path(scratch) / "public.bin"
        empty = Path(scratch) / "empty.bin"
        file.write_bytes(PAYLOAD)
        empty.write_bytes(b"")
        for profile in ("password", "keyfile", "both"):
            output = HERE / (profile + ".kdbx")
            if output.exists():
                output.unlink()
            auth = ["-p"] if profile != "keyfile" else []
            if profile != "password":
                auth += ["--set-key-file", HERE / "public.key"]
            run(args.cli, ["import", "-q", "-t", "100", *auth, HERE / "input.xml", output],
                (PASSWORD + "\n") * 2)
            auth = ["--no-password"] if profile == "keyfile" else []
            if profile != "password":
                auth += ["-k", HERE / "public.key"]
            for entry, name, data in [("Work メール/Почта — 東京", "résumé.bin", file),
                                      ("Work メール/Reference", "résumé.bin", file),
                                      ("Work メール/Почта — 東京", "empty.bin", empty)]:
                run(args.cli, ["attachment-import", "-q", *auth, output, entry, name, data], PASSWORD + "\n")
            exported = run(args.cli, ["export", "-q", *auth, output], PASSWORD + "\n")
            (HERE / (profile + ".xml")).write_bytes(exported)
            data = output.read_bytes()
            manifest["files"][output.name] = {"sha256": hashlib.sha256(data).hexdigest(), **header(data)}
    for name in ["input.xml", "public.key", "password.xml", "keyfile.xml", "both.xml"]:
        manifest["files"][name] = {"sha256": hashlib.sha256((HERE / name).read_bytes()).hexdigest()}
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Captured three public KDBX profiles with exact and empty attachments")

if __name__ == "__main__":
    main()
