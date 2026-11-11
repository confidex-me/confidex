"""Capture public credential-presence cases with the real KeePassXC CLI."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from capture import HERE, PAYLOAD, header, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    modes = [
        ("empty-password", "", None),
        ("empty-password-keyfile", "", "public.key"),
    ]
    manifest_path = HERE / "credentials.json"
    manifest = {"producer": run(args.cli, ["--version"], "").decode().strip(),
                "producer_sha256": hashlib.sha256(args.cli.read_bytes()).hexdigest(),
                "files": {}}
    with tempfile.TemporaryDirectory(prefix="confidex-public-credentials-") as scratch:
        payload = Path(scratch) / "public.bin"
        empty = Path(scratch) / "empty.bin"
        payload.write_bytes(PAYLOAD)
        empty.write_bytes(b"")
        for name, password, keyfile in modes:
            output = HERE / (name + ".kdbx")
            file_args = ["-k", HERE / keyfile] if keyfile else []
            if args.write:
                if output.exists():
                    output.unlink()
                auth = ["-p"] + (["--set-key-file", HERE / keyfile] if keyfile else [])
                # KeePassXC asks for confirmation instead of repeating an empty password.
                answer = "\ny\n" if not password else (password + "\n") * 2
                run(args.cli, ["import", "-q", "-t", "100", *auth,
                               HERE / "input.xml", output], answer)
                for entry, attachment, data in [
                    ("Work メール/Почта \u2014 東京", "résumé.bin", payload),
                    ("Work メール/Reference", "résumé.bin", payload),
                    ("Work メール/Почта \u2014 東京", "empty.bin", empty),
                ]:
                    run(args.cli, ["attachment-import", "-q", *file_args, output,
                                   entry, attachment, data], password + "\n")
            run(args.cli, ["db-info", "-q", *file_args, output], password + "\n")
            for entry, attachment, expected in [
                ("Work メール/Почта \u2014 東京", "résumé.bin", PAYLOAD),
                ("Work メール/Reference", "résumé.bin", PAYLOAD),
                ("Work メール/Почта \u2014 東京", "empty.bin", b""),
            ]:
                exported = Path(scratch) / "export.bin"
                run(args.cli, ["attachment-export", "-q", *file_args,
                               output, entry, attachment, exported], password + "\n")
                assert exported.read_bytes() == expected
                exported.unlink()
            wrong_auth = ["--no-password", *file_args] if not password else []
            rejected = subprocess.run([str(args.cli), "db-info", "-q",
                                       *map(str, wrong_auth), str(output)],
                                      input=(password + "\n").encode(), capture_output=True)
            assert rejected.returncode != 0, "Absent and empty credentials must differ"
            data = output.read_bytes()
            manifest["files"][output.name] = {
                "sha256": hashlib.sha256(data).hexdigest(), **header(data)}
    for name in ["input.xml", "public.key"]:
        manifest["files"][name] = {"sha256": hashlib.sha256((HERE / name).read_bytes()).hexdigest()}
    if args.write:
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    else:
        assert manifest == json.loads(manifest_path.read_text())
    print("Verified two public credential modes and six exact attachments")


if __name__ == "__main__":
    main()
