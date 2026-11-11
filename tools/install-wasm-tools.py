#!/usr/bin/env python3
"""Install verified WASM build tools for macOS and Linux."""
import hashlib
import io
import platform
import subprocess
import tarfile
from pathlib import Path

DEST = Path(__file__).resolve().parents[1] / '.tools/bin'
# Archive digests come from the official GitHub release assets.
TOOLS = {
    ('Darwin', 'arm64'): (
        'aarch64-apple-darwin', 'b90ddb9357f584b1af897d58ad77e4cce2b48fc17e2a967bc249a87f72809444',
        'arm64-macos', 'ad66da82ac13f163e424b1643f16c6dfcccc98b5966296b43e52d3cab04f84a8'),
    ('Darwin', 'x86_64'): (
        'x86_64-apple-darwin', 'eb209c115b7cb95832423c1aa3f4d06d6c53f63ef74fc4b6fb79ef0b2eea5f10',
        'x86_64-macos', '13a9b90be775c6389ce3d1f879cb8627bea56708ba8c122983941d53a8199b95'),
    ('Linux', 'x86_64'): (
        'x86_64-unknown-linux-musl', '9687f3bb551b9f66f37ed32a40d7913a00f7962db653054e56857bc306c3227f',
        'x86_64-linux', '2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489'),
    ('Linux', 'aarch64'): (
        'aarch64-unknown-linux-musl', '99ffc93ce80081b91632e2b539b782821a8f3439ab0fddc645287462b2f55d3d',
        'aarch64-linux', '89c07ea56faf38d0fbecf36ca8ec0721756716185f265b568e133d427f299bf8'),
}


def install(url, digest, executable):
    archive = subprocess.check_output(['curl', '--fail', '--location', '--retry', '3', url])
    if hashlib.sha256(archive).hexdigest() != digest:
        raise ValueError(f'Archive checksum mismatch: {url}')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        matches = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name == executable]
        if len(matches) != 1:
            raise ValueError(f'Archive must contain one {executable}')
        data = tar.extractfile(matches[0]).read()
        if executable == 'wasm-opt':
            libraries = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name in {'libbinaryen.dylib', 'libbinaryen.so'}]
            for member in libraries:
                output = DEST.parent / 'lib' / Path(member.name).name
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(tar.extractfile(member).read())
    DEST.mkdir(parents=True, exist_ok=True)
    output = DEST / executable
    output.write_bytes(data)
    output.chmod(0o755)
    subprocess.run([str(output), '--version'], check=True)


def main():
    target = (platform.system(), platform.machine())
    if target not in TOOLS:
        raise SystemExit(f'Unsupported build host: {target}; use Linux or macOS for the web build.')
    bindgen, bindgen_hash, binaryen, binaryen_hash = TOOLS[target]
    install(f'https://github.com/wasm-bindgen/wasm-bindgen/releases/download/0.2.130/wasm-bindgen-0.2.130-{bindgen}.tar.gz', bindgen_hash, 'wasm-bindgen')
    install(f'https://github.com/WebAssembly/binaryen/releases/download/version_133/binaryen-version_133-{binaryen}.tar.gz', binaryen_hash, 'wasm-opt')


if __name__ == '__main__':
    main()
