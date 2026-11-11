#!/usr/bin/env python3
"""Package native release binaries with licenses and source provenance."""
import argparse
import io
import json
import os
import plistlib
import subprocess
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def notices(binary):
    files = {}
    sources = [ROOT / 'vendor/keepass/LICENSE']
    for path in (ROOT / 'crates/confidex-ui/assets').rglob('*'):
        if path.is_file() and (any(word in path.name.upper() for word in ['LICENSE', 'OFL', 'ATTRIBUTION']) or path.name == 'README.md'):
            sources.append(path)
    if binary == 'confidexsyncd':
        sources = [path for path in (ROOT / 'apps/confidexsyncd/swagger-ui').iterdir()
                   if path.is_file() and any(word in path.name.upper() for word in ['LICENSE', 'NOTICE'])]
    for path in sources:
        files['NOTICES/' + path.relative_to(ROOT).as_posix()] = (path.read_bytes(), 0o644)
    return files


def package(binary, target, version, directory, output):
    if binary not in {'confidex', 'cfdex', 'confidexsyncd'}:
        raise ValueError('Unknown binary')
    if not version or any(c not in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_' for c in version):
        raise ValueError('Invalid release version')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    windows = 'windows' in target
    macos = 'apple-darwin' in target
    executable = binary + ('.exe' if windows else '')
    files = {executable: ((directory / executable).read_bytes(), 0o755)}
    license_file = ROOT / ('apps/confidexsyncd/LICENSE' if binary == 'confidexsyncd' else 'LICENSE')
    files['LICENSE'] = (license_file.read_bytes(), 0o644)
    files.update(notices(binary))
    files['SOURCE.json'] = (json.dumps({'version': version, 'commit': source, 'target': target}, sort_keys=True).encode() + b'\n', 0o644)
    if macos and binary == 'confidex':
        files['Confidex.app/Contents/MacOS/confidex'] = files.pop(executable)
        files['Confidex.app/Contents/Info.plist'] = (plistlib.dumps({
            'CFBundleIdentifier': 'me.confidex.app',
            'CFBundleName': 'Confidex', 'CFBundleExecutable': 'confidex',
            'CFBundlePackageType': 'APPL', 'CFBundleVersion': version.removeprefix('v'),
            'CFBundleShortVersionString': version.removeprefix('v'),
            'NSHighResolutionCapable': True,
        }), 0o644)
    output.mkdir(parents=True, exist_ok=True)
    suffix = '.zip' if windows or macos else '.tar.gz'
    dest = output / f'{binary}-{version}-{target}{suffix}'
    if suffix == '.zip':
        with zipfile.ZipFile(dest, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, (data, mode) in sorted(files.items()):
                info = zipfile.ZipInfo(name)
                info.external_attr = (0o100000 | mode) << 16
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    else:
        import gzip
        with dest.open('wb') as output_file, gzip.GzipFile(filename='', mode='wb', fileobj=output_file, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as archive:
                for name, (data, mode) in sorted(files.items()):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(data), mode, 0
                    archive.addfile(info, io.BytesIO(data))
    return dest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target')
    parser.add_argument('version')
    parser.add_argument('--directory', type=Path, default=Path(os.environ.get('CARGO_TARGET_DIR', 'target')) / 'release')
    parser.add_argument('--output', type=Path, default=Path('dist/releases'))
    args = parser.parse_args()
    for name in ['confidex', 'cfdex', 'confidexsyncd']:
        print(package(name, args.target, args.version, args.directory, args.output))
