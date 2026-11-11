"""Shared release inputs, native build and package metadata."""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import tomllib
from pathlib import Path
from version import release_version
from artifacts import filename

ROOT = Path(__file__).resolve().parents[1]
ICONS = ROOT / 'apps/confidex/assets/icons'


def run(*args, **kwargs):
    kwargs.setdefault('cwd', ROOT)
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def options():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', choices=['amd64', 'arm64'], default=host_arch())
    parser.add_argument('--version', default=os.environ.get('RELEASE_VERSION', ''))
    args = parser.parse_args()
    current = tomllib.loads((ROOT / 'apps/confidex/Cargo.toml').read_text())['package']['version']
    args.tag = args.version or 'v' + current
    args.commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    args.version = release_version(args.tag, args.commit)
    args.output = ROOT / 'dist/releases'
    args.output.mkdir(parents=True, exist_ok=True)
    return args


def host_arch():
    machine = platform.machine().lower()
    architectures = {'arm64': 'arm64', 'aarch64': 'arm64', 'amd64': 'amd64', 'x86_64': 'amd64'}
    if machine not in architectures:
        raise ValueError(f'Unsupported build host architecture: {machine}')
    return architectures[machine]


def prepare_version(args):
    os.environ['CONFIDEX_BUILD_VERSION'] = args.version
    os.environ['CONFIDEX_SOURCE_COMMIT'] = args.commit


def native(args, environment=None):
    if args.arch != host_arch():
        raise ValueError('Use a native runner for the selected architecture')
    prepare_version(args)
    if environment is not None:
        environment.update({key: os.environ[key] for key in ['CONFIDEX_BUILD_VERSION', 'CONFIDEX_SOURCE_COMMIT']})
    run('cargo', 'build', '--locked', '--release', '-p', 'confidex', '-p', 'cfdex', '-p', 'confidexsyncd', env=environment)
    directory = Path(os.environ.get('CARGO_TARGET_DIR', str(ROOT / 'target')))
    if not directory.is_absolute():
        directory = ROOT / directory
    return directory / 'release'


def metadata(version, target, component="confidex"):
    commit = os.environ.get('CONFIDEX_SOURCE_COMMIT') or subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    license_file = ROOT / ('apps/confidexsyncd/LICENSE' if component == 'confidexsyncd' else 'LICENSE')
    files = {'LICENSE': license_file.read_bytes(),
             'SOURCE.json': json.dumps({'version': version, 'commit': commit, 'target': target}, sort_keys=True).encode() + b'\n'}
    if component == 'confidexsyncd':
        files['NOTICES/core/LICENSE'] = (ROOT / 'LICENSE').read_bytes()
        for path in (ROOT / 'apps/confidexsyncd/swagger-ui').iterdir():
            if path.is_file() and any(word in path.name.upper() for word in ['LICENSE', 'NOTICE']):
                files['NOTICES/swagger-ui/' + path.name] = path.read_bytes()
        return files
    for path in (ROOT / 'crates/confidex-ui/assets').rglob('*'):
        if path.is_file() and (any(word in path.name.upper() for word in ['LICENSE', 'OFL', 'ATTRIBUTION', 'NOTICE']) or path.name == 'README.md'):
            files['NOTICES/' + path.relative_to(ROOT).as_posix()] = path.read_bytes()
    files['NOTICES/keepass/LICENSE'] = (ROOT / 'vendor/keepass/LICENSE').read_bytes()
    return files


def checksums(directory):
    paths = sorted(p for p in directory.iterdir() if p.is_file() and p.name != 'SHA256SUMS')
    lines = [f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in paths]
    (directory / 'SHA256SUMS').write_text(''.join(lines))


def archive(name, version, target, binaries, output):
    import gzip
    import io
    import tarfile
    files = metadata(version, target, name)
    files.update({name: path.read_bytes() for name, path in binaries.items()})
    destination = output / filename(name, version, target, 'tar.gz')
    with destination.open('wb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as tar:
            for member, data in sorted(files.items()):
                info = tarfile.TarInfo(member)
                info.size, info.mode, info.mtime = len(data), 0o755 if member.startswith('bin/') else 0o644, 0
                tar.addfile(info, io.BytesIO(data))
    return destination
