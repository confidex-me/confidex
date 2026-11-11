#!/usr/bin/env python3
"""Build the Cloudflare sync Worker and its release archive."""
import os
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artifacts import filename
from common import ROOT, metadata, options, prepare_version, run


def main():
    args = options()
    prepare_version(args)
    tools = ROOT / '.tools/bin'
    worker_build = tools / ('worker-build.exe' if os.name == 'nt' else 'worker-build')
    if not worker_build.exists():
        run('cargo', 'install', '--locked', 'worker-build', '--version', '0.8.7', '--root', ROOT / '.tools')
    actual = run(worker_build, '--version', capture_output=True, text=True).stdout.strip()
    if actual != '0.8.7':
        raise ValueError(f'Expected worker-build 0.8.7, found {actual}')
    environment = dict(os.environ)
    environment['PATH'] = str(tools) + os.pathsep + environment['PATH']
    run('cargo', 'fetch', '--locked', '--target', 'wasm32-unknown-unknown')
    environment['CARGO_NET_OFFLINE'] = 'true'
    source = ROOT / 'apps/confidexsyncd'
    run(worker_build, '--release', cwd=source, env=environment)
    print(package(args, source / 'build'))


def package(args, worker):
    for name in ['index.js', 'index_bg.wasm']:
        if not (worker / name).is_file():
            raise ValueError(f'Missing Worker output: {name}')
    for name, data in metadata(args.version, 'wasm32-unknown-unknown', 'confidexsyncd').items():
        path = worker / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    output = args.output / filename('confidexsyncd', args.version, 'worker', 'tar.gz')
    with tarfile.open(output, 'w:gz') as tar:
        for name in ['index.js', 'index_bg.wasm', 'SOURCE.json', 'LICENSE', 'NOTICES']:
            tar.add(worker / name, arcname=name)
    return output


if __name__ == '__main__':
    main()
