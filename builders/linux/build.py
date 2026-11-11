#!/usr/bin/env python3
"""Build Linux application and daemon archives for glibc or dynamic musl."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, archive, native, options, run


def package(args, binaries, libc):
    suffix = f'{args.arch}-linux-{libc}'
    app = archive('confidex', args.version, suffix,
                  {'bin/confidexm': binaries / 'confidex', 'bin/cfdex': binaries / 'cfdex'}, args.output)
    daemon = archive('confidexsyncd', args.version, suffix,
                     {'bin/confidexsyncd': binaries / 'confidexsyncd'}, args.output)
    return app, daemon


if __name__ == '__main__':
    libc = os.environ.get('CONFIDEX_LIBC', 'gnu')
    if libc not in {'gnu', 'musl'}:
        raise SystemExit('CONFIDEX_LIBC must be gnu or musl')
    args = options()
    if not os.environ.get('CONFIDEX_BUILD_CONTAINER'):
        run('docker', 'build', '-f', ROOT / f'builders/linux/Dockerfile.{libc}', '-t', f'confidex-{libc}', ROOT)
        run('docker', 'run', '--rm', '-v', f'{ROOT}:/source', '-e', f'CONFIDEX_LIBC={libc}', '-e', 'CONFIDEX_BUILD_CONTAINER=1',
            '-e', f'RELEASE_VERSION={os.environ.get("RELEASE_VERSION", "")}',
            '-e', f'CARGO_BUILD_JOBS={os.environ.get("CARGO_BUILD_JOBS", "2")}', '-e', 'CARGO_INCREMENTAL=0',
            '-e', f'CARGO_TARGET_DIR=/source/target/{libc}', f'confidex-{libc}', *sys.argv[1:])
    else:
        environment = dict(os.environ)
        if libc == 'musl':
            environment['RUSTFLAGS'] = '--cfg reqwest_unstable -C target-feature=-crt-static'
        for result in package(args, native(args, environment), libc):
            print(result)
