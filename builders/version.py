#!/usr/bin/env python3
"""Set workspace package versions from a release tag."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NUMBER = r'(?:0|[1-9][0-9]*)'
PRERELEASE = r'(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
VERSION = re.compile(
    rf'{NUMBER}\.{NUMBER}\.{NUMBER}'
    rf'(?:-{PRERELEASE}(?:\.{PRERELEASE})*)?'
    r'(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?'
)


def set_version(tag, root=ROOT):
    version = tag.removeprefix('v')
    if not VERSION.fullmatch(version):
        raise ValueError('Release tag must contain a semantic version, such as v0.1.0')
    manifests = list((root / 'apps').glob('*/Cargo.toml')) + list((root / 'crates').glob('*/Cargo.toml'))
    if not manifests:
        raise ValueError('No workspace packages found')
    updates = []
    for manifest in manifests:
        text, count = re.subn(r'(?m)^version = "[^"]+"$', f'version = "{version}"', manifest.read_text(), count=1)
        if count != 1:
            raise ValueError(f'Missing package version: {manifest}')
        updates.append((manifest, text))
    for manifest, text in updates:
        manifest.write_text(text)
    return version


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python3 builders/version.py RELEASE_TAG')
    print(set_version(sys.argv[1]))
