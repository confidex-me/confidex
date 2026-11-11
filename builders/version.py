#!/usr/bin/env python3
"""Derive the build version without changing source manifests."""
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


def release_version(tag, commit):
    version = tag.removeprefix('v')
    if not VERSION.fullmatch(version):
        raise ValueError('Release tag must contain a semantic version, such as v0.1.0')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Expected a full lowercase Git commit SHA')
    return version + ('.g' if '+' in version else '+g') + commit[:6]


if __name__ == '__main__':
    import subprocess
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python3 builders/version.py RELEASE_TAG')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    print(release_version(sys.argv[1], commit))
