#!/usr/bin/env python3
"""Validate artifacts and attach them to an existing GitHub Release."""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artifacts import parse
from common import ROOT, checksums, run
from version import release_version


def assets(directory, version):
    paths = sorted(path for path in directory.iterdir() if path.is_file() and path.name != 'SHA256SUMS')
    if not paths:
        raise ValueError('No release artifacts found')
    for path in paths:
        parsed = parse(path.name)
        if not parsed or parsed['version'] != version:
            raise ValueError(f'Unexpected release artifact: {path.name}')
    checksums(directory)
    return paths + [directory / 'SHA256SUMS']


if __name__ == '__main__':
    tag = os.environ['RELEASE_TAG']
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    paths = assets(ROOT / 'dist/releases', release_version(tag, commit))
    run('gh', 'release', 'upload', tag, *paths, '--repo', os.environ['GITHUB_REPOSITORY'], '--clobber')
