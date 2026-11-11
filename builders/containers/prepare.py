#!/usr/bin/env python3
"""Prepare container contexts from the tested release archives."""
import json
import os
import re
import shutil
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT
from artifacts import parse
from version import VERSION, release_version


def single(directory, pattern):
    paths = list(directory.glob(pattern))
    if len(paths) != 1:
        raise ValueError(f'Expected one archive matching {pattern}')
    return paths[0]


def identity(path, metadata):
    parsed = parse(path.name)
    source = {key: metadata[key] for key in ['version', 'commit']}
    if (not parsed or parsed['version'] != source['version']
            or not re.fullmatch('[0-9a-f]{40}', source['commit'])
            or not source['version'].endswith('g' + source['commit'][:6])):
        raise ValueError(f'Release source mismatch: {path.name}')
    return source


def prepare(directory, output):
    if output.exists():
        shutil.rmtree(output)
    expected = None
    for arch in ['amd64', 'arm64']:
        source = single(directory, f'confidexsyncd-*-{arch}-linux-gnu.tar.gz')
        path = output / 'syncd/bin' / arch / 'confidexsyncd'
        path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(source) as archive:
            metadata = archive.extractfile('SOURCE.json').read()
            source_info = json.loads(metadata)
            revision = identity(source, source_info)
            if expected is not None and revision != expected:
                raise ValueError(f'Release source mismatch: {source.name}')
            expected = revision
            binary = archive.extractfile('bin/confidexsyncd').read()
            if not binary.startswith(b'\x7fELF\x02\x01') or int.from_bytes(binary[18:20], 'little') != {'amd64': 62, 'arm64': 183}[arch]:
                raise ValueError(f'Wrong executable architecture: {source.name}')
            path.write_bytes(binary)
            (path.parent / 'SOURCE.json').write_bytes(metadata)
            if arch == 'amd64':
                for member in archive.getmembers():
                    if member.isfile() and (member.name == 'LICENSE' or member.name.startswith('NOTICES/')):
                        if '..' in Path(member.name).parts:
                            raise ValueError('Invalid notice path')
                        notice = output / 'syncd/licenses' / member.name
                        notice.parent.mkdir(parents=True, exist_ok=True)
                        notice.write_bytes(archive.extractfile(member).read())
        path.chmod(0o755)
    site = output / 'web/site'
    site.mkdir(parents=True, exist_ok=True)
    web = single(directory, 'confidex-*-web.tar.gz')
    with tarfile.open(web) as archive:
        build = json.loads(archive.extractfile('BUILD.json').read())
        if identity(web, build) != expected:
            raise ValueError('Web and server release sources differ')
        archive.extractall(site, filter='data')
    (output / 'web/Caddyfile').write_bytes((ROOT / 'builders/containers/Caddyfile').read_bytes())
    return expected


def image_namespace(owner, tag):
    if not VERSION.fullmatch(tag.removeprefix('v')) or not re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', tag):
        raise ValueError('Use a Docker-compatible semantic release tag without +metadata')
    return 'ghcr.io/' + owner.lower()


if __name__ == '__main__':
    tag = os.environ['RELEASE_TAG']
    namespace = image_namespace(os.environ.get('GITHUB_REPOSITORY_OWNER', 'confidex-me'), tag)
    source = prepare(ROOT / 'dist/releases', ROOT / 'dist/containers')
    if source['version'] != release_version(tag, source['commit']):
        raise ValueError('Release tag does not match the prepared artifacts')
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
            output.write(f'namespace={namespace}\nversion={source["version"]}\ncommit={source["commit"]}\n')
