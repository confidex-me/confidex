#!/usr/bin/env python3
"""Deploy the browser app and sync Worker from release archives."""
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, run
from artifacts import filename
from version import release_version


def unpack(path, destination, metadata, expected):
    with tarfile.open(path) as archive:
        source = json.loads(archive.extractfile(metadata).read())
        if any(source.get(key) != value for key, value in expected.items()):
            raise ValueError(f'Release source mismatch: {path.name}')
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(parents=True)
        archive.extractall(destination, filter='data')


def main():
    if not os.environ.get('CLOUDFLARE_API_TOKEN'):
        print('Cloudflare deployment skipped: CLOUDFLARE_API_TOKEN is not set.')
        return
    if not os.environ.get('CLOUDFLARE_ACCOUNT_ID'):
        raise SystemExit('Set CLOUDFLARE_ACCOUNT_ID as a repository variable or secret.')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    version = release_version(os.environ['RELEASE_TAG'], commit)
    expected = {'version': version, 'commit': commit}
    directory = ROOT / 'dist/releases'
    unpack(directory / filename('confidex', version, 'web', 'tar.gz'), ROOT / 'dist/web', 'BUILD.json', expected)
    unpack(directory / filename('confidexsyncd', version, 'worker', 'tar.gz'), ROOT / 'apps/confidexsyncd/build', 'SOURCE.json', expected)
    config = ROOT / 'apps/confidexsyncd/wrangler.toml'
    text = config.read_text()
    bindings = tomllib.loads(text)['d1_databases']
    if len(bindings) != 1 or bindings[0]['binding'] != 'INDEX':
        raise ValueError('Expected one INDEX D1 binding')
    binding = bindings[0]
    result = run('npx', 'wrangler', 'd1', 'list', '--json', '--config', config, capture_output=True, text=True)
    databases = json.loads(result.stdout)
    matches = [db for db in databases if db['name'] == binding['database_name']]
    if len(matches) != 1:
        raise SystemExit(f'Create D1 database {binding["database_name"]} before deployment.')
    text = text.replace(binding['database_id'], str(uuid.UUID(matches[0]['uuid'])))
    # Keep the existing S3 URLs and Worker secrets.
    text = re.sub(r'(?ms)^\[vars\]\n.*?(?=^\[|\Z)', '', text)
    text = re.sub(r'(?ms)^\[build\]\n.*?(?=^\[|\Z)', '', text)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', prefix='wrangler.release-', dir=config.parent) as generated:
        generated.write(text)
        generated.flush()
        run('npx', 'wrangler', 'deploy', '--config', generated.name, '--keep-vars')
    run('npx', 'wrangler', 'deploy', '--config', ROOT / 'apps/confidex/wrangler.toml', '--keep-vars')


if __name__ == '__main__':
    main()
