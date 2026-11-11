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
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

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


def worker_index(name):
    account = quote(os.environ['CLOUDFLARE_ACCOUNT_ID'], safe='')
    script = quote(name, safe='')
    request = Request(
        f'https://api.cloudflare.com/client/v4/accounts/{account}/workers/scripts/{script}/settings',
        headers={'Authorization': 'Bearer ' + os.environ['CLOUDFLARE_API_TOKEN']},
    )
    try:
        with urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except HTTPError as error:
        error.close()
        raise SystemExit(
            f'Cannot read Worker {name}: Cloudflare HTTP {error.code}. '
            'Check CLOUDFLARE_ACCOUNT_ID and the token\'s Workers Scripts permissions.'
        ) from None
    except (URLError, ValueError):
        raise SystemExit(f'Cannot read Worker {name}: invalid or unavailable Cloudflare response.') from None
    result = payload.get('result') if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or payload.get('success') is not True or not isinstance(result, dict):
        raise SystemExit(f'Cannot read Worker {name}: Cloudflare rejected the settings request.')
    bindings = result.get('bindings')
    if not isinstance(bindings, list):
        raise SystemExit(f'Cannot read Worker {name}: missing bindings in Cloudflare response.')
    matches = [binding for binding in bindings
               if isinstance(binding, dict) and binding.get('name') == 'INDEX' and binding.get('type') == 'd1']
    if len(matches) != 1:
        raise SystemExit(f'Configure one INDEX D1 binding on Worker {name} before deployment.')
    binding = matches[0]
    try:
        return str(uuid.UUID(binding.get('database_id') or binding.get('id', '')))
    except (ValueError, AttributeError, TypeError):
        raise SystemExit(f'Worker {name} has an invalid INDEX database ID.') from None


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
    configuration = tomllib.loads(text)
    bindings = configuration['d1_databases']
    if len(bindings) != 1 or bindings[0]['binding'] != 'INDEX':
        raise ValueError('Expected one INDEX D1 binding')
    binding = bindings[0]
    text = text.replace(binding['database_id'], worker_index(configuration['name']))
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
