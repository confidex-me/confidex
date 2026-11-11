#!/usr/bin/env python3
"""Build a self-host bundle with native servers, web assets and CF Workers."""
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, options
from containers.prepare import check_architecture, identity, image_namespace
from artifacts import filename


def extract(source, destination, metadata, expected):
    with tarfile.open(source) as archive:
        if identity(source, json.loads(archive.extractfile(metadata).read())) != expected:
            raise ValueError(f'Release source mismatch: {source.name}')
        destination.mkdir(parents=True, exist_ok=True)
        archive.extractall(destination, filter='data')


def worker_config(text):
    text = re.sub(r'(?ms)^\[build\]\n.*?(?=^\[|\Z)', '', text)
    text = re.sub(r'(?m)^routes = \[.*\]\n', '', text)
    return text.replace('workers_dev = false', 'workers_dev = true')


def package(args, directory):
    output = args.output / f'confidex-selfhost-{args.version}.zip'
    namespace = image_namespace(os.environ.get('GITHUB_REPOSITORY_OWNER', 'confidex-me'), args.tag)
    expected = {'version': args.version, 'commit': args.commit}
    tag = args.tag
    with tempfile.TemporaryDirectory(prefix='confidex-selfhost-') as temp:
        root = Path(temp)
        extract(directory / filename('confidex', args.version, 'web', 'tar.gz'), root / 'web', 'BUILD.json', expected)
        extract(directory / filename('confidexsyncd', args.version, 'worker', 'tar.gz'), root / 'cloudflare/syncd', 'SOURCE.json', expected)
        for arch in ['amd64', 'arm64']:
            for libc in ['gnu', 'musl']:
                destination = root / f'native/linux-{arch}-{libc}'
                extract(directory / filename('confidexsyncd', args.version, f'{arch}-linux-{libc}', 'tar.gz'), destination, 'SOURCE.json', expected)
                check_architecture((destination / 'bin/confidexsyncd').read_bytes(), arch)
        for name in ['syncd.toml', 'package.json', 'package-lock.json']:
            shutil.copy2(ROOT / 'builders/selfhost' / name, root / name)
        shutil.copy2(ROOT / 'builders/selfhost/docs/INSTALL.md', root / 'README.md')
        (root / 'SOURCE.json').write_text(json.dumps(expected, sort_keys=True) + '\n')
        for name in ['.node-version', 'LICENSE', 'LICENSE-AGPL']:
            shutil.copy2(ROOT / name, root / name)
        caddy = (ROOT / 'builders/containers/Caddyfile').read_text()
        (root / 'Caddyfile').write_text(caddy.replace('root * /srv', 'root * ./web').replace('reverse_proxy syncd:8080', 'reverse_proxy 127.0.0.1:8081'))
        app = root / 'cloudflare/app'
        app.mkdir()
        shutil.copy2(ROOT / 'apps/confidex/web/cloudflare.mjs', app / 'cloudflare.mjs')
        text = worker_config((ROOT / 'apps/confidex/wrangler.toml').read_text())
        text = text.replace('main = "web/cloudflare.mjs"', 'main = "cloudflare.mjs"')
        (app / 'wrangler.toml').write_text(text.replace('../../dist/web', '../../web'))
        syncd = root / 'cloudflare/syncd'
        text = worker_config((ROOT / 'apps/confidexsyncd/wrangler.toml').read_text()).replace('build/index.js', 'index.js')
        (syncd / 'wrangler.toml').write_text(text)
        shutil.copy2(ROOT / 'apps/confidexsyncd/schema.sql', syncd / 'schema.sql')
        (root / 'compose.yaml').write_text(f'''services:
  syncd:
    image: {namespace}/confidexsyncd:{tag}
    restart: unless-stopped
    volumes:
      - sync-data:/data
  web:
    image: {namespace}/confidex-web:{tag}
    restart: unless-stopped
    depends_on: [syncd]
    ports:
      - "127.0.0.1:8080:8080"
volumes:
  sync-data:
''')
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, strict_timestamps=False) as archive:
            for path in sorted(root.rglob('*')):
                if path.is_file():
                    archive.write(path, path.relative_to(root).as_posix())
    return output


if __name__ == '__main__':
    args = options()
    print(package(args, args.output))
