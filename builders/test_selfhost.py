"""Check the complete bundle layout, source identity and neutral CF defaults."""
import importlib.util
import io
import json
import tarfile
import tempfile
import tomllib
import types
import unittest
import zipfile
from pathlib import Path

import common

spec = importlib.util.spec_from_file_location('selfhost_build', common.ROOT / 'builders/selfhost/build.py')
selfhost = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selfhost)


def archive(path, files):
    with tarfile.open(path, 'w:gz') as output:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755 if name.startswith('bin/') else 0o644
            output.addfile(info, io.BytesIO(data))


def fixtures(root, bad_worker=False):
    source = {'version': '1.2.3+gaaaaaa', 'commit': 'a' * 40}
    archive(root / 'confidex-1.2.3+gaaaaaa-web.tar.gz',
            {'BUILD.json': json.dumps(source).encode(), 'index.html': b'public fixture', 'app_bg.wasm': b'\0asm\1\0\0\0'})
    worker = source | {'commit': 'b' * 40} if bad_worker else source
    archive(root / 'confidexsyncd-1.2.3+gaaaaaa-worker.tar.gz',
            {'SOURCE.json': json.dumps(worker).encode(), 'index.js': b'public fixture', 'index_bg.wasm': b'\0asm\1\0\0\0'})
    for arch, machine in [('amd64', 62), ('arm64', 183)]:
        data = bytearray(64)
        data[:6] = b'\x7fELF\x02\x01'
        data[18:20] = machine.to_bytes(2, 'little')
        for libc in ['gnu', 'musl']:
            archive(root / f'confidexsyncd-1.2.3+gaaaaaa-{arch}-linux-{libc}.tar.gz',
                    {'SOURCE.json': json.dumps(source).encode(), 'bin/confidexsyncd': bytes(data), 'LICENSE': b'public license fixture'})
    return types.SimpleNamespace(**source, tag='v1.2.3', output=root)


class SelfhostTests(unittest.TestCase):
    def test_bundle_is_complete_and_does_not_reference_the_source_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = fixtures(root)
            output = selfhost.package(args, root)
            with zipfile.ZipFile(output) as bundle:
                names = bundle.namelist()
                for name in ['compose.yaml', 'Caddyfile', 'README.md', 'syncd.toml', 'SOURCE.json',
                             'package.json', 'package-lock.json', '.node-version', 'LICENSE', 'LICENSE-AGPL',
                             'web/BUILD.json', 'cloudflare/syncd/schema.sql', 'cloudflare/syncd/index_bg.wasm']:
                    self.assertIn(name, names)
                for arch in ['amd64', 'arm64']:
                    for libc in ['gnu', 'musl']:
                        binary = f'native/linux-{arch}-{libc}/bin/confidexsyncd'
                        self.assertEqual((bundle.getinfo(binary).external_attr >> 16) & 0o777, 0o755)
                for component in ['app', 'syncd']:
                    config = tomllib.loads(bundle.read(f'cloudflare/{component}/wrangler.toml').decode())
                    self.assertTrue(config['workers_dev'])
                    self.assertNotIn('routes', config)
                    self.assertNotIn('build', config)
                self.assertEqual(tomllib.loads(bundle.read('cloudflare/app/wrangler.toml').decode())['assets']['directory'], '../../web')
                caddy = bundle.read('Caddyfile').decode()
                self.assertIn('root * ./web', caddy)
                self.assertIn('reverse_proxy 127.0.0.1:8081', caddy)
                self.assertIn('confidexsyncd:v1.2.3', bundle.read('compose.yaml').decode())
                self.assertFalse(any(name.endswith(('.sqlite', '.env', '.dev.vars')) for name in names))

    def test_mixed_source_releases_fail_before_writing_a_zip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = fixtures(root, bad_worker=True)
            with self.assertRaises(ValueError):
                selfhost.package(args, root)
            self.assertFalse(list(root.glob('*.zip')))


if __name__ == '__main__':
    unittest.main()
