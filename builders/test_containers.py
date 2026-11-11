"""Check multiarch contexts, provenance and registry tag constraints."""
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

import common

spec = importlib.util.spec_from_file_location('container_prepare', common.ROOT / 'builders/containers/prepare.py')
containers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(containers)


def archive(path, files):
    with tarfile.open(path, 'w:gz') as output:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            output.addfile(info, io.BytesIO(data))


def fixtures(root, wrong_arch=False, different_web=False, bad_notice=False):
    source = {'version': '1.2.3+gaaaaaa', 'commit': 'a' * 40}
    for arch, machine in [('amd64', 62), ('arm64', 183)]:
        binary = bytearray(64)
        binary[:6] = b'\x7fELF\x02\x01'
        binary[18:20] = (62 if wrong_arch else machine).to_bytes(2, 'little')
        files = {'bin/confidexsyncd': bytes(binary), 'SOURCE.json': json.dumps(source).encode(),
                 'LICENSE': b'public license fixture', 'NOTICES/core/LICENSE': b'public core fixture'}
        if bad_notice:
            files['NOTICES/../../../../escaped'] = b'public negative fixture'
        archive(root / f'confidexsyncd-1.2.3+gaaaaaa-{arch}-linux-gnu.tar.gz', files)
    web = source | {'commit': 'b' * 40, 'version': '1.2.3+gbbbbbb'} if different_web else source
    archive(root / f'confidex-{web["version"]}-web.tar.gz',
            {'BUILD.json': json.dumps(web).encode(), 'index.html': b'public site fixture'})
    return source


class ContainerTests(unittest.TestCase):
    def test_contexts_preserve_architecture_licenses_and_matching_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = fixtures(root)
            output = root / 'contexts'
            (output / 'web/site').mkdir(parents=True)
            (output / 'web/site/stale.js').write_text('public stale fixture')
            self.assertEqual(containers.prepare(root, output), expected)
            self.assertFalse((output / 'web/site/stale.js').exists())
            for arch in ['amd64', 'arm64']:
                binary = output / 'syncd/bin' / arch / 'confidexsyncd'
                self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
                self.assertEqual(json.loads((binary.parent / 'SOURCE.json').read_text()), expected)
            self.assertEqual((output / 'syncd/licenses/NOTICES/core/LICENSE').read_bytes(), b'public core fixture')
            self.assertTrue((output / 'web/Caddyfile').is_file())

    def test_wrong_architecture_mixed_sources_and_notice_traversal_fail(self):
        for options in [{'wrong_arch': True}, {'different_web': True}, {'bad_notice': True}]:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixtures(root, **options)
                with self.assertRaises(ValueError):
                    containers.prepare(root, root / 'contexts')
                self.assertFalse((root / 'escaped').exists())

    def test_registry_owner_and_original_release_tag(self):
        self.assertEqual(containers.image_namespace('Confidex-ME', 'v1.2.3-rc.1'), 'ghcr.io/confidex-me')
        for tag in ['latest', 'v01.2.3', 'v1.2.3+build.1', 'v1.2.3-' + 'a' * 128]:
            with self.assertRaises(ValueError):
                containers.image_namespace('confidex-me', tag)


if __name__ == '__main__':
    unittest.main()
