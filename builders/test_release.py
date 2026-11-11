"""Reject unrelated files and mixed source versions before release upload."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

import common

spec = importlib.util.spec_from_file_location('release_upload', common.ROOT / 'builders/release/upload.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_upload_input_is_nonempty_versioned_and_checksums_are_regenerated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                release.assets(root, '1.2.3+gabcdef')
            artifact = root / 'confidex-1.2.3+gabcdef-arm64-macos.dmg'
            artifact.write_bytes(b'public artifact fixture')
            paths = release.assets(root, '1.2.3+gabcdef')
            self.assertEqual(paths, [artifact, root / 'SHA256SUMS'])
            expected = (root / 'SHA256SUMS').read_bytes()
            for name in ['credentials.txt', 'confidex-1.2.3+g000000-arm64-macos.dmg']:
                unexpected = root / name
                unexpected.write_bytes(b'public negative fixture')
                with self.assertRaises(ValueError):
                    release.assets(root, '1.2.3+gabcdef')
                self.assertEqual((root / 'SHA256SUMS').read_bytes(), expected)
                unexpected.unlink()
            artifact.write_bytes(b'updated public fixture')
            release.assets(root, '1.2.3+gabcdef')
            self.assertNotEqual((root / 'SHA256SUMS').read_bytes(), expected)


if __name__ == '__main__':
    unittest.main()
