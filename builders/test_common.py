"""Check common release inputs and archive guarantees."""
import json
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import common
import version


class CommonTests(unittest.TestCase):
    def test_versions_preserve_dependencies_and_reject_invalid_tags_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'apps/client/Cargo.toml'
            path.parent.mkdir(parents=True)
            path.write_text('[package]\nversion = "0.1.0"\n[dependencies.example]\nversion = "2"\n')
            self.assertEqual(version.set_version('v1.2.3-beta.2+build.7', root), '1.2.3-beta.2+build.7')
            self.assertIn('version = "2"', path.read_text())
            before = path.read_bytes()
            for invalid in ['../invalid', 'v01.2.3', '1.2.3-01', '1.2.3-', '1.2.3-alpha..2', '1.2.3+meta..2']:
                with self.assertRaises(ValueError):
                    version.set_version(invalid, root)
                self.assertEqual(path.read_bytes(), before)
            broken = root / 'crates/broken/Cargo.toml'
            broken.parent.mkdir(parents=True)
            broken.write_text('[package]\nname = "broken"\n')
            with self.assertRaises(ValueError):
                version.set_version('v2.0.0', root)
            self.assertEqual(path.read_bytes(), before)

    def test_native_checks_architecture_before_changing_sources_and_resolves_cache_paths(self):
        args = types.SimpleNamespace(arch='arm64', version='1.2.3')
        with patch.object(common, 'host_arch', return_value='amd64'), patch.object(common, 'prepare_version') as prepare:
            with self.assertRaises(ValueError):
                common.native(args)
            prepare.assert_not_called()
        args.arch = 'amd64'
        with patch.object(common, 'host_arch', return_value='amd64'), patch.object(common, 'prepare_version'), patch.object(common, 'run'), patch.dict(common.os.environ, {'CARGO_TARGET_DIR': 'cache'}):
            self.assertEqual(common.native(args), common.ROOT / 'cache/release')
        with patch.object(common.platform, 'machine', return_value='riscv64'):
            with self.assertRaises(ValueError):
                common.host_arch()

    def test_archives_are_repeatable_with_executables_licenses_and_source(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(common.subprocess, 'check_output', return_value='a' * 40):
            root = Path(temporary)
            binary = root / 'public-binary'
            binary.write_bytes(b'public executable fixture')
            artifact = common.archive('confidexsyncd', '0.1.0', 'amd64-linux-gnu', {'bin/confidexsyncd': binary}, root)
            first = artifact.read_bytes()
            with tarfile.open(artifact) as archive:
                self.assertEqual(archive.getmember('bin/confidexsyncd').mode, 0o755)
                self.assertEqual(archive.extractfile('bin/confidexsyncd').read(), binary.read_bytes())
                self.assertEqual(archive.extractfile('LICENSE').read(), (common.ROOT / 'apps/confidexsyncd/LICENSE').read_bytes())
                self.assertEqual(json.loads(archive.extractfile('SOURCE.json').read())['commit'], 'a' * 40)
            common.archive('confidexsyncd', '0.1.0', 'amd64-linux-gnu', {'bin/confidexsyncd': binary}, root)
            self.assertEqual(artifact.read_bytes(), first)
            common.checksums(root)
            self.assertIn(artifact.name, (root / 'SHA256SUMS').read_text())
            self.assertNotIn('SHA256SUMS', (root / 'SHA256SUMS').read_text())
            self.assertIn('NOTICE', ''.join(common.metadata('0.1.0', 'amd64-linux-gnu')))


if __name__ == '__main__':
    unittest.main()
