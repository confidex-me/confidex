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
    def test_versions_use_first_six_sha_characters_and_validate_inputs(self):
        commit = 'abcdef' + '0' * 34
        self.assertEqual(version.release_version('v1.2.3', commit), '1.2.3+gabcdef')
        self.assertEqual(version.release_version('1.2.3-beta.2+ci.7', commit), '1.2.3-beta.2+ci.7.gabcdef')
        for invalid in ['../invalid', 'v01.2.3', '1.2.3-01', '1.2.3-', '1.2.3-alpha..2', '1.2.3+meta..2']:
            with self.assertRaises(ValueError):
                version.release_version(invalid, commit)
        for invalid in ['abcdef', 'G' * 40, '../invalid']:
            with self.assertRaises(ValueError):
                version.release_version('1.2.3', invalid)

    def test_native_checks_architecture_before_changing_sources_and_resolves_cache_paths(self):
        args = types.SimpleNamespace(arch='arm64', version='1.2.3+gabcdef', commit='abcdef' + '0' * 34)
        with patch.object(common, 'host_arch', return_value='amd64'), patch.object(common, 'prepare_version') as prepare:
            with self.assertRaises(ValueError):
                common.native(args)
            prepare.assert_not_called()
        args.arch = 'amd64'
        with patch.object(common, 'host_arch', return_value='amd64'), patch.object(common, 'run') as run, patch.dict(common.os.environ, {'CARGO_TARGET_DIR': 'cache'}):
            self.assertEqual(common.native(args, {'RUSTFLAGS': '--cfg reqwest_unstable'}), common.ROOT / 'cache/release')
            self.assertEqual(run.call_args.kwargs['env']['CONFIDEX_BUILD_VERSION'], args.version)
            self.assertEqual(run.call_args.kwargs['env']['RUSTFLAGS'], '--cfg reqwest_unstable')
            self.assertEqual(common.os.environ['CONFIDEX_SOURCE_COMMIT'], args.commit)
        with patch.object(common.platform, 'machine', return_value='riscv64'):
            with self.assertRaises(ValueError):
                common.host_arch()

    def test_archives_are_repeatable_with_executables_licenses_and_source(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(common.subprocess, 'check_output', return_value='a' * 40):
            root = Path(temporary)
            binary = root / 'public-binary'
            binary.write_bytes(b'public executable fixture')
            artifact = common.archive('confidexsyncd', '0.1.0+gaaaaaa', 'amd64-linux-gnu', {'bin/confidexsyncd': binary}, root)
            first = artifact.read_bytes()
            with tarfile.open(artifact) as archive:
                self.assertEqual(archive.getmember('bin/confidexsyncd').mode, 0o755)
                self.assertEqual(archive.extractfile('bin/confidexsyncd').read(), binary.read_bytes())
                self.assertEqual(archive.extractfile('LICENSE').read(), (common.ROOT / 'apps/confidexsyncd/LICENSE').read_bytes())
                self.assertEqual(json.loads(archive.extractfile('SOURCE.json').read())['commit'], 'a' * 40)
            common.archive('confidexsyncd', '0.1.0+gaaaaaa', 'amd64-linux-gnu', {'bin/confidexsyncd': binary}, root)
            self.assertEqual(artifact.read_bytes(), first)
            common.checksums(root)
            self.assertIn(artifact.name, (root / 'SHA256SUMS').read_text())
            self.assertNotIn('SHA256SUMS', (root / 'SHA256SUMS').read_text())
            self.assertIn('NOTICE', ''.join(common.metadata('0.1.0+gaaaaaa', 'amd64-linux-gnu')))
            notices = common.metadata('0.1.0+gaaaaaa', 'amd64-linux-gnu')
            for name in ['Egui-Hack-LICENSE.txt', 'Egui-Noto-OFL.txt', 'Egui-Ubuntu-LICENSE.txt',
                         'Egui-icons-LICENSE.txt', 'Egui-icons-NOTICE.txt']:
                self.assertIn('NOTICES/crates/confidex-ui/assets/fonts/' + name, notices)


if __name__ == '__main__':
    unittest.main()
