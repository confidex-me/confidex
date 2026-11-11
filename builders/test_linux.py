"""Check Linux archive layout, modes and libc-specific names."""
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import common

spec = importlib.util.spec_from_file_location('linux_build', common.ROOT / 'builders/linux/build.py')
linux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(linux)

spec = importlib.util.spec_from_file_location('ci_dependencies', common.ROOT / 'builders/linux/ci_dependencies.py')
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class LinuxTests(unittest.TestCase):
    def test_ci_keeps_fallbacks_and_stops_when_update_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            mirrors = Path(temporary) / 'apt-mirrors.txt'
            original = 'http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n'
            mirrors.write_text(original)
            with patch.object(ci, 'MIRRORS', mirrors), patch.object(ci, 'run') as run:
                ci.main()
                ci.main()
                self.assertEqual(mirrors.read_text(), ci.PREFERRED + original)
                self.assertEqual([call.args[-1] for call in run.call_args_list[::2]], ['update', 'update'])
                self.assertIn('APT::Update::Error-Mode=any', run.call_args_list[0].args)
                self.assertIn('Acquire::http::Timeout=10', run.call_args_list[0].args)
            with patch.object(ci, 'MIRRORS', mirrors), patch.object(ci, 'run',
                    side_effect=subprocess.CalledProcessError(100, 'apt-get')) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    ci.main()
                self.assertEqual(run.call_count, 1)

    def test_help_does_not_need_docker_or_git(self):
        result = subprocess.run([sys.executable, str(common.ROOT / 'builders/linux/build.py'), '--help'],
                                env=dict(os.environ, PATH=''), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--arch {amd64,arm64}', result.stdout)

    def test_both_libcs_keep_binaries_licenses_and_source(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(common.subprocess, 'check_output', return_value='a' * 40):
            root = Path(temporary)
            for name in ['confidex', 'cfdex', 'confidexsyncd']:
                (root / name).write_bytes(name.encode())
            for arch in ['amd64', 'arm64']:
                args = types.SimpleNamespace(arch=arch, version='1.2.3+gaaaaaa', output=root)
                for libc in ['gnu', 'musl']:
                    app, daemon = linux.package(args, root, libc)
                    self.assertIn(f'{arch}-linux-{libc}', app.name)
                    with tarfile.open(app) as archive:
                        self.assertEqual(archive.extractfile('bin/confidexm').read(), b'confidex')
                        self.assertEqual(archive.extractfile('bin/cfdex').read(), b'cfdex')
                        self.assertEqual(archive.getmember('bin/confidexm').mode, 0o755)
                        self.assertEqual(json.loads(archive.extractfile('SOURCE.json').read())['version'], args.version)
                    with tarfile.open(daemon) as archive:
                        self.assertEqual(archive.extractfile('bin/confidexsyncd').read(), b'confidexsyncd')
                        self.assertEqual(archive.extractfile('LICENSE').read(), (common.ROOT / 'apps/confidexsyncd/LICENSE').read_bytes())


if __name__ == '__main__':
    unittest.main()
