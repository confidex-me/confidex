"""Check release packaging and verified tool extraction without network access."""
import hashlib
import importlib.util
import io
import plistlib
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


package = load('package', 'package.py')
tools = load('wasm_tools', 'install-wasm-tools.py')


class ReleaseTests(unittest.TestCase):
    def test_native_archives_have_licenses_source_and_platform_layout(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(package.subprocess, 'check_output', return_value='a' * 40):
            root = Path(temp)
            (root / 'confidex').write_bytes(b'public executable fixture')
            (root / 'confidex.exe').write_bytes(b'public Windows fixture')
            mac = package.package('confidex', 'aarch64-apple-darwin', 'v0.1.0', root, root)
            with zipfile.ZipFile(mac) as archive:
                self.assertIn('LICENSE', archive.namelist())
                self.assertIn('SOURCE.json', archive.namelist())
                info = plistlib.loads(archive.read('Confidex.app/Contents/Info.plist'))
                self.assertEqual(info['CFBundleExecutable'], 'confidex')
                self.assertEqual(archive.getinfo('Confidex.app/Contents/MacOS/confidex').external_attr >> 16 & 0o777, 0o755)
            windows = package.package('confidex', 'x86_64-pc-windows-msvc', 'v0.1.0', root, root)
            with zipfile.ZipFile(windows) as archive:
                self.assertEqual(archive.read('confidex.exe'), b'public Windows fixture')
            linux = package.package('confidex', 'x86_64-unknown-linux-gnu', 'v0.1.0', root, root)
            before = linux.read_bytes()
            with tarfile.open(linux) as archive:
                self.assertEqual(archive.extractfile('confidex').read(), b'public executable fixture')
                self.assertEqual(archive.getmember('confidex').mode, 0o755)
            package.package('confidex', 'x86_64-unknown-linux-gnu', 'v0.1.0', root, root)
            self.assertEqual(linux.read_bytes(), before)
            with self.assertRaises(ValueError):
                package.package('confidex', 'x86_64-unknown-linux-gnu', '../invalid', root, root)

    def test_tool_installer_checks_digest_and_keeps_binaryen_library(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as tar:
            for name in ['release/bin/wasm-opt', 'release/lib/libbinaryen.dylib']:
                info = tarfile.TarInfo(name)
                info.size = 7
                tar.addfile(info, io.BytesIO(b'fixture'))
        archive = data.getvalue()
        with tempfile.TemporaryDirectory() as temp, patch.object(tools, 'DEST', Path(temp) / 'bin'), patch.object(tools.subprocess, 'check_output', return_value=archive), patch.object(tools.subprocess, 'run'):
            with self.assertRaises(ValueError):
                tools.install('https://example.invalid/tool', '0' * 64, 'wasm-opt')
            self.assertFalse(tools.DEST.exists())
            tools.install('https://example.invalid/tool', hashlib.sha256(archive).hexdigest(), 'wasm-opt')
            self.assertEqual((tools.DEST / 'wasm-opt').read_bytes(), b'fixture')
            self.assertEqual((tools.DEST.parent / 'lib/libbinaryen.dylib').read_bytes(), b'fixture')


if __name__ == '__main__':
    unittest.main()
