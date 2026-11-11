"""Check the Mac bundle layout and shared application icons."""
import importlib.util
import plistlib
import struct
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import common

spec = importlib.util.spec_from_file_location('macos_build', common.ROOT / 'builders/macos/build.py')
macos = importlib.util.module_from_spec(spec)
spec.loader.exec_module(macos)


class MacTests(unittest.TestCase):
    def test_bundle_has_cli_icons_licenses_and_applications_link(self):
        seen = []
        with tempfile.TemporaryDirectory() as temporary, patch.object(common.subprocess, 'check_output', return_value='a' * 40):
            root = Path(temporary)
            for name in ['confidex', 'cfdex']:
                (root / name).write_bytes(name.encode())
            args = types.SimpleNamespace(arch='arm64', version='0.1.0+gaaaaaa', output=root)
            def inspect(*command):
                if command[:2] != ('hdiutil', 'create'):
                    return
                staging = command[command.index('-srcfolder') + 1]
                app = staging / 'Confidex.app'
                info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
                self.assertEqual(info['CFBundleExecutable'], 'confidexm')
                self.assertEqual(info['CFBundleGetInfoString'], args.version)
                self.assertEqual(info['CFBundleShortVersionString'], '0.1.0')
                self.assertEqual((app / 'Contents/MacOS/cfdex').read_bytes(), b'cfdex')
                self.assertTrue((app / 'Contents/Resources/Confidex.icns').is_file())
                self.assertTrue((app / 'Contents/Resources/LICENSE').is_file())
                self.assertEqual((staging / 'Applications').readlink(), Path('/Applications'))
                seen.append(True)
            with patch.object(macos, 'run', side_effect=inspect):
                output = macos.package(args, root)
            self.assertEqual(output.suffix, '.dmg')
        self.assertEqual(seen, [True])

    def test_icons_have_standard_sizes_and_valid_containers(self):
        for size in [16, 32, 128, 256, 512]:
            for scale in [1, 2]:
                name = f'Confidex.iconset/icon_{size}x{size}{"@2x" if scale == 2 else ""}.png'
                png = (common.ICONS / name).read_bytes()
                self.assertEqual(struct.unpack('>II', png[16:24]), (size * scale, size * scale))
        icns = (common.ICONS / 'Confidex.icns').read_bytes()
        self.assertEqual(icns[:4], b'icns')
        self.assertEqual(struct.unpack('>I', icns[4:8])[0], len(icns))
        ico = (common.ICONS / 'Confidex.ico').read_bytes()
        self.assertEqual(struct.unpack('<HHH', ico[:6]), (0, 1, 7))


if __name__ == '__main__':
    unittest.main()
