"""Check MSI install identity, nested notices and CLI integration."""
import importlib.util
import tempfile
import types
import unittest
from pathlib import Path

import common

spec = importlib.util.spec_from_file_location('windows_build', common.ROOT / 'builders/windows/build.py')
windows = importlib.util.module_from_spec(spec)
spec.loader.exec_module(windows)


class WindowsTests(unittest.TestCase):
    def test_msi_keeps_versions_upgrade_identity_and_both_clients(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ['confidexm.exe', 'cfdex.exe', 'NOTICES/fonts/LICENSE', 'NOTICES/fonts/NOTICE']:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'public fixture')
            args = types.SimpleNamespace(version='1.2.3+gabcdef')
            document = windows.manifest(args, root)
            package = document.find('.//{*}Package')
            self.assertEqual(package.attrib['Version'], '1.2.3')
            self.assertEqual(package.attrib['InstallerVersion'], '500')
            self.assertEqual(package.attrib['Scope'], 'perMachine')
            self.assertEqual(package.attrib['UpgradeCode'], 'C581435B-43B8-4C0A-B403-393FC37CC8A7')
            files = document.findall('.//{*}File')
            self.assertEqual({Path(file.attrib['Source']).relative_to(root).as_posix() for file in files},
                             {'confidexm.exe', 'cfdex.exe', 'NOTICES/fonts/LICENSE', 'NOTICES/fonts/NOTICE'})
            self.assertEqual(document.find('.//{*}Shortcut').attrib['Name'], 'Confidex')
            path = document.find('.//{*}Environment')
            self.assertEqual((path.attrib['Name'], path.attrib['Part']), ('PATH', 'last'))
            properties = {node.attrib['Id']: node.attrib['Value'] for node in document.findall('.//{*}Property')}
            self.assertEqual(properties['CONFIDEXBUILDVERSION'], args.version)
            directories = document.findall('.//{*}Directory')
            self.assertEqual(len(directories), 3)


if __name__ == '__main__':
    unittest.main()
