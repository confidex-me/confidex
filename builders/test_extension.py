"""A failed build must preserve the extension installed from dist/extension."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_wasm import load, wasm

with patch.dict(sys.modules, {'build': wasm}):
    extension = load('extension_build', 'builders/wasm/build_extension.py')


def fixture(bundle):
    bundle.mkdir(parents=True)
    for name in ('manifest.json', 'popup.html', 'popup.css', 'popup-boot.js',
                 'extension-strings.js', 'vault-host.html', 'session.css', 'vault-host.js',
                 'session-messages.json', 'session-worker.js', 'background.js',
                 'content-bootstrap.js', 'content-channel.js', 'site-permissions.js',
                 'engine/engine.js', 'ui/ui.js', 'content/content.js'):
        path = bundle / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{}')
    for name in ('engine/engine_bg.wasm', 'ui/ui_bg.wasm', 'content/content_bg.wasm'):
        (bundle / name).write_bytes(b'\0asm\1\0\0\0')


class ExtensionTests(unittest.TestCase):
    def test_failed_or_incomplete_build_preserves_installed_extension(self):
        for failure in ('compile', 'missing-asset', 'missing-import'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                installed = root / 'dist/extension'
                fixture(installed)
                (installed / 'ui/ui.js').write_text('existing module')

                def build(stage):
                    self.assertEqual((installed / 'ui/ui.js').read_text(), 'existing module')
                    fixture(stage)
                    if failure == 'compile':
                        raise RuntimeError('compiler failed')
                    if failure == 'missing-asset':
                        (stage / 'ui/ui.js').unlink()
                    if failure == 'missing-import':
                        (stage / 'ui/ui.js').write_text("import { start } from './snippets/missing.js';")

                with patch.object(extension, 'ROOT', root), patch.object(extension, 'build_bundle', side_effect=build):
                    with self.assertRaises((RuntimeError, ValueError)):
                        extension.main()
                self.assertEqual((installed / 'ui/ui.js').read_text(), 'existing module')
                self.assertEqual(list((root / 'dist').glob('.extension-build-*')), [])

    def test_complete_build_replaces_installed_extension(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installed = root / 'dist/extension'
            fixture(installed)
            (installed / 'old-file').touch()
            with patch.object(extension, 'ROOT', root), patch.object(extension, 'build_bundle', side_effect=fixture):
                extension.main()
            extension.validate_bundle(installed)
            self.assertFalse((installed / 'old-file').exists())
            self.assertEqual(list((root / 'dist').glob('.extension-build-*')), [])

    def test_failed_install_restores_previous_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installed = root / 'dist/extension'
            fixture(installed)
            (installed / 'old-file').touch()
            rename = Path.rename

            def fail_install(path, target):
                if path.name == 'extension' and path.parent.name.startswith('.extension-build-'):
                    raise OSError('rename failed')
                return rename(path, target)

            with patch.object(extension, 'ROOT', root), patch.object(extension, 'build_bundle', side_effect=fixture), \
                    patch.object(Path, 'rename', fail_install):
                with self.assertRaises(OSError):
                    extension.main()
            self.assertTrue((installed / 'old-file').exists())
