"""Check pinned tools and the complete Worker archive."""
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import common


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, common.ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wasm = load('wasm_build', 'builders/wasm/build.py')
syncd = load('syncd_build', 'builders/syncd/build.py')
installer = load('wasm_tools', 'tools/install-wasm-tools.py')


class WasmTests(unittest.TestCase):
    def test_worker_fetches_all_targets_before_offline_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = root / '.tools/bin' / ('worker-build.exe' if syncd.os.name == 'nt' else 'worker-build')
            tool.parent.mkdir(parents=True)
            tool.touch()
            with patch.object(syncd, 'ROOT', root), patch.object(syncd, 'options'), \
                 patch.object(syncd, 'prepare_version'), patch.object(syncd, 'package'), \
                 patch.object(syncd, 'run', return_value=types.SimpleNamespace(stdout='0.8.7')) as run:
                syncd.main()
            self.assertEqual(run.call_args_list[1].args, ('cargo', 'fetch', '--locked'))
            worker = run.call_args_list[2]
            self.assertEqual(worker.args, (tool, '--release'))
            self.assertEqual(worker.kwargs['env']['CARGO_NET_OFFLINE'], 'true')

    def test_cached_tools_accept_only_pinned_versions(self):
        for optimizer in ['wasm-opt version 133', 'wasm-opt version 133 (version_133)']:
            outputs = [types.SimpleNamespace(stdout='wasm-bindgen 0.2.130\n'), types.SimpleNamespace(stdout=optimizer)]
            with patch.object(wasm, 'run', side_effect=outputs):
                wasm.check_tools('wasm-bindgen', 'wasm-opt')
        for outputs in [['wasm-bindgen 0.2.129'], ['wasm-bindgen 0.2.130', 'wasm-opt version 132']]:
            with patch.object(wasm, 'run', side_effect=[types.SimpleNamespace(stdout=value) for value in outputs]):
                with self.assertRaises(ValueError):
                    wasm.check_tools('wasm-bindgen', 'wasm-opt')

    def test_worker_archive_contains_the_actual_module_and_source(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(common.subprocess, 'check_output', return_value='a' * 40):
            root = Path(temporary)
            worker = root / 'build'
            worker.mkdir()
            args = types.SimpleNamespace(version='1.2.3+gaaaaaa', output=root)
            (worker / 'index.js').write_bytes(b'import module from "./index_bg.wasm";')
            with self.assertRaises(ValueError):
                syncd.package(args, worker)
            self.assertFalse(list(root.glob('*.tar.gz')))
            (worker / 'index_bg.wasm').write_bytes(b'\0asm\1\0\0\0')
            output = syncd.package(args, worker)
            with tarfile.open(output) as archive:
                self.assertEqual(archive.extractfile('index_bg.wasm').read(), b'\0asm\1\0\0\0')
                source = json.loads(archive.extractfile('SOURCE.json').read())
                self.assertEqual(source['version'], args.version)
                self.assertEqual(source['commit'], 'a' * 40)
                self.assertEqual(archive.extractfile('LICENSE').read(), (common.ROOT / 'apps/confidexsyncd/LICENSE').read_bytes())
                self.assertIn('NOTICES/core/LICENSE', archive.getnames())
                self.assertNotIn('worker/shim.mjs', archive.getnames())

    def test_installer_rejects_bad_digest_and_preserves_binaryen_library(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as archive:
            for name in ['release/bin/wasm-opt', 'release/lib/libbinaryen.dylib']:
                info = tarfile.TarInfo(name)
                info.size = 7
                archive.addfile(info, io.BytesIO(b'fixture'))
        payload = data.getvalue()
        with tempfile.TemporaryDirectory() as temporary, patch.object(installer, 'DEST', Path(temporary) / 'bin'), patch.object(installer.subprocess, 'check_output', return_value=payload), patch.object(installer.subprocess, 'run'):
            with self.assertRaises(ValueError):
                installer.install('https://example.invalid/tool', '0' * 64, 'wasm-opt')
            self.assertFalse(installer.DEST.exists())
            installer.install('https://example.invalid/tool', hashlib.sha256(payload).hexdigest(), 'wasm-opt')
            self.assertEqual((installer.DEST / 'wasm-opt').read_bytes(), b'fixture')
            self.assertEqual((installer.DEST.parent / 'lib/libbinaryen.dylib').read_bytes(), b'fixture')


if __name__ == '__main__':
    unittest.main()
