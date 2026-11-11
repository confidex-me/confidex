"""Check release identity and preserve the live D1 index and Worker variables."""
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import common

spec = importlib.util.spec_from_file_location('cloudflare_deploy', common.ROOT / 'builders/cloudflare/deploy.py')
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)
SOURCE = {'version': '1.2.3+gaaaaaa', 'commit': 'a' * 40}


def archive(path, files):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, 'w:gz') as output:
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            output.addfile(info, io.BytesIO(payload))


class CloudflareTests(unittest.TestCase):
    def test_no_token_skips_all_commands(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(deploy, 'run') as run, patch('builtins.print'):
            deploy.main()
            run.assert_not_called()
        with patch.dict(os.environ, {'CLOUDFLARE_API_TOKEN': 'public-test-token'}, clear=True), patch.object(deploy, 'run') as run:
            with self.assertRaisesRegex(SystemExit, 'repository variable or secret'):
                deploy.main()
            run.assert_not_called()

    def test_unpack_rejects_other_source_before_replacing_existing_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / 'web'
            destination.mkdir()
            (destination / 'existing').write_text('public fixture')
            archive(root / 'release.tar.gz', {'BUILD.json': json.dumps(SOURCE).encode()})
            with self.assertRaises(ValueError):
                deploy.unpack(root / 'release.tar.gz', destination, 'BUILD.json', SOURCE | {'commit': 'b' * 40})
            self.assertTrue((destination / 'existing').is_file())
            deploy.unpack(root / 'release.tar.gz', destination, 'BUILD.json', SOURCE)
            self.assertFalse((destination / 'existing').exists())

    def test_deployment_reuses_d1_and_keeps_variables_without_schema_writes(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(deploy, 'ROOT', Path(temporary)):
            root = Path(temporary)
            config = root / 'apps/confidexsyncd/wrangler.toml'
            config.parent.mkdir(parents=True)
            original = '''name = "syncd"
main = "build/index.js"
[[d1_databases]]
binding = "INDEX"
database_name = "existing-index"
database_id = "00000000-0000-0000-0000-000000000000"
[vars]
BACKEND_S3_URL_0 = "https://placeholder.invalid/bucket"
[observability]
enabled = true
'''
            config.write_text(original)
            app = root / 'apps/confidex/wrangler.toml'
            app.parent.mkdir(parents=True)
            app.write_text('name = "app"\n')
            directory = root / 'dist/releases'
            archive(directory / 'confidex-1.2.3+gaaaaaa-web.tar.gz', {'BUILD.json': json.dumps(SOURCE).encode(), 'index.html': b'public fixture'})
            archive(directory / 'confidexsyncd-1.2.3+gaaaaaa-worker.tar.gz', {'SOURCE.json': json.dumps(SOURCE).encode(), 'index.js': b'public fixture', 'index_bg.wasm': b'\0asm\1\0\0\0'})
            commands = []
            database = {'name': 'existing-index', 'uuid': '12345678-1234-4234-8234-123456789abc'}

            databases = [database]

            def run(*command, **kwargs):
                values = [str(value) for value in command]
                commands.append(values)
                if values[2:4] == ['d1', 'list']:
                    return types.SimpleNamespace(stdout=json.dumps(databases))
                self.assertEqual(values[2], 'deploy')
                self.assertIn('--keep-vars', values)
                selected = Path(values[values.index('--config') + 1])
                if selected != app:
                    text = selected.read_text()
                    self.assertIn(database['uuid'], text)
                    self.assertIn('[observability]', text)
                    self.assertNotIn('[vars]', text)
                    self.assertNotIn('placeholder.invalid', text)

            environment = {'CLOUDFLARE_API_TOKEN': 'public-test-token', 'CLOUDFLARE_ACCOUNT_ID': 'public-test-account', 'RELEASE_TAG': 'v1.2.3'}
            with patch.dict(os.environ, environment, clear=True), patch.object(deploy.subprocess, 'check_output', return_value='a' * 40), patch.object(deploy, 'run', side_effect=run):
                deploy.main()
                self.assertEqual(len(commands), 3)
                commands.clear()
                databases.clear()
                with self.assertRaises(SystemExit):
                    deploy.main()
                self.assertEqual(len(commands), 1)
            self.assertEqual(len(commands), 1)
            self.assertEqual(config.read_text(), original)
            self.assertFalse(list(config.parent.glob('wrangler.release-*.toml')))
            self.assertTrue((root / 'dist/web/index.html').is_file())


if __name__ == '__main__':
    unittest.main()
