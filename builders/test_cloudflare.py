"""Check release identity and preserve the live D1 index and Worker variables."""
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError, URLError
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
    def test_worker_index_reads_only_the_existing_d1_binding(self):
        environment = {'CLOUDFLARE_API_TOKEN': 'public-test-token', 'CLOUDFLARE_ACCOUNT_ID': 'public-test-account'}
        database_id = '12345678-1234-4234-8234-123456789abc'
        for key in ['database_id', 'id']:
            bindings = [
                {'name': 'INDEX', 'type': 'plain_text', 'text': 'unrelated'},
                {'name': 'OTHER', 'type': 'd1', key: '00000000-0000-0000-0000-000000000000'},
                {'name': 'INDEX', 'type': 'd1', key: database_id},
            ]
            response = {'success': True, 'result': {'bindings': bindings}}
            with self.subTest(key=key), patch.dict(os.environ, environment, clear=True), patch.object(
                deploy, 'urlopen', return_value=io.BytesIO(json.dumps(response).encode())
            ) as request:
                self.assertEqual(deploy.worker_index('syncd'), database_id)
                args, kwargs = request.call_args
                self.assertEqual(args[0].get_method(), 'GET')
                self.assertEqual(args[0].full_url, 'https://api.cloudflare.com/client/v4/accounts/public-test-account/workers/scripts/syncd/settings')
                self.assertEqual(args[0].get_header('Authorization'), 'Bearer public-test-token')
                self.assertEqual(kwargs, {'timeout': 30})

    def test_worker_index_rejects_missing_ambiguous_or_invalid_bindings(self):
        binding = {'name': 'INDEX', 'type': 'd1', 'id': '12345678-1234-4234-8234-123456789abc'}
        responses = [None, [], {'success': False}, {'success': True, 'result': None},
                     {'success': True, 'result': {'bindings': None}}]
        for bindings in [[], [binding, binding], [dict(binding, type='plain_text')],
                         [dict(binding, id='invalid')], [dict(binding, id=None)],
                         [dict(binding, id=42)]]:
            responses.append({'success': True, 'result': {'bindings': bindings}})
        environment = {'CLOUDFLARE_API_TOKEN': 'public-test-token', 'CLOUDFLARE_ACCOUNT_ID': 'public-test-account'}
        for response in responses:
            with self.subTest(response=response), patch.dict(os.environ, environment, clear=True), patch.object(
                deploy, 'urlopen', return_value=io.BytesIO(json.dumps(response).encode())
            ), self.assertRaises(SystemExit):
                deploy.worker_index('syncd')

    def test_worker_index_reports_http_errors_without_credentials(self):
        environment = {'CLOUDFLARE_API_TOKEN': 'public-test-token', 'CLOUDFLARE_ACCOUNT_ID': 'public-test-account'}
        for error in [HTTPError('https://api.cloudflare.com/', 403, 'Forbidden', {}, None),
                      URLError('public-test-token'), ValueError('public-test-token')]:
            with self.subTest(error=type(error).__name__), patch.dict(os.environ, environment, clear=True), patch.object(
                deploy, 'urlopen', side_effect=error
            ), self.assertRaises(SystemExit) as caught:
                deploy.worker_index('syncd')
            self.assertIn('Cannot read Worker syncd', str(caught.exception))
            self.assertNotIn('public-test-token', str(caught.exception))
            if isinstance(error, HTTPError):
                self.assertIn('HTTP 403', str(caught.exception))
                self.assertIn('Workers Scripts permissions', str(caught.exception))

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
            database = {'name': 'INDEX', 'type': 'd1', 'id': '12345678-1234-4234-8234-123456789abc'}

            bindings = [database]

            def run(*command, **kwargs):
                values = [str(value) for value in command]
                commands.append(values)
                self.assertEqual(values[2], 'deploy')
                self.assertIn('--keep-vars', values)
                selected = Path(values[values.index('--config') + 1])
                if selected != app:
                    text = selected.read_text()
                    self.assertIn(database['id'], text)
                    self.assertIn('[observability]', text)
                    self.assertNotIn('[vars]', text)
                    self.assertNotIn('placeholder.invalid', text)

            environment = {'CLOUDFLARE_API_TOKEN': 'public-test-token', 'CLOUDFLARE_ACCOUNT_ID': 'public-test-account', 'RELEASE_TAG': 'v1.2.3'}
            def response(*args, **kwargs):
                return io.BytesIO(json.dumps({'success': True, 'result': {'bindings': bindings}}).encode())

            with patch.dict(os.environ, environment, clear=True), patch.object(deploy.subprocess, 'check_output', return_value='a' * 40), patch.object(deploy, 'run', side_effect=run), patch.object(deploy, 'urlopen', side_effect=response):
                deploy.main()
                self.assertEqual(len(commands), 2)
                commands.clear()
                bindings.clear()
                with self.assertRaises(SystemExit):
                    deploy.main()
                self.assertEqual(len(commands), 0)
            self.assertEqual(len(commands), 0)
            self.assertEqual(config.read_text(), original)
            self.assertFalse(list(config.parent.glob('wrangler.release-*.toml')))
            self.assertTrue((root / 'dist/web/index.html').is_file())


if __name__ == '__main__':
    unittest.main()
