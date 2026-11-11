"""Read public edited-source outputs with independent container tools and CLI."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

kind, filename = sys.argv[1:3]
if kind in ['bitwarden-zip', 'onepassword-1pux']:
    with zipfile.ZipFile(filename) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(set(archive.namelist()))
        data_name = 'data.json' if kind == 'bitwarden-zip' else 'export.data'
        data = archive.read(data_name).decode()
        files = [archive.read(name).hex() for name in archive.namelist()
                 if name.startswith(('attachments/', 'files/')) and not name.endswith('/')]
        assert files == ['00ff0402'], files
    print(json.dumps({'data': data, 'attachment': files[0]}))
elif kind == 'csv':
    with open(filename, newline='', encoding='utf-8') as source:
        rows = list(csv.reader(source))
    assert rows == [
        ['name', 'url', 'username', 'password', 'note'],
        ['PUBLIC-current-title', 'https://current.example.invalid/edited?q=1&v=2',
         'current-user@example.invalid', 'PUBLIC-current-password\n第二行',
         'PUBLIC-current-note\n\nLast line']
    ], rows
    print(json.dumps({'rows': 1}))
else:
    assert kind in ['keepass-xml', 'kdbx']
    cli = sys.argv[3]
    password = sys.stdin.buffer.read()
    with tempfile.TemporaryDirectory(prefix='public-export-reverse-') as directory:
        database = Path(filename)
        if kind == 'keepass-xml':
            database = Path(directory) / 'public.kdbx'
            subprocess.run([cli, 'import', '-q', '-p', '-t', '100', filename, str(database)],
                           input=(password + b'\n') * 2, capture_output=True, check=True, timeout=60)
        xml = subprocess.run([cli, 'export', '-q', str(database)], input=password + b'\n',
                             capture_output=True, check=True, timeout=60).stdout
        entries = ET.fromstring(xml).findall('.//Entry')
        assert len(entries) == 1
        fields = {field.findtext('Key'): field.find('Value') for field in entries[0].findall('String')}
        for key, value in [
            ('Title', 'PUBLIC-current-title'), ('UserName', 'current-user@example.invalid'),
            ('Password', 'PUBLIC-current-password\n第二行'),
            ('URL', 'https://current.example.invalid/edited?q=1&v=2'),
            ('Secondary URL', 'https://added.example.invalid/'),
            ('Notes', 'PUBLIC-current-note\n\nLast line')
        ]:
            assert fields[key].text == value, (key, fields[key].text)
        assert all(fields[key].get('ProtectInMemory') == 'True' for key in ['Password', 'Notes'])
        source = sys.argv[4]
        if source == 'keepass' or source.startswith('kdbx-'):
            assert fields['URL'].get('ProtectInMemory') == 'True', 'protected source URL became public'
        otp = fields['otp'].text
        from urllib.parse import parse_qs, urlparse
        params = parse_qs(urlparse(otp).query)
        assert {key: params[key] for key in ['secret', 'algorithm', 'digits', 'period']} == {
            'secret': ['MZXW6YTBOI'], 'algorithm': ['SHA512'], 'digits': ['8'], 'period': ['60']}
        for removed in [b'PUBLIC-FIXTURE-PASSWORD', b'PUBLIC-FIXTURE-ORG', b'PUBLIC-FIXTURE-OLD',
                        b'PUBLIC-FIXTURE-HIDDEN', b'PUBLIC-FIXTURE-FUTURE', b'PUBLIC-FIXTURE-PIN',
                        b'PUBLIC-FIXTURE-GUARDED', b'PUBLIC-FIXTURE-PLUGIN',
                        b'alice@example.invalid', b'mail.example.invalid', b'https://second.example.invalid',
                        b'PUBLIC-FIXTURE-CREDENTIAL', b'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                        b'old public password', b'deleted public password', b'current public password']:
            assert removed not in xml, removed
        tree = ET.fromstring(xml)

        def entry_path(group, parents=()):
            path = parents + (group.findtext('Name', ''),)
            if entries[0].findtext('UUID') in [entry.findtext('UUID') for entry in group.findall('Entry')]:
                return '/'.join(path[1:] + ('PUBLIC-current-title',))
            for child in group.findall('Group'):
                found = entry_path(child, path)
                if found is not None:
                    return found

        path = entry_path(tree.find('Root/Group'))
        assert path is not None
        attachment = Path(directory) / 'current.bin'
        subprocess.run([cli, 'attachment-export', '-q', str(database), path, 'current.bin', str(attachment)],
                       input=password + b'\n', capture_output=True, check=True, timeout=60)
        assert attachment.read_bytes() == b'\0\xff\4\2'
    print(json.dumps({'records': 1, 'currentOtp': True, 'attachment': '00ff0402'}))
