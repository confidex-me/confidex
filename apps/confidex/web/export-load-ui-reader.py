"""Read only the public 10000-record UI workload with independent container tools."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
import zipfile

kind, filename = sys.argv[1:3]
if kind in ['bitwarden-zip', 'onepassword-1pux']:
    with zipfile.ZipFile(filename) as archive:
        assert archive.testzip() is None
        names = archive.namelist()
        assert len(names) == len(set(names))
        for info in archive.infolist():
            assert info.compress_type == zipfile.ZIP_STORED and not info.flag_bits & 1
            assert info.external_attr >> 16 & 0o777 == 0o600
        if kind == 'bitwarden-zip':
            assert 'data.json' in names and set(names) <= {'data.json', 'attachments/'}
            data = archive.read('data.json').decode()
            items = json.loads(data)['items']
            assert len(items) == 10000
            ids = [item['id'] for item in items]
        else:
            assert set(names) == {'export.attributes', 'export.data'}
            assert json.loads(archive.read('export.attributes'))['version'] == 3
            data = archive.read('export.data').decode()
            account = json.loads(data)['accounts'][0]
            vault = account['vaults'][0]
            assert len(vault['items']) == 10000
            ids = [account['attrs']['uuid'], vault['attrs']['uuid']] + [item['uuid'] for item in vault['items']]
        assert len(ids) == len(set(ids))
        assert all(isinstance(identifier, str) and identifier for identifier in ids)
        if kind == 'bitwarden-zip':
            assert all(uuid.UUID(identifier).version == 4 for identifier in ids)
    print(json.dumps({'data': data, 'records': 10000}))
else:
    assert kind in ['keepass-xml', 'kdbx']
    cli = sys.argv[3]
    password = sys.stdin.buffer.read()
    with tempfile.TemporaryDirectory(prefix='public-export-load-') as directory:
        database = Path(filename)
        if kind == 'keepass-xml':
            database = Path(directory)/'public.kdbx'
            subprocess.run([cli, 'import', '-q', '-p', '-t', '100', filename, str(database)],
                           input=(password+b'\n')*2, capture_output=True, check=True, timeout=60)
        xml = subprocess.run([cli, 'export', '-q', str(database)], input=password+b'\n',
                             capture_output=True, check=True, timeout=60).stdout
        entries = ET.fromstring(xml).findall('.//Entry')
        assert len(entries) == 10000
        seen = set()
        for entry in entries:
            fields = {field.findtext('Key'): field.find('Value') for field in entry.findall('String')}
            title = fields['Title'].text
            assert title.startswith('Public ')
            index = int(title.removeprefix('Public '))
            assert 0 <= index < 10000 and index not in seen
            seen.add(index)
            for key, value in [('UserName', f'public-user-{index}'), ('Password', f'PUBLIC-current-{index}'),
                               ('URL', f'https://example.invalid/{index}'), ('Notes', f'Public note {index}')]:
                assert fields[key].text == value
            assert all(fields[key].get('ProtectInMemory') == 'True' for key in ['Password', 'Notes'])
    print(json.dumps({'records': 10000, 'reader': subprocess.check_output([cli, '--version'], text=True).strip()}))
