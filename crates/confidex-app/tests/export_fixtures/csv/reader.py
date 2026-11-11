"""Use Python's CSV reader before the independent destination mapping reader."""
import csv
from io import StringIO
from pathlib import Path
import subprocess
import sys

profile, shared, sources = sys.argv[1:]
data = sys.stdin.buffer.read()
rows = list(csv.reader(StringIO(data.decode('utf8'), newline=''), strict=True))
assert len(rows) == 2
assert len(rows[0]) == len(rows[1])
headings = {
    'chromium': ['name', 'url', 'username', 'password', 'note'],
    'firefox': ['url', 'username', 'password', 'httpRealm', 'formActionOrigin', 'guid', 'timeCreated', 'timeLastUsed', 'timePasswordChanged'],
    'apple-passwords': ['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth'],
}
assert rows[0] == headings[profile]
assert 'PUBLIC-CURRENT' in rows[1]
assert not any('PUBLIC-OLD-REMOVED' in value for value in rows[1])
if profile == 'firefox':
    assert rows[1][3:] == [''] * 6
    assert data.endswith(b'"PUBLIC-CURRENT",,,,,,\r\n')
subprocess.run(['node', str(Path(__file__).with_name('reader.cjs')), shared, sources, profile], input=data, check=True)
print('Independent Python CSV framing and exact profile header order: PASS')
