"""Stable release names shared with the website downloads parser."""
import json
import re
from pathlib import Path

CONTRACT = json.loads(Path(__file__).with_name('artifacts.json').read_text())


def parse(name):
    for entry in CONTRACT['formats']:
        pattern = re.escape(entry['template'])
        for key, expression in {'version': CONTRACT['version_pattern'], **CONTRACT['fields']}.items():
            pattern = pattern.replace(re.escape('{' + key + '}'), f'(?P<{key}>{expression})')
        match = re.fullmatch(pattern, name)
        if match:
            return {key: entry[key] for key in ['id', 'role', 'platform', 'kind']} | {
                key: match.groupdict().get(key) for key in ['version', 'arch', 'libc']}
    return None


def filename(product, version, target, extension):
    name = f'{product}-{version}-{target}.{extension}'
    if not parse(name):
        raise ValueError(f'Unsupported release asset name: {name}')
    return name
