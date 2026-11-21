#!/usr/bin/env python3
"""Build the unpacked Chromium extension with the pinned web tools."""
import fcntl
import json
import re
import shutil
import tempfile
from pathlib import Path

from build import ROOT, build_wasm, wasm_tools


def build_bundle(bundle):
    target, bindgen, optimizer = wasm_tools()
    source = ROOT / 'apps/confidex-extension/web'
    bundle.mkdir(parents=True)
    for name in ('manifest.json', 'background.js', 'session.html', 'session.css',
                 'session-boot.js', 'session-worker.js', 'content-bootstrap.js'):
        shutil.copy2(source / name, bundle)
    messages = {}
    for path in sorted((ROOT / 'crates/confidex-ui/locales').glob('*.ftl')):
        if path.name.startswith('gallery.'):
            continue
        catalogue = dict(re.findall(r'^(extension-startup-error|vault-working|vault-refresh) = (.+)$',
                                    path.read_text(), re.MULTILINE))
        if len(catalogue) != 3:
            raise ValueError(f'Missing startup translations in {path.name}')
        messages[path.stem] = catalogue
    (bundle / 'session-messages.json').write_text(json.dumps(messages, ensure_ascii=False))
    for directory, names in (
        ('fonts', ('*.ttf', '*.txt')),
        ('icons', ('16.png', '32.png', '48.png', '128.png')),
    ):
        destination = bundle / directory
        destination.mkdir()
        path = ROOT / ('crates/confidex-ui/assets/fonts' if directory == 'fonts'
                       else 'apps/confidex/assets/icons/png')
        for pattern in names:
            for asset in sorted(path.glob(pattern)):
                shutil.copy2(asset, destination)
    shutil.copy2(ROOT / 'LICENSE', bundle)
    for feature, name in [('session', 'engine'), ('ui', 'ui')]:
        build_wasm(target, bindgen, optimizer, bundle / name, 'confidex-extension',
                   'confidex_extension', name, 268435456, '--features', feature)
    build_wasm(target, bindgen, optimizer, bundle / 'content', 'confidex-extension-content',
               'confidex_extension_content', 'content', 16777216)
    for path in bundle.rglob('*.d.ts'):
        path.unlink()


def validate_bundle(bundle):
    for name in ('manifest.json', 'session.html', 'session.css', 'session-boot.js',
                 'session-messages.json', 'session-worker.js', 'background.js',
                 'content-bootstrap.js', 'engine/engine.js', 'ui/ui.js', 'content/content.js'):
        if not (bundle / name).is_file() or not (bundle / name).stat().st_size:
            raise ValueError(f'Missing extension asset: {name}')
    for name in ('engine/engine_bg.wasm', 'ui/ui_bg.wasm', 'content/content_bg.wasm'):
        with (bundle / name).open('rb') as module:
            if module.read(8) != b'\0asm\1\0\0\0':
                raise ValueError(f'Invalid extension WASM: {name}')
    for path in bundle.rglob('*.js'):
        for relative in re.findall(r'(?:from\s*|import\s*\(\s*)[\'"](\.[^\'"]+)[\'"]',
                                   path.read_text()):
            imported = (path.parent / relative).resolve()
            if not imported.is_relative_to(bundle.resolve()) or not imported.is_file():
                raise ValueError(f'Missing extension import in {path.relative_to(bundle)}: {relative}')


def main():
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    bundle = dist / 'extension'
    # Serialize builders and keep the installed bundle available during compilation.
    with (dist / '.extension-build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory(prefix='.extension-build-', dir=dist) as temporary:
            stage = Path(temporary) / 'extension'
            previous = Path(temporary) / 'previous'
            build_bundle(stage)
            validate_bundle(stage)
            if bundle.exists():
                bundle.rename(previous)
            try:
                stage.rename(bundle)
            except OSError:
                if previous.exists():
                    previous.rename(bundle)
                raise
    print(bundle)


if __name__ == '__main__':
    main()
