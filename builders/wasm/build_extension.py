#!/usr/bin/env python3
"""Build the unpacked Chromium extension with the pinned web tools."""
import shutil

from build import ROOT, build_wasm, wasm_tools


def main():
    target, bindgen, optimizer = wasm_tools()
    source = ROOT / 'apps/confidex-extension/web'
    bundle = ROOT / 'dist/extension'
    if bundle.exists():
        shutil.rmtree(bundle)
    bundle.mkdir(parents=True)
    for name in ('manifest.json', 'background.js', 'session.html', 'session.css',
                 'session-boot.js', 'session-worker.js', 'content-bootstrap.js'):
        shutil.copy2(source / name, bundle)
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
    print(bundle)


if __name__ == '__main__':
    main()
