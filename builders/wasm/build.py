#!/usr/bin/env python3
"""Build, optimize, check and package the complete browser application."""
import os
import shutil
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artifacts import filename
from common import ROOT, options, prepare_version, run


def check_tools(bindgen, optimizer):
    for executable, versions in [
        (bindgen, {'wasm-bindgen 0.2.130'}),
        (optimizer, {'wasm-opt version 133', 'wasm-opt version 133 (version_133)'}),
    ]:
        actual = run(executable, '--version', capture_output=True, text=True).stdout.strip()
        if actual not in versions:
            raise ValueError(f'Unexpected tool version for {executable}: {actual}')


def main():
    args = options()
    prepare_version(args)
    target = Path(os.environ.get('CARGO_TARGET_DIR', str(ROOT / 'target')))
    if not target.is_absolute():
        target = ROOT / target
    tools = ROOT / '.tools/bin'
    if not (tools / 'wasm-bindgen').exists() or not (tools / 'wasm-opt').exists():
        run(sys.executable, ROOT / 'tools/install-wasm-tools.py')
    bindgen, optimizer = tools / 'wasm-bindgen', tools / 'wasm-opt'
    check_tools(bindgen, optimizer)
    bundle, web = ROOT / 'dist/wasm', ROOT / 'dist/web'
    bundle.mkdir(parents=True, exist_ok=True)
    for package, module, name, memory in [
        ('confidex-image-codec', 'confidex_image_codec', 'image_codec', 2147483648),
        ('confidex', 'confidex', 'app', 268435456),
    ]:
        run('cargo', 'rustc', '--locked', '--profile', 'wasm-release', '-p', package,
            '--lib', '--target', 'wasm32-unknown-unknown', '--', '-C', f'link-arg=--max-memory={memory}')
        run(bindgen, target / f'wasm32-unknown-unknown/wasm-release/{module}.wasm',
            '--target', 'web', '--out-dir', bundle, '--out-name', name)
        module = bundle / f'{name}_bg.wasm'
        optimized = module.with_suffix('.optimized')
        run(optimizer, module, '-Oz', '--strip-debug', '-o', optimized)
        optimized.replace(module)
    if web.exists():
        shutil.rmtree(web)
    run('node', ROOT / 'apps/confidex/web/build-static.mjs', bundle, web)
    shutil.copy2(ROOT / 'LICENSE', web / 'LICENSE')
    run('node', ROOT / 'tools/check-web.mjs', web)
    output = args.output / filename('confidex', args.version, 'web', 'tar.gz')
    with tarfile.open(output, 'w:gz') as tar:
        for path in sorted(web.iterdir()):
            tar.add(path, arcname=path.name)
    print(output)


if __name__ == '__main__':
    main()
