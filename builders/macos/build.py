#!/usr/bin/env python3
"""Build the macOS app and package a drag-to-Applications DMG."""
import os
import plistlib
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artifacts import filename
from common import ICONS, ROOT, archive, host_arch, metadata, native, options, prepare_version, run


def build(args):
    if args.arch == host_arch():
        return native(args)
    prepare_version(args)
    target = ('aarch64' if args.arch == 'arm64' else 'x86_64') + '-apple-darwin'
    run('rustup', 'target', 'add', target)
    run('cargo', 'build', '--locked', '--release', '--target', target,
        '-p', 'confidex', '-p', 'cfdex', '-p', 'confidexsyncd')
    directory = Path(os.environ.get('CARGO_TARGET_DIR', str(ROOT / 'target')))
    if not directory.is_absolute():
        directory = ROOT / directory
    return directory / target / 'release'


def package(args, binaries):
    target = ('aarch64' if args.arch == 'arm64' else 'x86_64') + '-apple-darwin'
    output = args.output / filename('confidex', args.version, f'{args.arch}-macos', 'dmg')
    with tempfile.TemporaryDirectory(prefix='confidex-dmg-') as temp:
        staging = Path(temp)
        app = staging / 'Confidex.app'
        executables = app / 'Contents/MacOS'
        resources = app / 'Contents/Resources'
        executables.mkdir(parents=True)
        resources.mkdir(parents=True)
        for source, name in [('confidex', 'confidexm'), ('cfdex', 'cfdex')]:
            shutil.copy2(binaries / source, executables / name)
        shutil.copy2(ICONS / 'Confidex.icns', resources / 'Confidex.icns')
        info = {
            'CFBundleIdentifier': 'me.confidex.app', 'CFBundleName': 'Confidex',
            'CFBundleExecutable': 'confidexm', 'CFBundleIconFile': 'Confidex.icns',
            'CFBundlePackageType': 'APPL', 'CFBundleVersion': args.version.split('-')[0].split('+')[0],
            'CFBundleShortVersionString': args.version.split('-')[0].split('+')[0],
            'CFBundleGetInfoString': args.version, 'NSHighResolutionCapable': True,
        }
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        for name, data in metadata(args.version, target).items():
            path = resources / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        run('codesign', '--force', '--sign', '-', executables / 'cfdex')
        run('codesign', '--force', '--deep', '--sign', '-', app)
        run('codesign', '--verify', '--deep', '--strict', app)
        (staging / 'Applications').symlink_to('/Applications', target_is_directory=True)
        shutil.copy2(ICONS / 'Confidex.icns', staging / '.VolumeIcon.icns')
        run('xcrun', 'SetFile', '-a', 'C', staging)
        run('hdiutil', 'create', '-ov', '-volname', 'Confidex', '-srcfolder', staging,
            '-format', 'UDZO', '-fs', 'HFS+', output)
    run('hdiutil', 'verify', output)
    return output


if __name__ == '__main__':
    args = options()
    binaries = build(args)
    print(package(args, binaries))
    print(archive('confidexsyncd', args.version, f'{args.arch}-macos', {'bin/confidexsyncd': binaries / 'confidexsyncd'}, args.output))
