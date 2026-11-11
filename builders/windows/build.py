#!/usr/bin/env python3
"""Build Windows binaries and a native MSI installer."""
import os
import shutil
import sys
import tempfile
import uuid
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artifacts import filename
from common import ICONS, ROOT, metadata, native, options, run

WIX_VERSION = '5.0.2'
NAMESPACE = 'http://wixtoolset.org/schemas/v4/wxs'
ET.register_namespace('', NAMESPACE)


def element(parent, tag, **attributes):
    return ET.SubElement(parent, '{' + NAMESPACE + '}' + tag, attributes)


def manifest(args, staging):
    root = ET.Element('{' + NAMESPACE + '}Wix')
    package = element(root, 'Package', Name='Confidex', Manufacturer='Confidex',
                      Version=args.version.split('-')[0].split('+')[0], Language='1033',
                      UpgradeCode='C581435B-43B8-4C0A-B403-393FC37CC8A7', Scope='perMachine', InstallerVersion='500')
    element(package, 'MajorUpgrade', DowngradeErrorMessage='A newer version of Confidex is installed.')
    element(package, 'MediaTemplate', EmbedCab='yes')
    program = element(package, 'StandardDirectory', Id='ProgramFiles64Folder')
    install = element(program, 'Directory', Id='INSTALLFOLDER', Name='Confidex')
    element(package, 'StandardDirectory', Id='ProgramMenuFolder')
    feature = element(package, 'Feature', Id='Main', Title='Confidex', Level='1')
    for index, path in enumerate(sorted(staging.rglob('*'))):
        if not path.is_file():
            continue
        relative = path.relative_to(staging)
        parent = install
        for part_index in range(len(relative.parts) - 1):
            directory_id = 'Dir' + uuid.uuid5(uuid.NAMESPACE_URL, '/'.join(relative.parts[:part_index + 1])).hex
            found = install.find('.//*[@Id="' + directory_id + '"]')
            parent = found if found is not None else element(parent, 'Directory', Id=directory_id, Name=relative.parts[part_index])
        component_id = 'File' + str(index)
        component = element(parent, 'Component', Id=component_id, Guid='*')
        attributes = {'Id': 'AppExe' if relative.as_posix() == 'confidexm.exe' else component_id,
                      'Source': str(path), 'KeyPath': 'yes'}
        file = element(component, 'File', **attributes)
        if relative.as_posix() == 'confidexm.exe':
            element(file, 'Shortcut', Id='StartMenu', Directory='ProgramMenuFolder', Name='Confidex',
                    WorkingDirectory='INSTALLFOLDER', Advertise='yes', Icon='ConfidexIcon')
        if relative.as_posix() == 'cfdex.exe':
            element(component, 'Environment', Id='CliPath', Name='PATH', Value='[INSTALLFOLDER]',
                    Part='last', Action='set', System='yes')
        element(feature, 'ComponentRef', Id=component_id)
    element(package, 'Icon', Id='ConfidexIcon', SourceFile=str(ICONS / 'Confidex.ico'))
    element(package, 'Property', Id='ARPPRODUCTICON', Value='ConfidexIcon')
    element(package, 'Property', Id='ARPHELPLINK', Value='https://confidex.me')
    element(package, 'Property', Id='CONFIDEXBUILDVERSION', Value=args.version)
    element(package, 'Property', Id='ARPURLINFOABOUT', Value='https://confidex.me')
    return ET.ElementTree(root)


def package(args, binaries):
    wix = ROOT / f'.tools/wix-{WIX_VERSION}/wix.exe'
    if not wix.exists():
        run('dotnet', 'tool', 'install', 'wix', '--version', WIX_VERSION, '--tool-path', wix.parent,
            cwd=ROOT / 'builders/windows', env=dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1'))
    actual = run(wix, '--version', capture_output=True, text=True).stdout.strip().split('+')[0]
    if actual != WIX_VERSION:
        raise ValueError(f'Expected WiX {WIX_VERSION}, found {actual}')
    target = ('aarch64' if args.arch == 'arm64' else 'x86_64') + '-pc-windows-msvc'
    output = args.output / filename('confidex', args.version, f'{args.arch}-windows', 'msi')
    with tempfile.TemporaryDirectory(prefix='confidex-msi-') as temp:
        staging = Path(temp) / 'files'
        staging.mkdir()
        for source, name in [('confidex.exe', 'confidexm.exe'), ('cfdex.exe', 'cfdex.exe')]:
            shutil.copy2(binaries / source, staging / name)
        for name, data in metadata(args.version, target).items():
            path = staging / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        source = Path(temp) / 'installer.wxs'
        manifest(args, staging).write(source, encoding='utf-8', xml_declaration=True)
        run(wix, 'build', source, '-pdbtype', 'none', '-arch', 'arm64' if args.arch == 'arm64' else 'x64', '-o', output)
    return output


if __name__ == '__main__':
    args = options()
    environment = dict(os.environ)
    environment['RUSTFLAGS'] = '--cfg reqwest_unstable -C target-feature=+crt-static'
    binaries = native(args, environment)
    print(package(args, binaries))
    output = args.output / filename('confidexsyncd', args.version, f'{args.arch}-windows', 'zip')
    files = metadata(args.version, f'{args.arch}-windows', 'confidexsyncd')
    files['bin/confidexsyncd.exe'] = (binaries / 'confidexsyncd.exe').read_bytes()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    print(output)
