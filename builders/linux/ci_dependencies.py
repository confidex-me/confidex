#!/usr/bin/env python3
"""Install Ubuntu CI dependencies with bounded APT mirror fallback."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import run

MIRRORS = Path('/etc/apt/apt-mirrors.txt')
PREFERRED = 'https://mirrors.edge.kernel.org/ubuntu/\tpriority:0\n'
OPTIONS = ['-o', 'Acquire::Retries=1', '-o', 'Acquire::http::Timeout=10',
           '-o', 'Acquire::https::Timeout=10', '-o', 'APT::Update::Error-Mode=any']
PACKAGES = ['libtss2-dev', 'libxkbcommon-dev', 'libwayland-dev', 'libx11-dev',
            'libxi-dev', 'libxcursor-dev', 'libxrandr-dev', 'libgl1-mesa-dev']


def main():
    mirrors = MIRRORS.read_text()
    MIRRORS.write_text(PREFERRED + mirrors.replace(PREFERRED, ''))
    print('APT preferred mirror: https://mirrors.edge.kernel.org/ubuntu/', flush=True)
    run('apt-get', *OPTIONS, 'update')
    run('apt-get', *OPTIONS, 'install', '-y', *PACKAGES)


if __name__ == '__main__':
    main()
