#!/usr/bin/env python3
"""Build a standalone reference compiler on its destination operating system."""
from __future__ import annotations

from pathlib import Path
import platform
import subprocess
import sys


def main() -> int:
    """Freeze the compiler with the pinned PyInstaller build dependency."""
    root = Path(__file__).resolve().parents[1]
    if platform.machine().lower() not in ('amd64', 'x86_64'):
        raise SystemExit('Binary release builds require an x86-64 host.')
    target = {'win32': 'windows-x64', 'linux': 'linux-x64'}.get(sys.platform)
    if target is None:
        raise SystemExit('Build on Windows or Linux; freezing is not cross-compilation.')
    subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--noupx', '--onefile',
                    '--collect-submodules', 'mlc', '--name', 'mlc',
                    '--distpath', f'build/binary/{target}', '--workpath', f'build/pyinstaller/{target}',
                    '--specpath', f'build/pyinstaller/{target}', 'mlc_win64.py'], cwd=root, check=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
