#!/usr/bin/env python3
"""Package a verified compiler executable and its standard library for release."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile


def main() -> int:
    """Create a platform archive, binary manifest and SHA-256 sidecar."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--platform', required=True, choices=['windows-x64', 'linux-x64'])
    parser.add_argument('--version', default='1.2.6')
    parser.add_argument('--third-party', action='append', default=[], type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    compiler_name = 'MiniLangCompilerPy' if (root / 'mlc_win64.py').is_file() else 'MiniLangCompilerML'
    binary = args.binary.resolve(strict=True)
    expected = b'MZ' if args.platform == 'windows-x64' else b'\x7fELF'
    with binary.open('rb') as stream:
        if not stream.read(len(expected)) == expected:
            raise ValueError('Compiler binary does not match the selected platform')
    revision = subprocess.check_output(
        ['git', '-C', str(root), 'rev-parse', f'v{args.version}^{{commit}}'], text=True).strip()
    name = f'{compiler_name}-{args.version}-{args.platform}'
    output = root / 'build' / 'releases'
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='package-', dir=output) as temporary:
        package = Path(temporary) / name
        package.mkdir()
        executable = package / ('mlc.exe' if args.platform == 'windows-x64' else 'mlc')
        shutil.copy2(binary, executable)
        executable.chmod(0o755)
        shutil.copytree(root / 'std', package / 'std', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for filename in ['LICENSE', 'README-BINARY.md', 'CHANGELOG.md', f'RELEASE_NOTES_{args.version}.md']:
            shutil.copy2(root / filename, package / filename)
        example = package / 'examples' / 'hello.ml'
        example.parent.mkdir()
        example.write_text('import std.string_builder as sb\n\nfunction main(args)\n'
                           '  message = sb.StringBuilder.new()\n  message.append("Hello from MiniLang!")\n'
                           '  print message.toString()\n  return 0\nend function\n', encoding='utf-8')
        manifest = {'compiler': compiler_name, 'version': args.version, 'platform': args.platform,
                    'compilerSourceRevision': revision,
                    'executable': executable.name,
                    'executableSha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
        (package / 'BUILD_INFO.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        if args.third_party:
            licenses = package / 'third-party'
            licenses.mkdir()
            for path in args.third_party:
                if path.is_dir():
                    shutil.copytree(path, licenses / path.name)
                else:
                    shutil.copy2(path, licenses / path.name)
        if args.platform == 'windows-x64':
            archive = output / (name + '.zip')
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as target:
                for path in sorted(package.rglob('*')):
                    if path.is_file():
                        target.write(path, path.relative_to(package.parent))
        else:
            archive = output / (name + '.tar.gz')
            with tarfile.open(archive, 'w:gz', compresslevel=9) as target:
                target.add(package, arcname=name)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    Path(str(archive) + '.sha256').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    print(f'Built {archive}\nSHA256 {digest}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
