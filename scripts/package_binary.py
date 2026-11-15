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
    parser.add_argument('--platform', required=True, choices=['windows-x64', 'linux-x64', 'minux-x64'])
    parser.add_argument('--version', default='1.3.9')
    parser.add_argument('--third-party', action='append', default=[], type=Path)
    parser.add_argument('--runtime-dir', type=Path, help='verified MinUX runtime output, including its manifest and licenses')
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
        shutil.copytree(root / 'native' / 'video', package / 'native' / 'video',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'test.ps1'))
        shutil.copytree(root / 'native' / 'minux', package / 'native' / 'minux')
        bridge_name = 'minilang_video.dll' if args.platform == 'windows-x64' else 'libminilang_video.so'
        runtime_source = (args.runtime_dir or root/'build/minux-native').resolve()
        bridge_source = (runtime_source / bridge_name if args.platform == 'minux-x64'
                         else root / 'build' / 'native' / 'video' / args.platform / bridge_name)
        if not bridge_source.is_file():
            build_script = ('native/video/windows/build.ps1' if args.platform == 'windows-x64'
                            else 'native/video/linux/build.sh')
            raise FileNotFoundError(
                f'native video bridge is missing: run {build_script} before packaging')
        runtime_directory = package / 'runtimes' / args.platform
        runtime_directory.mkdir(parents=True)
        bridge = runtime_directory / bridge_name
        shutil.copy2(bridge_source, bridge)
        minux_runtime = None
        if args.platform == 'minux-x64':
            if binary.stat().st_size > 16*1024*1024:
                raise ValueError('MinUX compiler exceeds the native loader limit; build with --pack')
            manifest_source = runtime_source/'runtime-manifest.json'
            minux_runtime = json.loads(manifest_source.read_text(encoding='utf-8'))
            for library, record in minux_runtime['libraries'].items():
                data = (runtime_source/library).read_bytes()
                if len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
                    raise ValueError(f'MinUX runtime does not match its audited manifest: {library}')
            for library in ('libminilang_minux.so', 'libminigui_minux.so'):
                shutil.copy2(runtime_source/library, runtime_directory/library)
            shutil.copy2(manifest_source, runtime_directory/'runtime-manifest.json')
            shutil.copytree(runtime_source/'licenses', package/'third-party'/'minux')
            bundle = runtime_source/'ca-certificates.crt'
            if bundle.is_file():
                shutil.copy2(bundle, runtime_directory/bundle.name)
            shutil.copy2(root/'tools/build_minux_native.py', package/'native'/'build_minux_native.py')
        for filename in ['LICENSE', 'THIRD_PARTY_NOTICES.md', 'README-BINARY.md', 'CHANGELOG.md', f'RELEASE_NOTES_{args.version}.md']:
            shutil.copy2(root / filename, package / filename)
        for document in ('EXECUTABLE_PACKING.md', 'INCREMENTAL_BUILDS.md',
                         'MINUX.md',
                         'PLATFORM_SERVICES.md', 'OOP.md',
                         'reports/NATIVE_PACKING_2026-11-14.md',
                         'reports/STDLIB_OOP_2026-11-14.md',
                         'reports/OOP_DISPATCH_2026-11-14.md',
                         'reports/OOP_DISPATCH_2026-11-14.json',
                         'reports/TYPEOF_FOLDING_2026-11-13.md',
                         'reports/TYPEOF_FOLDING_2026-11-13.json',
                         'reports/LOOP_PARITY_2026-11-13.md',
                         'reports/LOOP_PARITY_2026-11-13.json',
                         'reports/ARRAY_LOOP_USE_COUNT_GATE_2026-11-12.md',
                         'reports/ARRAY_LOOP_USE_COUNT_GATE_2026-11-12.json',
                         'reports/REGISTER_NAME_DISPATCH_2026-11-13.md',
                         'reports/REGISTER_NAME_DISPATCH_2026-11-13.json',
                         'reports/COMPILER_OPTIMIZATIONS_2026-11-04.md',
                         'reports/COMPILER_OPTIMIZATIONS_2026-11-04.json',
                         'reports/COMPILER_OPTIMIZATIONS_2026-11-06.md',
                         'reports/COMPILER_OPTIMIZATIONS_2026-11-06.json',
                         'reports/COMPILER_OPTIMIZATIONS_2026-10-30.md',
                         'reports/COMPILER_OPTIMIZATION_EXPERIMENTS_2026-10-30.md',
                         'reports/INCREMENTAL_BUILDS_2026-10-29.md',
                         'reports/INCREMENTAL_BUILDS_2026-10-29.json',
                         f'reports/release-{args.version}-version-matrix.json'):
            destination = package / 'docs' / document
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / 'docs' / document, destination)
        example = package / 'examples' / 'hello.ml'
        example.parent.mkdir()
        example.write_text('import std.string_builder as sb\n\nfunction main(args)\n'
                           '  message = sb.StringBuilder.new()\n  message.append("Hello from MiniLang!")\n'
                           '  print message.toString()\n  return 0\nend function\n', encoding='utf-8')
        manifest = {'compiler': compiler_name, 'version': args.version, 'platform': args.platform,
                    'compilerSourceRevision': revision,
                    'executable': executable.name,
                    'executableSha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'nativeVideoBridge': {
                        'abiVersion': 1,
                        'path': str(bridge.relative_to(package)).replace('\\', '/'),
                        'sha256': hashlib.sha256(bridge.read_bytes()).hexdigest(),
                    }}
        if minux_runtime is not None:
            manifest['minuxRuntime'] = {
                'requiredKernelCommit': '3675df7',
                'manifest': f'runtimes/{args.platform}/runtime-manifest.json',
                'libraries': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in sorted(runtime_directory.glob('*.so'))},
                'loaderLimitBytes': 16*1024*1024,
            }
        (package / 'BUILD_INFO.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        if args.third_party:
            licenses = package / 'third-party'
            licenses.mkdir(exist_ok=True)
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
            def linux_archive_mode(info: tarfile.TarInfo) -> tarfile.TarInfo:
                """Set portable Linux modes even when packaging on Windows."""
                # Windows chmod only controls the read-only attribute; it
                # cannot supply the executable bits tarfile reads from stat.
                executable_member = (info.name == f'{name}/mlc' or info.name.endswith('.sh')
                                     or (args.platform == 'minux-x64' and info.name.endswith('.so')))
                info.mode = 0o755 if info.isdir() or executable_member else 0o644
                return info

            archive = output / (name + '.tar.gz')
            with tarfile.open(archive, 'w:gz', compresslevel=9) as target:
                target.add(package, arcname=name, filter=linux_archive_mode)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    Path(str(archive) + '.sha256').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    print(f'Built {archive}\nSHA256 {digest}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
