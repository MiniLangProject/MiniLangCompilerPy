"""Verify dependency-free packing, execution, restoration and byte parity.

Run on Windows with WSL Ubuntu for ELF execution. The optional Linux-native
compiler adds a third host to the cross-host/target matrix.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def run(command: list[str], *, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, timeout=240,
                            encoding='utf-8', errors='replace')
    if result.returncode != expected:
        raise AssertionError(f'{command}\nexit={result.returncode}, expected={expected}\n'
                             f'{result.stdout}\n{result.stderr}')
    return result


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--windows-compiler', required=True, type=Path)
    parser.add_argument('--python-compiler', required=True, type=Path)
    parser.add_argument('--linux-compiler', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('this runner uses Windows plus WSL Ubuntu')

    root = Path(__file__).resolve().parents[1]
    source = root / 'tests/native_packing_workload.ml'
    include = root
    linux_cache: dict[Path, str] = {}

    def linux(path: Path) -> str:
        path = path.resolve()
        if path not in linux_cache:
            linux_cache[path] = run(['wsl', '-d', 'Ubuntu', '--', 'wslpath', '-a',
                                     '-u', str(path)]).stdout.strip()
        return linux_cache[path]

    hosts = [
        ('python', [sys.executable, str(args.python_compiler.resolve())], False),
        ('windows-ml', [str(args.windows_compiler.resolve())], False),
    ]
    if args.linux_compiler:
        hosts.append(('linux-ml', ['wsl', '-d', 'Ubuntu', '--',
                                   linux(args.linux_compiler)], True))

    def compile_with(host, output: Path, target: str, pipeline: str,
                     *, pack: bool) -> None:
        _, command, is_linux = host
        convert = linux if is_linux else str
        argv = [*command, convert(source), convert(output), '-I', convert(include),
                '--target', target, pipeline]
        if pack:
            argv.append('--pack')
        run(argv)
        if not output.is_file():
            raise AssertionError(f'missing output: {output}')

    def standalone(host, mode: str, source_path: Path, destination: Path,
                   *, expected: int = 0) -> None:
        _, command, is_linux = host
        convert = linux if is_linux else str
        run([*command, mode, convert(source_path), convert(destination)], expected=expected)

    rows = []
    scratch_root = root / 'build'
    scratch_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='np-', dir=scratch_root) as folder:
        folder = Path(folder)
        for target in ('windows-x64', 'linux-x64'):
            extension = '.exe' if target == 'windows-x64' else '.elf'
            baseline = folder / f'{target}-original{extension}'
            compile_with(hosts[0], baseline, target, '--no-object-pipeline', pack=False)
            digests = []
            canonical = None
            for host in hosts:
                for pipeline in ('--no-object-pipeline', '--object-pipeline'):
                    name = f'{target}-{host[0]}-{pipeline[2:]}'
                    packed = folder / f'{name}{extension}'
                    compile_with(host, packed, target, pipeline, pack=True)
                    digest = sha(packed)
                    digests.append(digest)
                    rows.append({'target': target, 'host': host[0], 'pipeline': pipeline,
                                 'bytes': packed.stat().st_size, 'sha256': digest})
                    canonical = canonical or packed
                    restored = folder / f'{name}-restored{extension}'
                    standalone(host, '--unpack-exe', packed, restored)
                    if sha(restored) != sha(baseline):
                        raise AssertionError(f'restoration mismatch: {name}')
            if len(set(digests)) != 1:
                raise AssertionError(f'packed byte parity failed: {target}')
            separate = folder / f'{target}-standalone{extension}'
            standalone(hosts[1], '--pack-exe', baseline, separate)
            if sha(separate) != digests[0]:
                raise AssertionError(f'standalone packing mismatch: {target}')
            if target == 'windows-x64':
                execution = run([str(canonical)])
            else:
                run(['wsl', '-d', 'Ubuntu', '--', 'chmod', '+x', linux(canonical)])
                execution = run(['wsl', '-d', 'Ubuntu', '--', linux(canonical)])
            if execution.stdout.strip() != 'native pack 17 [OK]':
                raise AssertionError(f'packed program output mismatch: {execution.stdout!r}')

            corrupted = folder / f'{target}-bad-footer{extension}'
            data = bytearray(canonical.read_bytes())
            data[-12] ^= 1
            corrupted.write_bytes(data)
            destination = folder / f'{target}-bad-restored{extension}'
            _, command, is_linux = hosts[0]
            failure = subprocess.run([*command, '--unpack-exe', str(corrupted),
                                      str(destination)], capture_output=True, text=True,
                                     timeout=30)
            if failure.returncode == 0 or destination.exists():
                raise AssertionError('corrupt footer was published')

            corrupted_code = folder / f'{target}-bad-code{extension}'
            data = bytearray(canonical.read_bytes())
            if target == 'windows-x64':
                pe = struct.unpack_from('<I', data, 60)[0]
                sections = struct.unpack_from('<H', data, pe + 6)[0]
                start = pe + 264
                packed_off = next(struct.unpack_from('<I', data, start + i * 40 + 20)[0]
                                  for i in range(sections)
                                  if data[start + i * 40:start + i * 40 + 7] == b'.packed')
            else:
                phoff = struct.unpack_from('<Q', data, 32)[0]
                phnum = struct.unpack_from('<H', data, 56)[0]
                packed_off = struct.unpack_from('<Q', data,
                                                 phoff + (phnum - 1) * 56 + 8)[0]
            data[packed_off + 100] ^= 1
            corrupted_code.write_bytes(data)
            if target == 'windows-x64':
                rc = subprocess.run([str(corrupted_code)], timeout=30).returncode
            else:
                run(['wsl', '-d', 'Ubuntu', '--', 'chmod', '+x', linux(corrupted_code)])
                rc = subprocess.run(['wsl', '-d', 'Ubuntu', '--', linux(corrupted_code)],
                                    timeout=30).returncode
            if rc != 127:
                raise AssertionError(f'corrupt code did not stop safely: {target}: {rc}')
            print(f'[OK] {target}: {len(digests)} identical packed images, '
                  'exact restoration, execution, corruption rejected')

    result = {'images': rows, 'total': len(rows)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f'NATIVE PACKING PARITY [OK]: {len(rows)} images')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
