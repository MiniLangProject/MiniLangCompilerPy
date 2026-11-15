"""Compile MinUX fixtures through Python, native direct and native MLO paths.

Require byte parity, record SHA-256 evidence, and optionally boot an isolated
MinUX image for real ABI/GC/file/thread/exit-status acceptance.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def checked(command, log):
    result = subprocess.run([str(part) for part in command], cwd=ROOT,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    log.write_text(result.stdout, encoding='utf-8')
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}); see {log}\n{result.stdout[-4000:]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'build/minux-verification')
    parser.add_argument('--guest', action='store_true')
    parser.add_argument('--minux-root', type=Path)
    parser.add_argument('--pack',action='store_true',help='check packed output through all compiler paths')
    parser.add_argument('--extensions',action='store_true',help='include library/GUI fixtures in the compile matrix; use their dedicated guest runners')
    args = parser.parse_args()
    if args.extensions and args.guest:parser.error('--extensions is a compile matrix; use check_minux_extensions.py/check_minux_network.py for guest execution')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    native = args.native.resolve()
    cases = {
        'minux_runtime_smoke': [], 'minux_services': [], 'minux_ffi': [],
        'minux_heap': ['--heap-reserve', '4g', '--heap-commit', '32m',
                       '--heap-grow', '16m', '--heap-shrink', '--heap-shrink-min', '1m'],
    }
    if args.extensions:
        cases.update({name:[] for name in ('minux_stdlib','minux_files','minux_media','minux_network','minux_gui','crypto_cng','ecdsa_p256')})
    matrix, images = [], []
    for case, flags in cases.items():
        variants = []
        for mode in ('python', 'native-direct', 'native-mlo'):
            image = output/f'{case}-{mode}'
            command = ([sys.executable, ROOT/'mlc_win64.py'] if mode == 'python' else [native])
            command += [ROOT/'tests'/f'{case}.ml', image, '--target', 'minux-x64', '-I', ROOT, *flags]
            if case=='minux_gui':command+=['-I',ROOT.parent/'MiniGui']
            if args.pack:command.append('--pack')
            if mode != 'python':
                command.append('--object-pipeline' if mode == 'native-mlo' else '--no-object-pipeline')
            checked(command, output/f'{case}-{mode}.compile.log')
            content = image.read_bytes()
            variants.append(content)
            matrix.append({'fixture':case, 'mode':mode, 'bytes':len(content),
                           'sha256':hashlib.sha256(content).hexdigest()})
        if not variants[0] == variants[1] == variants[2]:
            raise RuntimeError(f'compiler/pipeline parity failed: {case}')
        images.append(output/f'{case}-native-mlo')
        print(f'[OK] {case}: Python/native/MLO byte parity', flush=True)
    # The error paths must also work through the newly built native compiler.
    for library, symbol, diagnostic in (
            ('libc.so.6', 'strlen', 'Linux ABI library'),
            ('/lib/libc.so.1', 'strlen', 'exact library basename'),
            ('__minilang_minux_runtime', 'unknown', 'unknown private')):
        source = output/'invalid.ml'
        source.write_text(f'extern function native() from "{library}" symbol "{symbol}" returns int\nprint native()\n')
        result = subprocess.run([str(native), str(source), str(output/'invalid'),
            '--target', 'minux-x64', '--no-object-pipeline', '-I', str(ROOT)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        if result.returncode == 0 or diagnostic not in result.stdout:
            raise RuntimeError(f'native target diagnostic failed: {result.stdout}')
    (output/'matrix.json').write_text(json.dumps(matrix, indent=2)+'\n')
    if args.guest:
        if args.minux_root is None:
            parser.error('--guest requires --minux-root')
        work = output/'guest'
        if os.name == 'nt':
            def linux(path):
                return subprocess.check_output(['wsl.exe', '-e', 'wslpath', '-a', str(path)], text=True).strip()
            command = ['wsl.exe', '-e', 'python3', linux(ROOT/'tests/run_minux_guest.py'),
                '--minux-root', linux(args.minux_root.resolve()), '--work', linux(work),
                *map(linux, images)]
        else:
            command = [sys.executable, ROOT/'tests/run_minux_guest.py', '--minux-root',
                args.minux_root.resolve(), '--work', work, *images]
        checked(command, output/'guest.log')
        print('[OK] MinUX guest: real ABI, GC, files, synchronization, threads, heap and exit status', flush=True)
    print(f'MinUX verification passed; evidence: {output}', flush=True)


if __name__ == '__main__':
    main()
