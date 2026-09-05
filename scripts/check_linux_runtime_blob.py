#!/usr/bin/env python3
"""Check the ML syscall blob against the current Python assembler.

By default this is a read-only parity gate. ``--patch`` prints an apply_patch
patch refreshing the blob, labels and relocation constants; it never edits a
source file itself. The unused legacy thread range is preserved deliberately.
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path
from types import SimpleNamespace


def main() -> int:
    """Emit canonical thunks and check all embedded bytes/offsets together."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--patch', action='store_true')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    py_root = repo if (repo / 'mlc/asm.py').exists() else repo.parent / 'MiniLangCompilerPy'
    ml_root = repo if (repo / 'mlc/asm.ml').exists() else repo.parent / 'MiniLangCompilerML'
    sys.path.insert(0, str(py_root))
    from mlc.asm import Asm
    from mlc.data import DataBuilder, RDataBuilder
    from mlc.linux_runtime import emit_linux_runtime

    cg = SimpleNamespace(asm=Asm(), data=DataBuilder(), rdata=RDataBuilder(), extern_sigs={})
    emit_linux_runtime(cg)
    code = cg.asm.buf[:]
    external = []
    for pos, target, kind in cg.asm.patches:
        if target in cg.asm.labels:
            struct.pack_into('<i', code, pos, cg.asm.labels[target] - pos - 4)
        else:
            external.append((pos, target))
    assert [name for _, name in external] == ['elfiat_runtime_pthread_create', 'elfiat_runtime_pthread_join', 'elfiat_runtime_pthread_join']
    path = ml_root / 'mlc/linux_runtime.ml'
    source = path.read_text(encoding='utf-8')
    constants = dict((name, int(value)) for name, value in re.findall(r'const (RUNTIME_\w+) = (\d+)', source))
    pattern = r'(function _runtime_blob_raw\(\).*?return fromHex\(")([0-9a-f]+)("\))'
    old_raw = bytes.fromhex(re.search(pattern, source, re.S)[2])
    legacy = old_raw[constants['RUNTIME_LEGACY_THREAD_START']:constants['RUNTIME_LEGACY_THREAD_END']]
    start = cg.asm.labels['linux_CreateThread']
    end = cg.asm.labels['linux_fmod']
    prefix = code[:start]
    # The legacy container stores exit(60); emit_runtime deliberately patches
    # it to exit_group(231) so all threads terminate together.
    exit_offset = cg.asm.labels['linux_ExitProcess'] + 3
    assert code[exit_offset - 1] == 0xb8
    struct.pack_into('<I', prefix, exit_offset, 60)
    raw = prefix + legacy + code[end:]
    expected = re.sub(pattern, lambda m: m[1] + raw.hex() + m[3], source, flags=re.S)
    expected = re.sub(r'(function _pthread_runtime_blob\(\)\s+return fromHex\(")[0-9a-f]+("\))',
                      lambda m: m[1] + code[start:end].hex() + m[2], expected)
    offsets = {'RUNTIME_EXIT_SYSCALL_OFFSET': exit_offset, 'RUNTIME_LEGACY_THREAD_START': start,
               'RUNTIME_LEGACY_THREAD_END': start + len(legacy),
               **dict(zip(('RUNTIME_PTHREAD_CREATE_PATCH', 'RUNTIME_PTHREAD_WAIT_PATCH', 'RUNTIME_PTHREAD_CLOSE_PATCH'), (p for p, _ in external)))}
    for name, value in offsets.items():
        expected = re.sub(rf'(const {name} = )\d+', lambda m: m[1] + str(value), expected)
    expected = re.sub(r'(RuntimeLabel\("([^"]+)", )\d+(\))',
                      lambda m: m[1] + str(cg.asm.labels[m[2]]) + m[3], expected)
    declared = re.findall(r'RuntimeLabel\("([^"]+)"', expected)
    assert set(declared) == set(cg.asm.labels), 'Runtime label inventory differs'
    if expected == source:
        print(f'OK: canonical Linux runtime blob ({len(code)} bytes; {len(declared)} labels; 3 external relocations)')
        return 0
    if not args.patch:
        print('FAIL: ML Linux runtime blob differs from the current Python assembler; run this script with --patch')
        return 1
    print('*** Begin Patch')
    print('*** Update File: ' + path.as_posix())
    # Line count is stable: only numeric offsets and hexadecimal literals change.
    old_lines, new_lines = source.splitlines(), expected.splitlines()
    assert len(old_lines) == len(new_lines)
    for before, after in zip(old_lines, new_lines):
        if before != after:
            print('@@\n-' + before + '\n+' + after)
    print('*** End Patch')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
