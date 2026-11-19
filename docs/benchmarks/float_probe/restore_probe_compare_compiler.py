#!/usr/bin/env python3
"""Write a compiler wrapper that restores the Phase-8 raw probe comparison.

The generated wrapper accepts ordinary mlc_win64.py arguments. Its source root
is fixed explicitly so it can be passed as --disabled-compiler to the comparison
helper without relying on the current checkout or environment variables.
"""
from __future__ import annotations

import argparse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.compiler_root.resolve()
    output = args.output.resolve()
    if not (root / 'mlc_win64.py').is_file() or not (root / 'mlc/codegen/codegen_expr.py').is_file():
        parser.error('--compiler-root must contain the measured Python compiler')
    if output.suffix != '.py':
        parser.error('--output must end in .py so compiler_command selects Python')
    if output.exists():
        parser.error('--output already exists; choose a fresh reproduction path')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(f'''#!/usr/bin/env python3
"""Exact inverse ablation: append the former raw f32-probe comparison."""
import sys
sys.path.insert(0, {str(root)!r})
from mlc.codegen import Codegen
from mlc.compiler import main

candidate = Codegen._opt_emit_float_tree_normalize

def original(self, slow):
    candidate(self, slow)
    self.asm.ucomisd_xmm_xmm('xmm0', 'xmm3')

Codegen._opt_emit_float_tree_normalize = original
raise SystemExit(main(sys.argv))
''')
    print(output)


if __name__ == '__main__':
    main()
