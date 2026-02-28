#!/usr/bin/env python3
"""Regression test for the x86-64 opcode emitter (mlc/asm.py).

Idea:
  - For every public Asm instruction helper, we keep a *golden* vector:
      method name + representative args/kwargs + expected emitted bytes.
  - The test replays all vectors and fails with a clear diff if any encoding
    changes.

This is primarily a *regression* safety net. If you intentionally change any
encodings, regenerate the golden file:

  python tests/gen_asm_opcodes_golden.py

Optional correctness cross-check:
  If NASM is on PATH and MINILANG_ASM_VERIFY_NASM=1 is set, we additionally
  assemble vectors that have a usable `asm` string and compare bytes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_golden() -> dict:
    p = Path(__file__).resolve().parent / "asm_opcodes_golden.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _current_asm_methods() -> list[str]:
    # Import lazily so we can insert project_root into sys.path.
    import sys

    sys.path.insert(0, str(_project_root()))
    from mlc.asm import Asm

    ignore = {
        "emit",
        "emit8",
        "emit32",
        "emit64",
        "pos",
        "labels",
        "patches",
        "buf",
        "mark",
        "finalize",
        "enable_listing",
        "disable_listing",
        "write_listing",
        "__getattribute__",
    }

    out = []
    for name, obj in Asm.__dict__.items():
        if not callable(obj) or name.startswith("_") or name in ignore:
            continue
        out.append(name)
    return sorted(out)


def _emit_bytes(method: str, args: list, kwargs: dict) -> bytes:
    import sys
    import inspect

    sys.path.insert(0, str(_project_root()))
    from mlc.asm import Asm

    a = Asm()
    a._peephole_enabled = False

    sig = inspect.signature(getattr(Asm, method))
    if "label" in sig.parameters:
        # Vectors use label "L"; define it at position 0 so rel32/rip32 patching
        # is deterministic.
        a.mark("L")

    getattr(a, method)(*args, **kwargs)
    return a.finalize()


def _to_nasm_line(s: str) -> str:
    # Convert the trace-friendly pseudo-asm into NASM-friendly syntax.
    # The main incompatibility is the RIP spelling.
    s = s.replace("[rip+", "[rel ")
    s = s.replace("]", "]")
    return s


def _assemble_with_nasm(lines: list[str]) -> bytes:
    nasm = shutil.which("nasm")
    if not nasm:
        raise FileNotFoundError("nasm not found on PATH")

    src = "BITS 64\nDEFAULT REL\nL:\n" + "\n".join(lines) + "\n"
    with tempfile.TemporaryDirectory(prefix="ml_asm_nasm_") as td:
        td_p = Path(td)
        asm_p = td_p / "t.asm"
        bin_p = td_p / "t.bin"
        asm_p.write_text(src, encoding="utf-8")
        p = subprocess.run([nasm, "-f", "bin", "-o", str(bin_p), str(asm_p)], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        if p.returncode != 0:
            raise RuntimeError(p.stderr.strip() or "nasm failed")
        return bin_p.read_bytes()


class TestAsmOpcodeVectors(unittest.TestCase):
    def test_vectors_match_golden(self) -> None:
        golden = _load_golden()
        vectors = golden.get("vectors", [])
        self.assertIsInstance(vectors, list)

        by_name = {v["name"]: v for v in vectors}
        current = _current_asm_methods()

        missing = [m for m in current if m not in by_name]
        extra = [m for m in by_name.keys() if m not in current]

        if missing or extra:
            msg = []
            if missing:
                msg.append("Missing vectors for: " + ", ".join(missing))
            if extra:
                msg.append("Golden has extra vectors for: " + ", ".join(extra))
            msg.append("Regenerate with: python tests/gen_asm_opcodes_golden.py")
            self.fail("\n".join(msg))

        # Replay
        for name in current:
            v = by_name[name]
            exp_hex = v["hex"]
            got = _emit_bytes(name, v.get("args", []), v.get("kwargs", {}))
            got_hex = got.hex()
            if got_hex != exp_hex:
                self.fail(
                    "\n".join(
                        [
                            f"Opcode vector mismatch: {name}",
                            f"  args  : {v.get('args', [])}",
                            f"  kwargs: {v.get('kwargs', {})}",
                            f"  asm   : {v.get('asm', '')}",
                            f"  expected: {exp_hex}",
                            f"  got     : {got_hex}",
                            "Regenerate with: python tests/gen_asm_opcodes_golden.py",
                        ]
                    )
                )

    def test_optional_nasm_verification(self) -> None:
        # Off by default (to avoid requiring extra tooling on all setups)
        if os.environ.get("MINILANG_ASM_VERIFY_NASM") not in ("1", "true", "TRUE", "yes", "YES"):
            self.skipTest("MINILANG_ASM_VERIFY_NASM not enabled")

        if not shutil.which("nasm"):
            self.fail("MINILANG_ASM_VERIFY_NASM=1 but nasm was not found on PATH")

        golden = _load_golden()
        vectors = golden.get("vectors", [])

        checked = 0
        for v in vectors:
            asm_line = (v.get("asm") or "").strip()
            if not asm_line or asm_line.startswith(";"):
                continue

            try:
                ref = _assemble_with_nasm([_to_nasm_line(asm_line)])
            except Exception:
                # Not all pseudo-asm strings are NASM-compatible.
                continue

            got = _emit_bytes(v["name"], v.get("args", []), v.get("kwargs", {}))
            self.assertEqual(ref, got, f"NASM mismatch for {v['name']}: {asm_line}")
            checked += 1

        if checked == 0:
            self.fail("MINILANG_ASM_VERIFY_NASM=1 but no vectors could be assembled via NASM")


if __name__ == "__main__":
    unittest.main(verbosity=2)
