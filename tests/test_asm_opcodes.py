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
    """Verify exact x64 encodings and the assembler's local peephole rules."""

    def setUp(self) -> None:
        """Make tests independently runnable instead of depending on test order."""
        import sys
        sys.path.insert(0, str(_project_root()))

    def test_compact_immediate_boundaries(self) -> None:
        """Independent opcode expectations cover accumulator, mask and REX edges."""
        vectors = [
            ('and_r64_imm', ['rax', 7], '83e007'),
            ('and_r64_imm', ['r8', 7], '4183e007'),
            ('and_r64_imm', ['rax', 128], '2580000000'),
            ('and_r64_imm', ['rax', 0x7fffffff], '25ffffff7f'),
            ('and_r64_imm', ['rax', -1], '4883e0ff'),
            ('and_r64_imm', ['rax', 0x80000000], '482500000080'),
            ('and_r64_imm', ['r8', -2147483648], '4981e000000080'),
            ('add_r64_imm', ['rax', 127], '4883c07f'),
            ('add_r64_imm', ['rax', 128], '480580000000'),
            ('sub_r32_imm', ['eax', 128], '2d80000000'),
            ('cmp_r64_imm', ['rax', -129], '483d7fffffff'),
            ('xor_r8_imm8', ['al', 255], '34ff'),
            ('or_r8_imm8', ['r8b', 7], '4180c807'),
            ('test_r64_imm32', ['rax', -1], '48a9ffffffff'),
            ('test_rax_imm32', [8], '48a908000000'),
            ('and_rax_imm8', [7], '83e007'),
            ('cmp_rax_imm32', [128], '483d80000000'),
            ('test_r64_imm32', ['r8', 7], '49f7c007000000'),
        ]
        for method, args, expected in vectors:
            with self.subTest(method=method, args=args):
                self.assertEqual(_emit_bytes(method, args, {}).hex(), expected)

    def test_implicit_one_shifts(self) -> None:
        """Do not reinterpret masked-zero or multi-bit counts as implicit one."""
        for width in (32, 64):
            for reg, rex in [('eax' if width == 32 else 'rax', '' if width == 32 else '48'),
                             ('r9d' if width == 32 else 'r9', '41' if width == 32 else '49')]:
                for operation, modrm in [('shl', 0xe0), ('shr', 0xe8), ('sar', 0xf8)]:
                    for count in (0, 1, 2, 31, 32, 33, 63, 64, 65, 255, 257):
                        byte = count & 255
                        tail = ('d1' if byte == 1 else 'c1') + f'{modrm + (reg.startswith("r9")):02x}'
                        if byte != 1:
                            tail += f'{byte:02x}'
                        with self.subTest(width=width, reg=reg, operation=operation, count=count):
                            self.assertEqual(_emit_bytes(f'{operation}_r{width}_imm8', [reg, count], {}).hex(), rex + tail)

    def test_fallthrough_branch_pairs(self) -> None:
        """All sixteen conditions invert and retain correct rel32 targets."""
        from mlc.asm import Asm

        conditions = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
                      's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')
        for opcode, condition in enumerate(conditions):
            with self.subTest(condition=condition):
                a = Asm()
                a.enable_listing('unused.asm')
                a.jcc(condition, 'yes')
                a.jmp('no')
                a.mark('yes')
                a.nop()
                a.mark('no')
                self.assertEqual(a.finalize(), bytes([15, 0x80 + (opcode ^ 1), 1, 0, 0, 0, 0x90]))
                self.assertEqual(a.labels, {'yes': 6, 'no': 7})
                self.assertEqual(a.patches, [(2, 'no', 'rel32')])
                self.assertEqual(a._trace[0].refs, ('no',))
                self.assertEqual(a._trace[0].text, a._format_call('jcc', (conditions[opcode ^ 1], 'no'), {})[0])

    def test_branch_pair_barriers_and_relocations(self) -> None:
        """Labels/instructions are barriers; earlier calls and RIP references survive."""
        from mlc.asm import Asm

        for barrier in ('label', 'nop'):
            a = Asm()
            a.jcc('e', 'yes')
            if barrier == 'label':
                a.mark('other_entry')
            else:
                a.nop()
            a.jmp('no')
            a.mark('yes')
            a.nop()
            a.mark('no')
            self.assertEqual(a.finalize()[:2], b'\x0f\x84')
            self.assertEqual(len(a.patches), 2)
        a = Asm()
        a.call('no')
        a.lea_rax_rip('yes')
        a.jcc('e', 'yes')
        a.jmp('no')
        a.mark('yes')
        a.nop()
        a.mark('no')
        code = a.finalize()
        for pos, label, _ in a.patches:
            self.assertEqual(int.from_bytes(code[pos:pos + 4], 'little', signed=True) + pos + 4, a.labels[label])

    @unittest.skipUnless(os.name == 'nt' and __import__('platform').machine().lower() in ('amd64', 'x86_64'),
                         'native Windows x64 flag equivalence test')
    def test_compact_native_results_and_flags(self) -> None:
        """Execute old/new instructions and compare full results plus defined flags."""
        import ctypes
        import struct
        from mlc.asm import Asm

        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
        kernel.VirtualAlloc.restype = ctypes.c_void_p
        kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        kernel.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
        kernel.FlushInstructionCache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

        def execute(instruction, reg, value):
            # Preserve RBX, use it for the output pointer, and capture FLAGS
            # before any later instruction can modify them. No executable
            # file or shared process state is modified by this test.
            a = Asm()
            a.push_reg('rbx')
            a.mov_r64_r64('rbx', 'rdx')
            a.mov_r64_r64(reg, 'rcx')
            a.emit(b'\xf8')  # CLC: deterministic carry input for zero shifts.
            a.emit(instruction)
            a.emit(b'\x9c\x41\x5b')  # PUSHFQ; POP R11.
            a.mov_membase_disp_r64('rbx', 0, 'r11')
            a.mov_r64_r64('rax', reg)
            a.pop_reg('rbx')
            a.ret()
            code = a.finalize()
            address = kernel.VirtualAlloc(None, len(code), 0x3000, 0x04)
            self.assertTrue(address, ctypes.get_last_error())
            try:
                ctypes.memmove(address, code, len(code))
                old_protect = ctypes.c_uint32()
                self.assertTrue(kernel.VirtualProtect(address, len(code), 0x20, ctypes.byref(old_protect)))
                self.assertTrue(kernel.FlushInstructionCache(ctypes.c_void_p(-1), address, len(code)))
                fn = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64))(address)
                flags = ctypes.c_uint64()
                result = fn(value, ctypes.byref(flags))
                return result, flags.value
            finally:
                self.assertTrue(kernel.VirtualFree(address, 0, 0x8000))

        inputs = (0, 1, 127, 0x80000000, 0xffffffff, 0x8000000000000000, 0xffffffffffffffff, 0x123456789abcdef0)
        for reg, rid in [('rax', 0), ('rcx', 1), ('rdx', 2), ('r8', 8), ('r10', 10)]:
            for mask in (0, 1, 7, 127, 128, 0x7fffffff, 0x80000000, -1, -2147483648):
                prefix = bytes([0x48 | (rid >> 3)])
                old = prefix + (bytes([0x83, 0xe0 | (rid & 7), mask & 255]) if -128 <= mask <= 127
                                else bytes([0x81, 0xe0 | (rid & 7)]) + struct.pack('<I', mask & 0xffffffff))
                new = _emit_bytes('and_r64_imm', [reg, mask], {})
                for value in inputs:
                    with self.subTest(reg=reg, mask=mask, value=value):
                        before, bf = execute(old, reg, value)
                        after, af = execute(new, reg, value)
                        self.assertEqual(after, before)
                        self.assertEqual(af & 0x8c5, bf & 0x8c5)  # CF/PF/ZF/SF/OF; AF is undefined.
            for width in (32, 64):
                for operation, subop in [('shl', 4), ('shr', 5), ('sar', 7)]:
                    prefix = bytes([(0x48 if width == 64 else 0x40) | (rid >> 3)]) if width == 64 or rid >= 8 else b''
                    old = prefix + bytes([0xc1, 0xc0 | (subop << 3) | (rid & 7), 1])
                    new = _emit_bytes(f'{operation}_r{width}_imm8', [reg, 1], {})
                    for value in inputs:
                        before, bf = execute(old, reg, value)
                        after, af = execute(new, reg, value)
                        self.assertEqual(after, before)
                        self.assertEqual(af & 0x8c5, bf & 0x8c5)

    def test_push_pop_peephole_requires_true_adjacency(self) -> None:
        """An intervening instruction may legitimately end in a PUSH opcode byte."""
        import sys

        sys.path.insert(0, str(_project_root()))
        from mlc.asm import Asm

        a = Asm()
        a.push_reg("rax")
        a.mov_r32_imm32("eax", 0x50000000)
        a.pop_reg("rax")
        self.assertEqual(a.finalize(), bytes.fromhex("50b80000005058"))

    def test_short_backward_branches(self) -> None:
        """Resolved loop back-edges use rel8; unresolved forward edges stay rel32."""
        import sys

        sys.path.insert(0, str(_project_root()))
        from mlc.asm import Asm

        a = Asm()
        a.mark("loop")
        a.nop()
        a.jmp("loop")
        self.assertEqual(a.finalize(), bytes.fromhex("90ebfd"))

        a = Asm()
        a.mark("loop")
        a.nop()
        a.jcc("ne", "loop")
        self.assertEqual(a.finalize(), bytes.fromhex("9075fd"))

        a = Asm()
        a.jmp("later")
        a.nop()
        a.mark("later")
        self.assertEqual(a.finalize(), bytes.fromhex("e90100000090"))

        a = Asm()
        a.jcc("e", "later")
        a.nop()
        a.mark("later")
        self.assertEqual(a.finalize(), bytes.fromhex("0f840100000090"))

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
