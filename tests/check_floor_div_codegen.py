"""Check floor-division instruction selection across the tagged integer domain."""
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mlc.codegen.codegen_expr import CodegenExpr
from mlc.constants import TAG_INT

class ShiftProbe:
    """Model exactly the small x64 instruction vocabulary used by this fast path."""
    def __init__(self, value):
        self.input = ((value << 3) | TAG_INT) & ((1 << 64) - 1)
        self.value = 0
        self.count = 0

    def mov_rax_r10(self):
        self.value = self.input
        self.count += 1

    def sar_rax_imm8(self, count):
        assert 0 < count < 64
        signed = self.value - (1 << 64) if self.value >= (1 << 63) else self.value
        self.value = (signed >> count) & ((1 << 64) - 1)
        self.count += 1

    def shl_rax_imm8(self, count):
        self.value = (self.value << count) & ((1 << 64) - 1)
        self.count += 1

    def or_rax_imm8(self, tag):
        assert tag == TAG_INT
        self.value |= tag
        self.count += 1

def main():
    rng = random.Random(20260930)
    values = [-(1 << 60), -(1 << 60) + 1, -1025, -1, 0, 1, 1025, (1 << 60) - 1]
    values += [rng.randrange(-(1 << 60), 1 << 60) for _ in range(128)]
    compiler = CodegenExpr()
    for shift in range(60):
        divisor = 1 << shift
        for value in values:
            compiler.asm = ShiftProbe(value)
            assert compiler._opt_emit_known_int_binop("div", None, divisor)
            expected = (((value // divisor) << 3) | TAG_INT) & ((1 << 64) - 1)
            assert compiler.asm.value == expected, (value, divisor)
            assert compiler.asm.count == (1 if shift == 0 else 4)
    # Values outside the positive signed-61-bit domain cannot use this path:
    # the actual runtime divisor may wrap to negative or zero.
    for divisor in (None, 0, -1, -8, 3, (1 << 60), (1 << 61), (1 << 64)):
        compiler.asm = ShiftProbe(9)
        assert not compiler._opt_emit_known_int_binop("div", None, divisor)
        assert compiler.asm.count == 0
    print("[OK] floor division instruction selection")

if __name__ == "__main__":
    main()
