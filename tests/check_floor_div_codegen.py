"""Check floor-division instruction selection across the tagged integer domain."""
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mlc.codegen.codegen_expr import CodegenExpr
from mlc.constants import TAG_INT
from mlc.asm import Asm
from mlc import minilang_parser as ast
from types import SimpleNamespace

class ReciprocalProbe:
    """Interpret the emitted reciprocal path, including its correction branch."""
    MASK = (1 << 64) - 1

    def __init__(self, value):
        self.reg = {'r10': ((value << 3) | TAG_INT) & self.MASK}
        self.ops = []

    def __getattr__(self, op):
        return lambda *args: self.ops.append((op, args))

    def run(self):
        r = self.reg
        labels = {args[0]: i for i, (op, args) in enumerate(self.ops) if op == 'mark'}
        pc = 0
        cmp = 0
        while pc < len(self.ops):
            op, args = self.ops[pc]
            pc += 1
            if op == 'mov_rax_r10': r['rax'] = r['r10']
            elif op == 'mov_r64_r64': r[args[0]] = r[args[1]]
            elif op == 'mov_r64_imm64': r[args[0]] = args[1]
            elif op in ('sar_rax_imm8', 'sar_r64_imm8'):
                dst, count = ('rax', args[0]) if op == 'sar_rax_imm8' else args
                v = r[dst]
                r[dst] = ((v - (1 << 64) if v >= (1 << 63) else v) >> count) & self.MASK
            elif op in ('shl_rax_imm8', 'shl_r64_imm8', 'shr_r64_imm8'):
                dst, count = ('rax', args[0]) if op == 'shl_rax_imm8' else args
                r[dst] = ((r[dst] >> count) if op == 'shr_r64_imm8' else (r[dst] << count)) & self.MASK
            elif op == 'xor_r64_r64': r[args[0]] ^= r[args[1]]
            elif op == 'or_r64_r64': r[args[0]] |= r[args[1]]
            elif op == 'or_rax_imm8': r['rax'] |= args[0]
            elif op == 'mul_r64':
                product = r['rax'] * r[args[0]]
                r['rax'], r['rdx'] = product & self.MASK, product >> 64
            elif op == 'imul_r64_r64': r[args[0]] = (r[args[0]] * r[args[1]]) & self.MASK
            elif op == 'cmp_r64_r64': cmp = r[args[0]] - r[args[1]]
            elif op == 'jcc':
                assert args[0] == 'be'
                if cmp <= 0: pc = labels[args[1]]
            elif op == 'dec_r64': r[args[0]] = (r[args[0]] - 1) & self.MASK
            elif op != 'mark': raise AssertionError(op)
        return r['rax']


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
    # Assert the new MUL encoding for low and extended registers, independently
    # of the arithmetic interpreter (which does not check instruction bytes).
    assembler = Asm()
    assembler.mul_r64('rcx')
    assembler.mul_r64('r11')
    assert assembler.finalize() == bytes.fromhex('48f7e149f7e3')

    rng = random.Random(20260930)
    values = [-(1 << 60), -(1 << 60) + 1, -1025, -1, 0, 1, 1025, (1 << 60) - 1]
    values += [rng.randrange(-(1 << 60), 1 << 60) for _ in range(128)]
    compiler = CodegenExpr()
    compiler.new_label_id = lambda: 1
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
    divisors = [3, 5, 7, 10, 31, (1 << 30) - 1, (1 << 59) - 1, (1 << 60) - 1]
    divisors += [rng.randrange(3, 1 << 60) for _ in range(256)]
    for divisor in divisors:
        boundary = [divisor - 1, divisor, divisor + 1, -divisor, -divisor - 1]
        for value in values + [v for v in boundary if -(1 << 60) <= v < (1 << 60)]:
            probe = ReciprocalProbe(value)
            compiler.asm = probe
            assert compiler._opt_emit_known_int_binop('div', None, divisor)
            expected = (((value // divisor) << 3) | TAG_INT) & probe.MASK
            assert probe.run() == expected, (value, divisor)
    for divisor in (None, 0, -1, -8, (1 << 60), (1 << 61), (1 << 64)):
        compiler.asm = ShiftProbe(9)
        assert not compiler._opt_emit_known_int_binop("div", None, divisor)
        assert compiler.asm.count == 0
    compiler.ml = ast
    compiler._known_int_names = {'x'}
    compiler._known_value_types = {}
    compiler._qualify_identifier = lambda name, node: name
    binding = SimpleNamespace(kind='local', boxed=False, is_const=False)
    compiler.resolve_binding = lambda name: binding
    expr = ast.Bin(ast.Var('x'), '+', ast.Num(3))
    assert compiler._opt_same_local_int_expr(expr, expr)
    assert not compiler._opt_same_local_int_expr(expr, ast.Bin(ast.Var('x'), '+', ast.Num(4)))
    for kind, boxed in (('global', False), ('local', True), ('param', True)):
        binding.kind, binding.boxed = kind, boxed
        assert not compiler._opt_same_local_int_expr(expr, expr)
    binding.kind, binding.boxed = 'local', False
    for op in ('div', '/', '%', '<<', 'and'):
        unsafe = ast.Bin(ast.Var('x'), op, ast.Num(0))
        assert not compiler._opt_same_local_int_expr(unsafe, unsafe)
    assert not compiler._opt_same_local_int_expr(ast.Num(1.0), ast.Num(1.0))
    for _ in range(5): expr = ast.Bin(expr, '+', ast.Num(1))
    assert not compiler._opt_same_local_int_expr(expr, expr)
    print("[OK] floor division instruction selection")

if __name__ == "__main__":
    main()
