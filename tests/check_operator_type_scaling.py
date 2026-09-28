"""Bound real type-inference visits independently of machine speed."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mlc import minilang_parser as ml
from mlc.codegen.codegen_expr import CodegenExpr


class Probe(CodegenExpr):
    """Count visits and abort early if repeated subtree inference returns."""

    def __init__(self, enabled: bool, budget: int):
        self.ml = ml
        self.operator_overloads_present = enabled
        self.visits = 0
        self.budget = budget

    def _opt_expr_known_type(self, expr):
        self.visits += 1
        if self.visits > self.budget:
            raise AssertionError("type inference exceeded its linear visit budget")
        return super()._opt_expr_known_type(expr)


def main():
    """Exercise unary and binary spines with and without overload checking."""
    for depth in (16, 32, 64):
        mixed = ml.Num(0)
        numeric = ml.Num(0)
        unary = ml.Num(1)
        for index in range(depth):
            mixed = ml.Bin(mixed, '+', ml.Str(':') if index % 2 == 0 else ml.Num(index))
            numeric = ml.Bin(numeric, '+', ml.Num(index))
            unary = ml.Unary('-', unary)
        for enabled in (False, True):
            for expr, expected, nodes in ((mixed, None, 2 * depth + 1),
                                          (numeric, 'int', 2 * depth + 1),
                                          (unary, 'int', depth + 1)):
                probe = Probe(enabled, 2 * nodes)
                assert probe._opt_expr_known_type(expr) == expected
                assert probe.visits <= 2 * nodes
    print('[OK] operator type inference scales linearly')


if __name__ == '__main__':
    main()
