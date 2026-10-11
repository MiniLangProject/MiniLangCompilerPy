"""Structural unroll costs must not depend on the host's AST representation."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mlc import minilang_parser as ml
from mlc.codegen.codegen_stmt import CodegenStmt


class Harness(CodegenStmt):
    def __init__(self):
        self.ml = ml


class UnrollBudgetTests(unittest.TestCase):
    def setUp(self):
        self.backend = Harness()

    def accepts(self, condition, assignments=0):
        body = [ml.Assign('value', ml.Num(1)) for _ in range(assignments)]
        return self.backend._for_unroll_body_ok([ml.If(condition, body, [], [])], 'index')

    def test_literal_payload_is_not_an_expression(self):
        condition = ml.Bin(ml.Var('value'), '>', ml.Num(0))
        self.assertTrue(self.accepts(condition, 8))   # exactly twelve nodes
        self.assertFalse(self.accepts(condition, 9))

    def test_same_kind_binary_children_consume_the_budget(self):
        condition = ml.Num(1)
        for _ in range(8):
            condition = ml.Bin(condition, '+', ml.Num(1))
        self.assertFalse(self.accepts(condition))

    def test_deep_tree_stops_at_the_budget(self):
        condition = ml.Num(1)
        for _ in range(5000):
            condition = ml.Bin(condition, '+', ml.Num(1))
        self.assertFalse(self.accepts(condition))

    def test_coalescing_children_are_counted(self):
        condition = ml.Var('fallback')
        for _ in range(6):
            condition = ml.Coalesce(ml.Var('value'), condition)
        self.assertFalse(self.accepts(condition))

    def test_call_target_is_counted(self):
        condition = ml.Call(ml.Member(ml.Var('receiver'), 'test'), [])
        self.assertTrue(self.accepts(condition, 8))
        self.assertFalse(self.accepts(condition, 9))


if __name__ == '__main__':
    unittest.main()
