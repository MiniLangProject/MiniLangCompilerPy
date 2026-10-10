"""SATB leaf barriers must not invoke RSP-relative expression-root spills."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mlc.asm import Asm
from mlc.codegen.codegen_memory import CodegenMemory


class BarrierHarness(CodegenMemory):
    def __init__(self, enabled=True):
        self.asm = Asm()
        self.heap_config = {'gc_concurrent': enabled}
        self.used_helpers = set()

    def new_label_id(self):
        return 1


class ConcurrentGCCodegenTests(unittest.TestCase):
    def test_leaf_barriers_preserve_spill_hook(self):
        for method, arguments in (
            ('emit_gc_write_barrier', ('r11', 8)),
            ('emit_gc_write_barrier_index', ('r11', 'r10', 8)),
            ('emit_gc_write_barrier_range', ()),
        ):
            with self.subTest(method=method):
                backend = BarrierHarness()
                spills, calls = [], []
                callback = lambda: spills.append('spill')
                backend.asm._before_call = callback
                backend.asm._on_call_label = calls.append
                getattr(backend, method)(*arguments)
                self.assertEqual(spills, [])
                self.assertEqual(calls, ['fn_gc_satb_record'])
                self.assertIs(backend.asm._before_call, callback)
                backend.asm.call('ordinary_call')
                self.assertEqual(spills, ['spill'])

    def test_disabled_barriers_emit_nothing(self):
        backend = BarrierHarness(enabled=False)
        backend.emit_gc_write_barrier('r11', 8)
        backend.emit_gc_write_barrier_index('r11', 'r10', 8)
        backend.emit_gc_write_barrier_range()
        self.assertEqual(backend.asm.finalize(), b'')
        self.assertEqual(backend.used_helpers, set())

    def test_spill_hook_restored_after_failed_emission(self):
        backend = BarrierHarness()
        callback = lambda: None
        backend.asm._before_call = callback
        def fail(_label):
            raise RuntimeError('emitter failure')
        backend.asm.call = fail
        with self.assertRaises(RuntimeError):
            backend._emit_gc_satb_leaf_call()
        self.assertIs(backend.asm._before_call, callback)


if __name__ == '__main__':
    unittest.main(verbosity=2)
