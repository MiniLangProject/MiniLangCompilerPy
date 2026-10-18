"""Guard the scope, diagnostics and generated-code shape of local compaction."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mlc.codegen import codegen_opt as opt
from mlc import minilang_parser as ast


class CompactionTests(unittest.TestCase):
    def test_unused_proof_is_conservative_and_paths_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'main.ml'
            source.write_text('function neverCalled()\nreturn 1\nend function\n'
                              'function callback()\nreturn 2\nend function\nx = callback\n'
                              'function documented()\nreturn 3\nend function\n// documented\n', encoding='utf-8')
            cg = SimpleNamespace(call_profile=False, filename=str(source),
                                 file_prefix_map={str(source.parent) + '/./main.ml': ''},
                                 user_functions={n: SimpleNamespace(_filename=str(source))
                                                 for n in ('neverCalled', 'callback', 'documented')},
                                 struct_fields={})
            self.assertEqual(opt.unused_functions(cg), {'neverCalled'})
            cg.call_profile = True
            self.assertFalse(opt.unused_functions(cg))
            cg.call_profile = False
            cg.file_prefix_map['missing-source-file.ml'] = ''
            self.assertFalse(opt.unused_functions(cg))

    def test_whole_loop_intervals_and_unknown_syntax(self):
        body = [ast.Assign('a', ast.Num(1)),
                ast.While(ast.Bool(True), [ast.Assign('a', ast.Bin(ast.Var('a'), '+', ast.Num(1))),
                                           ast.Print(ast.Var('a')), ast.Print(ast.Var('a'))]),
                ast.Assign('b', ast.Num(2)), ast.Return(ast.Var('b'))]
        result = opt.intervals(body)
        self.assertEqual(result['a'], [0, 1, 3, 1, False])
        self.assertEqual(result['b'][:2], [2, 3])
        self.assertIsNone(opt.intervals([object()]))
        self.assertIsNone(opt.accesses([ast.Num(1)] * 4097))
        self.assertIsNotNone(opt.intervals([ast.Return(None)]))
        loop = ast.For('i', ast.Num(1), ast.Num(3), [ast.Print(ast.Var('i'))])
        self.assertTrue(opt.intervals([loop])['i'][4])

    def test_codegen_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            image, listing = Path(tmp) / 'safe.exe', Path(tmp) / 'safe.asm'
            result = subprocess.run([sys.executable, str(ROOT / 'mlc_win64.py'),
                                     str(ROOT / 'tests/optimizer_safety.ml'), str(image), '-I', str(ROOT),
                                     '--asm', '--asm-out', str(listing)], capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            text = listing.read_text(encoding='utf-8')
            def function(name):
                found = re.search(r'(?ms)^fn_user_' + re.escape(name) + r':.*?(?=^fn_user_|\Z)', text)
                self.assertIsNotNone(found, name)
                return found[0]
            self.assertNotIn('fn_user_deliberatelyUnreferencedLeaf:', text)
            self.assertNotIn('call fn_alloc', function('scalarLocal'))
            for name in ('escaped', 'returnObject', 'rebound', 'typed'):
                self.assertIn('call fn_alloc', function(name))
            registers = function('registers')
            for number in range(6, 12):
                self.assertIn(f'xmm{number}', registers)
            reused = function('reuseLifetimes')
            self.assertIn('xmm6', reused)
            self.assertIn('xmm7', reused)
            self.assertNotIn('xmm8', reused)
            self.assertIn('icall_devirt_indirect_', function('optimizer_support.defer_scope.exercise'))


if __name__ == '__main__':
    unittest.main()
