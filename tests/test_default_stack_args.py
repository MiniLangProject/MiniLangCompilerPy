"""Default expansion must reserve outgoing ABI slots before laying out locals."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DefaultStackArgumentTests(unittest.TestCase):
    def compile(self, source, directory, target, pipeline):
        image = directory / ('case.exe' if target == 'windows-x64' else 'case')
        listing = directory / 'case.asm'
        result = subprocess.run(
            [sys.executable, str(ROOT / 'mlc_win64.py'), str(source), str(image),
             '-I', str(ROOT), '-I', str(directory), '--target', target, pipeline,
             '--asm', '--asm-out', str(listing)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        native = ((target == 'linux-x64' and sys.platform.startswith('linux'))
                  or (target == 'windows-x64' and sys.platform == 'win32'))
        if native:
            run = subprocess.run([str(image)], capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('[OK]', run.stdout)
        return image.read_bytes(), listing.read_text(encoding='utf-8')

    def assert_outgoing_area(self, listing, function, physical_arguments):
        block = re.search(r'(?ms)^fn_user_' + re.escape(function) + r':.*?(?=^fn_user_|\Z)', listing)
        self.assertIsNotNone(block, function)
        # Saved diagnostic state precedes locals and must survive every call.
        # It therefore cannot start inside any outgoing stack-argument slot.
        saved_script = re.search(
            r'mov rax, qword \[rip\+dbg_loc_script\][^\n]*\n'
            r'[^\n]*mov qword \[rsp\+0x([0-9A-F]+)\], rax', block[0])
        self.assertIsNotNone(saved_script, function)
        outgoing_end = 0x20 + max(1, physical_arguments - 4) * 8
        self.assertGreaterEqual(int(saved_script[1], 16), outgoing_end, function)

    def test_default_calls_preserve_frames_on_both_targets_and_pipelines(self):
        source = ROOT / 'tests/language_default_stack_args.ml'
        callers = ('preservesCallerLocals', 'DefaultScope.preservesNamedCaller',
                   'preservesMethodCaller', 'preservesStaticCaller',
                   'preservesConstructorCaller', 'preservesHiddenDefaultCaller',
                   'preservesTypedCaller', 'DefaultCaller.preservesDefaultContext')
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for target in ('linux-x64', 'windows-x64'):
                images = []
                for pipeline in ('--no-object-pipeline', '--object-pipeline'):
                    with self.subTest(target=target, pipeline=pipeline):
                        image, listing = self.compile(source, directory, target, pipeline)
                        for caller in callers:
                            self.assert_outgoing_area(listing, caller, 10)
                        images.append(image)
                self.assertEqual(images[0], images[1], target)

    def test_import_alias_defaults_preserve_caller(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            package = directory / 'probe'
            package.mkdir()
            (package / 'defaults.ml').write_text('''package probe.defaults
function values(a, b, c, d = 4, e = 5, f = 6, g = 7, h = 8, i = 9, j = 10)
  return [a, b, c, d, e, f, g, h, i, j]
end function
''', encoding='utf-8')
            source = directory / 'main.ml'
            source.write_text('''import probe.defaults as imported
struct Marker
  values
end struct
function preservesImportedCaller()
  marker = Marker([801, 802])
  result = imported.values(c = 3, b = 2, a = 1)
  if typeof(marker) != "struct" then return 1 end if
  if marker.values[0] != 801 or marker.values[1] != 802 then return 2 end if
  if result[0] != 1 or result[9] != 10 then return 3 end if
  return 0
end function
function main(args)
  result = preservesImportedCaller()
  if result != 0 then return result end if
  print "[OK] imported default arguments preserve caller locals"
  return 0
end function
''', encoding='utf-8')
            for target in ('linux-x64', 'windows-x64'):
                with self.subTest(target=target):
                    _, listing = self.compile(source, directory, target, '--object-pipeline')
                    self.assert_outgoing_area(listing, 'preservesImportedCaller', 10)


if __name__ == '__main__':
    unittest.main()
