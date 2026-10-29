"""Exercise the Python cache's data-only codec and reject malformed records."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mlc.incremental import FunctionCache, _encode, _unview


class IncrementalCodecTests(unittest.TestCase):
    def test_primitive_roundtrip(self):
        original = [None, False, True, -123, 2**60 - 1, 1.5, "Grüße 🌍",
                    bytes(range(256)), [], (), {"a", "b"}, {b"x": (1, 2)}]
        self.assertEqual(_unview(json.loads(_encode(original))), original)

    def test_invalid_float_width(self):
        for raw in ("", "00", "00" * 9):
            with self.assertRaises(ValueError):
                _unview(["float", raw])

    def test_unknown_object_is_not_instantiated(self):
        with self.assertRaises(ValueError):
            _unview(["FunctionDef", []])

    def test_invalid_base64(self):
        with self.assertRaises(ValueError):
            _unview(["bytes", "*not-base64*"])

    def test_invalid_fragment_shapes(self):
        for record in (None, {}, [], [None] * 11):
            self.assertFalse(FunctionCache._valid_record(record, 0))

    def test_selected_frontend_invalidates_both_cache_layers(self):
        repo = Path(__file__).resolve().parents[1]
        target = "windows-x64" if os.name == "nt" else "linux-x64"
        (repo / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="incremental-parser-", dir=repo / "build") as temp:
            root = Path(temp)
            source = root / "main.ml"
            source.write_text("function value()\n  return 70\nend function\nprint value()\n", encoding="utf-8")
            adapter = root / "minilang_parser.py"
            output = root / "app.exe"
            manifest = root / "minilang.toml"
            manifest.write_text('[project]\nentry = "main.ml"\noutput = "app.exe"\n' +
                                f'target = "{target}"\n', encoding="utf-8")

            def build(project=False, clean=False):
                args = ["--project", str(manifest)] if project else [str(source), str(output),
                    "--target", target, "--incremental-cache", str(root / "cache")]
                if clean:
                    args += ["--no-incremental"]
                result = subprocess.run([sys.executable, str(repo / "mlc_win64.py"), *args, "--no-asm"],
                                        cwd=repo, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return hashlib.sha256(output.read_bytes()).hexdigest(), result.stdout

            stamp = time.time()
            for project in (False, True):
                original = None
                for value in (71, 72):
                    adapter.write_text("from mlc.minilang_parser import *\n" +
                        "from mlc.minilang_parser import preprocess_compile_directives as _preprocess\n" +
                        "def preprocess_compile_directives(code, filename):\n" +
                        f"    return _preprocess(code, filename).replace('return 70', 'return {value}')\n", encoding="utf-8")
                    # Avoid Python's timestamp-based .pyc reuse for same-size
                    # edits within one second; this test targets our caches.
                    stamp += 2
                    os.utime(adapter, (stamp, stamp))
                    changed, _ = build(project)
                    if original is not None:
                        self.assertNotEqual(original, changed)
                    repeated, log = build(project)
                    self.assertEqual(changed, repeated)
                    self.assertIn("cache hit; restored" if project else "reused=1", log)
                    clean, _ = build(project, clean=True)
                    self.assertEqual(changed, clean)
                    original = changed


if __name__ == "__main__":
    unittest.main()
