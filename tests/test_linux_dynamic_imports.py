"""Linux loader regressions that are cheaper to verify below the language layer."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from mlc.asm import Asm
from mlc.data import DataBuilder, RDataBuilder
from mlc.linux_runtime import emit_linux_runtime, linux_dynamic_imports
from mlc.tools import extern_library_label_token


class _CodegenFixture(SimpleNamespace):
    def _extern_iat_label(self, library: str, symbol: str) -> str:
        return f"iat_{extern_library_label_token(library)}_{symbol}"


class TestLinuxDynamicImports(unittest.TestCase):
    """Verify deterministic, library-specific ELF dynamic import generation."""

    def test_duplicate_symbol_names_keep_library_specific_slots(self) -> None:
        cg = _CodegenFixture(
            asm=Asm(), data=DataBuilder(), rdata=RDataBuilder(),
            extern_sigs={
                "first.shared": {"dll": "libfirst.so", "symbol": "shared", "params": []},
                "second.shared": {"dll": "libsecond.so", "symbol": "shared", "params": []},
            },
        )

        imports = linux_dynamic_imports(cg)
        self.assertEqual({symbol for _, symbol, _ in imports},
                         {"pthread_create", "pthread_join", "dlopen", "dlsym", "dlclose"})
        first = f"elfiat_{extern_library_label_token('libfirst.so')}_shared"
        second = f"elfiat_{extern_library_label_token('libsecond.so')}_shared"
        self.assertIn(first, cg.data.labels)
        self.assertIn(second, cg.data.labels)
        self.assertNotEqual(cg.data.labels[first], cg.data.labels[second])

        emit_linux_runtime(cg)
        patch_targets = {label for _, label, _ in cg.asm.patches}
        self.assertIn("elfiat_runtime_dlopen", patch_targets)
        self.assertIn("elfiat_runtime_dlsym", patch_targets)
        self.assertIn("elfiat_runtime_dlclose", patch_targets)
        self.assertIn(first, patch_targets)
        self.assertIn(second, patch_targets)
        # LOCK CMPXCHG [r11],rdx claims each lazy resolver slot exactly once.
        self.assertIn(b"\xF0\x49\x0F\xB1\x13", bytes(cg.asm.buf))

    def test_exact_library_spelling_cannot_collapse(self) -> None:
        libraries = (
            "/opt/a/libsame.so",
            "/opt/b/libsame.so",
            "liba+b.so",
            "liba-b.so",
            "LIBA-B.SO",
        )
        tokens = [extern_library_label_token(library) for library in libraries]
        self.assertEqual(len(tokens), len(set(tokens)))
        self.assertTrue(all(token.startswith("lib_") for token in tokens))

    def test_same_basename_and_punctuation_dispatch_end_to_end(self) -> None:
        """Exact library identities must select four independent ELF handles."""

        wsl = shutil.which("wsl.exe") if os.name == "nt" else None
        if os.name == "nt" and wsl is None:
            self.skipTest("WSL is not installed")
        if os.name != "nt" and shutil.which("gcc") is None:
            self.skipTest("gcc is not installed")

        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="ml_linux_ffi_identity_") as td:
            work = Path(td)
            libraries = [
                (work / "a" / "libsame.so", 11),
                (work / "b" / "libsame.so", 22),
                (work / "punct" / "liba+b.so", 33),
                (work / "punct" / "liba-b.so", 44),
            ]
            for path, value in libraries:
                path.parent.mkdir(parents=True, exist_ok=True)
                source = path.with_suffix(".c")
                source.write_text(f"int shared(void) {{ return {value}; }}\n", encoding="utf-8")
                if os.name == "nt":
                    linux_source = subprocess.check_output(
                        [wsl, "wslpath", "-a", "-u", str(source).replace("\\", "/")], text=True,
                    ).strip()
                    linux_library = subprocess.check_output(
                        [wsl, "wslpath", "-a", "-u", str(path).replace("\\", "/")], text=True,
                    ).strip()
                    built = subprocess.run([wsl, "gcc", "-shared", "-fPIC", "-o", linux_library, linux_source])
                else:
                    built = subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(path), str(source)])
                self.assertEqual(built.returncode, 0)

            if os.name == "nt":
                library_names = [subprocess.check_output(
                    [wsl, "wslpath", "-a", "-u", str(path).replace("\\", "/")], text=True,
                ).strip() for path, _ in libraries]
            else:
                library_names = [str(path) for path, _ in libraries]
            program = work / "identity.ml"
            declarations = "\n".join(
                f'extern function value{index}() from "{name}" symbol "shared" returns int'
                for index, name in enumerate(library_names)
            )
            checks = "\n".join(
                f"  if value{index}() != {value} then return {index + 1} end if"
                for index, (_, value) in enumerate(libraries)
            )
            program.write_text(
                declarations + "\n\nfunction main(args)\n" + checks
                + '\n  print "[OK] exact Linux extern library identity"\n  return 0\nend function\n',
                encoding="utf-8",
            )
            image = work / "identity"
            compiler_override = os.environ.get("MINILANG_TEST_COMPILER", "").strip()
            compiler_command = ([compiler_override] if compiler_override else
                                [sys.executable, str(root / "mlc_win64.py")])
            compiled = subprocess.run(
                [*compiler_command, str(program), str(image), "--target", "linux-x64"],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            if os.name == "nt":
                linux_image = subprocess.check_output(
                    [wsl, "wslpath", "-a", "-u", str(image).replace("\\", "/")], text=True,
                ).strip()
                subprocess.check_call([wsl, "chmod", "+x", linux_image])
                executed = subprocess.run([wsl, linux_image], capture_output=True, text=True)
            else:
                image.chmod(0o755)
                executed = subprocess.run([str(image)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertIn("[OK] exact Linux extern library identity", executed.stdout)


if __name__ == "__main__":
    unittest.main()
