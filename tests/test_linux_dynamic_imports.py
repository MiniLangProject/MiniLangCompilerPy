"""Linux loader regressions that are cheaper to verify below the language layer."""

from __future__ import annotations

import re
import unittest
from types import SimpleNamespace

from mlc.asm import Asm
from mlc.data import DataBuilder, RDataBuilder
from mlc.linux_runtime import emit_linux_runtime, linux_dynamic_imports


class _CodegenFixture(SimpleNamespace):
    def _extern_iat_label(self, library: str, symbol: str) -> str:
        base = re.sub(r"[^a-z0-9_]+", "_", library.lower()).strip("_") or "library"
        return f"iat_{base}_{symbol}"


class TestLinuxDynamicImports(unittest.TestCase):
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
                         {"pthread_create", "pthread_join", "dlopen", "dlsym"})
        self.assertIn("elfiat_libfirst_so_shared", cg.data.labels)
        self.assertIn("elfiat_libsecond_so_shared", cg.data.labels)
        self.assertNotEqual(cg.data.labels["elfiat_libfirst_so_shared"],
                            cg.data.labels["elfiat_libsecond_so_shared"])

        emit_linux_runtime(cg)
        patch_targets = {label for _, label, _ in cg.asm.patches}
        self.assertIn("elfiat_runtime_dlopen", patch_targets)
        self.assertIn("elfiat_runtime_dlsym", patch_targets)
        self.assertIn("elfiat_libfirst_so_shared", patch_targets)
        self.assertIn("elfiat_libsecond_so_shared", patch_targets)


if __name__ == "__main__":
    unittest.main()
