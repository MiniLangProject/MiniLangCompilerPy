"""Source-level documentation policy checks for the Python compiler."""

from __future__ import annotations

import ast
from pathlib import Path
import unittest


class TestSourceDocumentation(unittest.TestCase):
    """Keep public Python declarations documented as the compiler evolves."""

    def test_public_module_declarations_have_docstrings(self) -> None:
        """Require docstrings on every public module-level function and class."""

        root = Path(__file__).resolve().parents[1]
        missing: list[str] = []
        for path in sorted((root / "mlc").rglob("*.py")):
            module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in module.body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if node.name.startswith("_") or ast.get_docstring(node) is not None:
                    continue
                location = path.relative_to(root).as_posix()
                missing.append(f"{location}:{node.lineno}: {node.name}")

        self.assertEqual(missing, [], "Missing public docstrings:\n" + "\n".join(missing))


if __name__ == "__main__":
    unittest.main()
