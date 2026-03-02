"""mlc.frontend

Helpers for loading and invoking the MiniLang frontend (tokenizer/parser/AST).

The compiler uses the frontend implemented in ``minilang_parser.py``. During tests and
CLI runs, the current working directory may vary, so a plain ``import minilang``
can accidentally resolve to an installed package or a stale cached module.

To keep resolution deterministic, we try to load ``minilang_parser.py`` by absolute
file path (via ``importlib``) with the following *best-effort* search order:

1) ``<dir(input .ml)>/../minilang_parser.py`` (common layout: ``tests/*.ml`` under root)
2) ``<dir(mlc/frontend.py)>/../..//minilang_parser.py`` (historical layout support)
3) ``<cwd>/../minilang_parser.py``
4) Fallback to regular ``import minilang``

Note:
    The path probes above are intentionally conservative and mirror the existing
    behavior. They are not meant to be an exhaustive module resolver.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from typing import Any, List, Tuple

# Cache loaded frontend modules by their absolute file path.
_CACHE: dict[str, Any] = {}


def _load_module_from_path(py_path: str) -> Any:
    """Load a Python module from an explicit file path.

    The module is cached by its absolute path. To avoid name collisions, a
    deterministic-but-unique module name is generated from the file path hash.

    Args:
        py_path: Path to the ``minilang_parser.py`` frontend file.

    Returns:
        The loaded Python module object.

    Raises:
        ImportError: If the module cannot be loaded from the given path.
    """

    py_path_abs = os.path.abspath(py_path)
    cached = _CACHE.get(py_path_abs)
    if cached is not None:
        return cached

    mod_name = f"minilang_{abs(hash(py_path_abs))}"
    spec = importlib.util.spec_from_file_location(mod_name, py_path_abs)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load minilang frontend from: {py_path_abs}")

    module = importlib.util.module_from_spec(spec)

    # Ensure dataclasses / typing lookups can find the module under its generated name.
    sys.modules[mod_name] = module

    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    _CACHE[py_path_abs] = module
    return module


def load_minilang_frontend(input_path: str) -> Any:
    """Resolve and load the MiniLang frontend module for a given input file.

    Args:
        input_path: Path to the ``.ml`` file being compiled.

    Returns:
        The loaded ``minilang`` module (either from a discovered ``minilang_parser.py``
        file or via regular import as a last resort).
    """

    # 1) minilang_parser.py located one directory above the input file.
    ml_dir = os.path.dirname(os.path.abspath(input_path))
    cand1 = os.path.join(ml_dir, "minilang_parser.py")
    if os.path.isfile(cand1):
        return _load_module_from_path(cand1)

    # 2) project root relative to this file (historical layout support).
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, os.pardir))
    cand2 = os.path.join(root, "minilang_parser.py")
    if os.path.isfile(cand2):
        return _load_module_from_path(cand2)

    # 2b) fallback: cwd
    cand3 = os.path.join(os.getcwd(), "minilang_parser.py")
    if os.path.isfile(cand3):
        return _load_module_from_path(cand3)

    # 3) last resort: normal import (might come from site-packages)
    from mlc import minilang_parser

    return minilang_parser


def normalize_code_for_tokenizer(code: str) -> str:
    """Normalize source code for tokenization.

    Currently this only rewrites *binary minus* cases where a digit follows
    immediately, e.g. ``x-1`` becomes ``x - 1``.

    Constraints:
        - Never touches string literals.
        - Never touches ``//`` line comments.
        - Keeps unary negatives intact: ``-1``, ``2*-3``, ``(-4)``, etc.

    Args:
        code: Raw MiniLang source.

    Returns:
        A normalized source string.
    """

    out: list[str] = []
    n = len(code)
    i = 0

    in_string = False
    in_line_comment = False
    escape = False

    def prev_nonspace_char(out_list: list[str]) -> str:
        j = len(out_list) - 1
        while j >= 0 and out_list[j].isspace():
            j -= 1
        return out_list[j] if j >= 0 else ""

    while i < n:
        c = code[i]

        # Handle line comments
        if in_line_comment:
            out.append(c)
            if c == "\n":
                in_line_comment = False
            i += 1
            continue

        # Enter line comment (only when not in string)
        if not in_string and c == "/" and i + 1 < n and code[i + 1] == "/":
            out.append(c)
            out.append(code[i + 1])
            i += 2
            in_line_comment = True
            continue

        # Handle string literals (double quotes)
        if in_string:
            out.append(c)
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue

        # Enter string
        if c == '"':
            out.append(c)
            in_string = True
            i += 1
            continue

        # Rewrite: "-" followed by digit, where the previous non-space char can end an expr.
        if c == "-" and i + 1 < n and code[i + 1].isdigit():
            p = prev_nonspace_char(out)
            # Expression-ending chars: identifier/number (alnum/_), ')' or ']'
            if p.isalnum() or p == "_" or p in (")", "]"):
                # Ensure space before '-'
                if out and not out[-1].isspace():
                    out.append(" ")
                out.append("-")
                # Ensure space after '-'
                if i + 1 < n and not code[i + 1].isspace():
                    out.append(" ")
                i += 1
                continue

        # Default: copy char
        out.append(c)
        i += 1

    return "".join(out)


def parse_program(minilang_mod: Any, input_path: str) -> tuple[str, Any]:
    """Parse a MiniLang source file into an AST.

    Args:
        minilang_mod: The loaded frontend module (see :func:`load_minilang_frontend`).
        input_path: Path to the ``.ml`` source file.

    Returns:
        A tuple ``(normalized_source, program_ast)``.

    Raises:
        Exception: Reraises frontend exceptions. For parse errors that carry
            position information, this function tries to attach the filename and
            the normalized source to improve diagnostics.
    """

    with open(input_path, "r", encoding="utf-8") as f:
        code = f.read()

    code = normalize_code_for_tokenizer(code)

    # Current signature: Parser(tokens, source, filename)
    try:
        try:
            program = minilang_mod.Parser(minilang_mod.tokenize(code), code, input_path, ).parse_program()
        except TypeError:
            # Legacy signature: Parser(tokens)
            program = minilang_mod.Parser(minilang_mod.tokenize(code)).parse_program()
    except Exception as e:
        # Ensure position-bearing frontend errors (especially ParseError) carry
        # filename + the *normalized* source, so diagnostics point to the correct
        # imported module and caret positions match the rewritten code.
        if getattr(e, "pos", None) is not None and type(e).__name__ in ("ParseError",):
            try:
                setattr(e, "filename", input_path)
            except Exception:
                pass
            try:
                setattr(e, "source", code)
            except Exception:
                pass
        raise

    return code, program


def parse_program_keepgoing(
    minilang_mod: Any,
    input_path: str,
    *,
    max_errors: int = 50,
) -> Tuple[str, Any, List[BaseException]]:
    """Parse a file but keep going on syntax errors.

    Returns (normalized_source, program_ast, errors).
    """

    with open(input_path, "r", encoding="utf-8") as f:
        code = f.read()

    code = normalize_code_for_tokenizer(code)

    # Tokenizer errors can't be recovered from in a meaningful way; report and return.
    try:
        toks = minilang_mod.tokenize(code)
    except Exception as e:
        if getattr(e, "pos", None) is not None and type(e).__name__ in ("ParseError",):
            try:
                setattr(e, "filename", input_path)
            except Exception:
                pass
            try:
                setattr(e, "source", code)
            except Exception:
                pass
        return code, [], [e]

    # Current signature: Parser(tokens, source, filename, collect_errors=?, max_errors=?)
    parser = None
    try:
        try:
            parser = minilang_mod.Parser(toks, code, input_path, collect_errors=True, max_errors=int(max_errors))
        except TypeError:
            # Legacy signature: Parser(tokens, source, filename)
            parser = minilang_mod.Parser(toks, code, input_path)
            # No recovery mode available in legacy frontends.
    except Exception as e:
        return code, [], [e]

    try:
        program = parser.parse_program()
    except Exception as e:
        # If the parser itself explodes, treat it as one error.
        if getattr(e, "pos", None) is not None and type(e).__name__ in ("ParseError",):
            try:
                setattr(e, "filename", input_path)
            except Exception:
                pass
            try:
                setattr(e, "source", code)
            except Exception:
                pass
        return code, [], [e]

    errs = list(getattr(parser, "errors", []) or [])
    # Attach filename + normalized source for consistent formatting.
    for e in errs:
        if getattr(e, "pos", None) is None:
            continue
        if getattr(e, "filename", None) is None:
            try:
                setattr(e, "filename", input_path)
            except Exception:
                pass
        if getattr(e, "source", None) is None:
            try:
                setattr(e, "source", code)
            except Exception:
                pass

    return code, program, errs
