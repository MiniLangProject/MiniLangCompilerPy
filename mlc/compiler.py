"""
High level compilation entry points (compile_to_exe / CLI main).
"""

from __future__ import annotations

import argparse
import io
import re
import os
import sys
import ctypes
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from mlc.codegen import Codegen
from .errors import CompileError, Diagnostic, MultiCompileError
from .frontend import load_minilang_frontend, parse_program, normalize_code_for_tokenizer
from .pe import PEBuilder, build_idata, KERNEL32, MSVCRT
from .tools import u32


# Reserved identifiers cannot be used as `import ... as <alias>` (and are generally
# protected elsewhere in codegen).
_RESERVED_IDENTIFIERS = {"try", "error"}


# ---------------- CLI helpers ----------------

_SIZE_SUFFIXES = {
    "b": 1,
    "k": 1024,
    "kb": 1024,
    "kib": 1024,
    "m": 1024 ** 2,
    "mb": 1024 ** 2,
    "mib": 1024 ** 2,
    "g": 1024 ** 3,
    "gb": 1024 ** 3,
    "gib": 1024 ** 3,
    "t": 1024 ** 4,
    "tb": 1024 ** 4,
    "tib": 1024 ** 4,
}

def parse_size(s: str) -> int:
    """Parse byte sizes like '256m', '16mb', '4096'.

    Uses binary units (KiB/MiB/GiB) for k/m/g/t suffixes.
    """
    raw = str(s).strip().lower().replace("_", "")
    m = re.fullmatch(r"(\d+)([a-z]+)?", raw)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid size: {s!r}")
    n = int(m.group(1))
    suf = m.group(2) or "b"
    if suf not in _SIZE_SUFFIXES:
        raise argparse.ArgumentTypeError(
            f"invalid size suffix: {suf!r} (use k/m/g/t, kb/mb/gb/tb, or bytes)"
        )
    out = n * _SIZE_SUFFIXES[suf]
    if out <= 0:
        raise argparse.ArgumentTypeError(f"size must be > 0: {s!r}")
    return out

# ---------------- imports / multi-file loader ----------------

def _flatten_program(program: Any) -> List[Any]:
    """Return a flat list of statements from the parser output."""
    if isinstance(program, list):
        return program
    for attr in ("stmts", "statements", "body"):
        if hasattr(program, attr):
            v = getattr(program, attr)
            if isinstance(v, list):
                return v
    return [program]


def _is_import_stmt(ml: Any, st: Any) -> bool:
    n = type(st).__name__
    if n in ("Import", "ImportStmt"):
        return True
    for tname in ("Import", "ImportStmt"):
        t = getattr(ml, tname, None)
        if t is not None and isinstance(st, t):
            return True
    return False


def _import_path(st: Any) -> str:
    for attr in ("path", "filename", "file", "value", "name"):
        if hasattr(st, attr):
            v = getattr(st, attr)
            if isinstance(v, str):
                return v
    raise CompileError("Import statement missing path")



def _node_pos(node: Any) -> Optional[int]:
    return getattr(node, 'pos', None) or getattr(node, '_pos', None)


def _node_filename(node: Any) -> Optional[str]:
    return getattr(node, 'filename', None) or getattr(node, '_filename', None)


def _pos_to_line_col(code: str, pos: int) -> tuple[int, int]:
    """Convert a byte/char offset (pos) into 1-based (line, col)."""
    if pos < 0:
        return 1, 1
    # Fast path: count newlines before pos.
    line = code.count("\n", 0, min(pos, len(code))) + 1
    last_nl = code.rfind("\n", 0, min(pos, len(code)))
    col = (pos - last_nl) if last_nl >= 0 else (pos + 1)
    return line, max(1, col)


def _pretty_path(p: str, root: str) -> str:
    """Prefer a short, stable display path (relative to entry root when possible)."""
    try:
        rp = os.path.realpath(os.path.abspath(p))
        rr = os.path.realpath(os.path.abspath(root))
        # Only relpath when it doesn't get weird.
        rel = os.path.relpath(rp, rr)
        if not rel.startswith('..' + os.sep) and rel != '..':
            return rel.replace('\\', '/')
        return rp.replace('\\', '/')
    except Exception:
        return str(p).replace('\\', '/')


@dataclass(frozen=True)
class _ImportEdge:
    importer: str          # absolute path of importing file
    requested: str         # normalized requested path (e.g. "foo/bar.ml")
    resolved: str          # absolute resolved path
    pos: Optional[int]     # pos of the import statement in importer
    filename: str          # filename for diagnostics (usually importer)
    module: Optional[str] = None   # if module-style import, the dotted name (foo.bar)
    alias: Optional[str] = None    # optional `as alias`


def _is_abs_like(p: str) -> bool:
    # os.path.isabs doesn't treat 'C:\x' as absolute on POSIX.
    if os.path.isabs(p):
        return True
    if re.match(r"^[a-zA-Z]:[\\/]", p or ''):
        return True
    if p.startswith('\\\\') or p.startswith('//'):
        return True
    return False



def _resolve_import(requested: str, *, base_dir: str, include_dirs: List[str]) -> tuple[Optional[str], List[str], List[str], Optional[str], Optional[str]]:
    """Resolve an import to an absolute path.

    Search order:
      1) absolute path (if requested is absolute)
      2) <importer_dir>/<requested>
      3) each <include_dir>/<requested> in order

    Returns (resolved_abs_path_or_none, tried_paths, matching_paths, resolved_kind, resolved_root).

    resolved_kind is one of:
      - "abs"     : requested path was absolute (no stable package<->path mapping)
      - "rel"     : resolved via <importer_dir>/<requested>
      - "include" : resolved via one of the -I/--import-path roots
    resolved_root is the corresponding root directory for "rel"/"include", else None.
    """
    tried: List[str] = []
    origins: Dict[str, tuple[str, Optional[str]]] = {}

    def add_cand(p: str, *, kind: str, root: Optional[str]):
        ap = os.path.realpath(os.path.abspath(os.path.normpath(p)))
        if ap not in tried:
            tried.append(ap)
            origins[ap] = (kind, root)

    if _is_abs_like(requested):
        add_cand(requested, kind="abs", root=None)
    else:
        base_abs = os.path.realpath(os.path.abspath(base_dir))
        add_cand(os.path.join(base_abs, requested), kind="rel", root=base_abs)
        for inc in include_dirs:
            inc_abs = os.path.realpath(os.path.abspath(inc))
            add_cand(os.path.join(inc_abs, requested), kind="include", root=inc_abs)

    matches = [ap for ap in tried if os.path.exists(ap)]
    resolved = matches[0] if matches else None
    if not resolved:
        return None, tried, matches, None, None
    kind, root = origins.get(resolved, (None, None))  # type: ignore[assignment]
    return resolved, tried, matches, kind, root


def _path_to_package(rel_path: str) -> Optional[str]:
    """Convert a relative filesystem path (like foo/bar.ml) into a dotted package name (foo.bar)."""
    rp = rel_path.replace('\\', '/').lstrip('./')
    # no stable mapping if parent traversal is involved
    if rp.startswith('../') or '/..' in rp:
        return None
    base, ext = os.path.splitext(rp)
    if ext.lower() == '.ml':
        rp = base
    if not rp:
        return None
    parts = [p for p in rp.split('/') if p and p not in ('.', '..')]
    if not parts:
        return None
    return '.'.join(parts)


def _expected_package_for_file(abs_path: str, *, resolved_kind: Optional[str], resolved_root: Optional[str]) -> Optional[str]:
    """Best-effort expected package name derived from where the file was found.

    We only enforce this when the file was resolved via a stable root ("include" or "rel" without '..').
    """
    if resolved_kind not in ("rel", "include") or not resolved_root:
        return None
    try:
        rel = os.path.relpath(abs_path, resolved_root)
    except Exception:
        return None
    return _path_to_package(rel)

def _is_decl_stmt(ml: Any, st: Any) -> bool:
    """Return True if `st` is allowed at top-level of imported modules (declaration-only)."""
    n = type(st).__name__
    decl_names = (
        "FunctionDef", "StructDef", "EnumDef",
        "NamespaceDef", "NamespaceDecl",
        # extern declarations (Step 4/5)
        "ExternFunctionDef", "ExternFunctionDecl",
        # const/global bindings in libraries (Step 10)
        'ConstDecl', 'Assign',
    )
    if n in decl_names:
        return True
    for tname in decl_names:
        t = getattr(ml, tname, None)
        if t is not None and isinstance(st, t):
            return True
    return False


# ---------------- constexpr helpers (Step 3) ----------------

_CONSTEXPR_BINOPS = {
    'or', 'and',
    '|', '^', '&',
    '==', '!=', '>', '<', '>=', '<=',
    '<<', '>>',
    '+', '-', '*', '/', '%',
}

_CONSTEXPR_UNOPS = {'-', '~', 'not'}


def _expr_to_qualname(ml: Any, expr: Any) -> Optional[str]:
    """Return dotted qualname if expr is a simple member chain (Var/Member), else None."""
    var_cls = getattr(ml, 'Var', None)
    mem_cls = getattr(ml, 'Member', None)
    if var_cls is not None and isinstance(expr, var_cls):
        nm = getattr(expr, 'name', None)
        return nm if isinstance(nm, str) else None
    if mem_cls is not None and isinstance(expr, mem_cls):
        tgt = getattr(expr, 'target', None)
        seg = getattr(expr, 'name', None)
        base = _expr_to_qualname(ml, tgt)
        if base is None or not isinstance(seg, str):
            return None
        return f"{base}.{seg}"
    return None


def _is_constexpr_expr(ml: Any, expr: Any) -> bool:
    """Syntactic constexpr check.

    Used to ensure imported modules remain declaration-only: we only allow
    side-effect free initializers at top-level / inside namespaces.
    """
    if expr is None:
        return False

    # literals
    for lit in ('Num', 'Str', 'Bool'):
        cls = getattr(ml, lit, None)
        if cls is not None and isinstance(expr, cls):
            return True

    # name references (resolved later)
    var_cls = getattr(ml, 'Var', None)
    if var_cls is not None and isinstance(expr, var_cls):
        return True

    # qualified member references like Foo.Bar.Baz
    if _expr_to_qualname(ml, expr) is not None:
        return True

    # unary
    un_cls = getattr(ml, 'Unary', None)
    if un_cls is not None and isinstance(expr, un_cls):
        op = getattr(expr, 'op', None)
        rhs = getattr(expr, 'right', None)
        return (op in _CONSTEXPR_UNOPS) and _is_constexpr_expr(ml, rhs)

    # binary
    bin_cls = getattr(ml, 'Bin', None)
    if bin_cls is not None and isinstance(expr, bin_cls):
        op = getattr(expr, 'op', None)
        if op not in _CONSTEXPR_BINOPS:
            return False
        return _is_constexpr_expr(ml, getattr(expr, 'left', None)) and _is_constexpr_expr(ml, getattr(expr, 'right', None))

    return False


def _check_decl_only_recursive(ml: Any, st: Any, *, module_path: str) -> None:
    """Raise CompileError if `st` (or any nested stmt in a namespace) violates declaration-only rules.

    Imported modules are libraries and must not contain executable statements at top-level.
    Namespace bodies are not functions, so they are treated like top-level as well.
    """
    if st is None:
        return

    # Namespace blocks may nest; their body must also be declaration-only.
    ns_cls = getattr(ml, "NamespaceDef", None)
    if type(st).__name__ == "NamespaceDef" or (ns_cls is not None and isinstance(st, ns_cls)):
        body = getattr(st, "body", None)
        if isinstance(body, list):
            for ch in body:
                _check_decl_only_recursive(ml, ch, module_path=module_path)
        return

    # Step 3: imported-module initializers must be constexpr
    const_cls = getattr(ml, 'ConstDecl', None)
    if const_cls is not None and isinstance(st, const_cls):
        ex = getattr(st, 'expr', None)
        if not _is_constexpr_expr(ml, ex):
            raise CompileError(
                f"Imported module const initializer must be constexpr: {module_path}",
                pos=_node_pos(st),
                filename=_node_filename(st) or module_path,
            )
        return

    assign_cls = getattr(ml, 'Assign', None)
    if assign_cls is not None and isinstance(st, assign_cls):
        # Imported-module globals are initialized at runtime before main(args).
        # Only `const`/enum values stay under constexpr rules here.
        return

    enum_cls = getattr(ml, 'EnumDef', None)
    if enum_cls is not None and isinstance(st, enum_cls):
        vals = list(getattr(st, 'values', []) or [])
        if any(v is not None for v in vals):
            for vx in vals:
                if vx is None:
                    # missing values are allowed (auto-fill happens later)
                    continue
                if not _is_constexpr_expr(ml, vx):
                    raise CompileError(
                        f"Imported module enum values must be constexpr: {module_path}",
                        pos=_node_pos(st),
                        filename=_node_filename(st) or module_path,
                    )
        return

    if _is_import_stmt(ml, st) or _is_decl_stmt(ml, st):
        return

    raise CompileError(
        f"Imported module must be declaration-only: {module_path}",
        pos=_node_pos(st),
        filename=_node_filename(st) or module_path,
    )


def load_modules_recursive(
    ml: Any,
    entry_path: str,
    *,
    include_dirs: Optional[List[str]] = None,
    keep_going: bool = False,
    max_errors: int = 20,
) -> tuple[str, List[Any], Dict[str, str], Dict[str, Optional[str]]]:
    """Load entry file + all transitive imports.

    - Imports resolved relative to importing file's directory.
    - Imported modules must be declaration-only (no top-level executable statements other than
      declarations and allowed global initializers).
    - Import cycles are tolerated during loading; a module already being loaded is treated as
      "known/in progress" and is not recursively re-entered.
    - Import statements are removed from the merged statement list.

    When ``keep_going`` is enabled, the loader attempts to continue after an error
    and collects up to ``max_errors`` diagnostics. In that mode a
    :class:`~mlc.errors.MultiCompileError` is raised at the end.

    Returns:
      (entry_source, merged_program_stmts, import_aliases, packages_by_file)
    """

    if not isinstance(max_errors, int) or max_errors <= 0:
        max_errors = 1

    cache: Dict[str, List[Any]] = {}
    sources: Dict[str, str] = {}
    failed: set[str] = set()

    entry_abs = os.path.realpath(os.path.abspath(entry_path))
    entry_root = os.path.dirname(entry_abs)

    # Normalize include roots.
    # IMPORTANT: Always add the entry file's directory as an implicit include root.
    # Otherwise, nested imports inside subdirectories (e.g. std/time.ml importing
    # std/result.ml) would only search relative to the importer directory and fail
    # with paths like std/std/result.ml.
    include_dirs_norm: List[str] = []
    entry_root_abs = os.path.realpath(os.path.abspath(entry_root))
    include_dirs_norm.append(entry_root_abs)
    for d in (include_dirs or []):
        if not d:
            continue
        dd = os.path.realpath(os.path.abspath(d))
        if dd not in include_dirs_norm:
            include_dirs_norm.append(dd)

    visiting: List[str] = []
    visiting_edges: List[Optional[_ImportEdge]] = []
    order: List[str] = []
    packages: Dict[str, Optional[str]] = {}
    import_aliases: Dict[str, str] = {}

    diags: List[Diagnostic] = []
    stop_now = False

    def _record_diag(diag: Diagnostic) -> None:
        nonlocal stop_now
        if stop_now:
            return
        if len(diags) < max_errors:
            diags.append(diag)
        if len(diags) >= max_errors:
            stop_now = True

    def _record_exc(e: Exception, *, default_filename: str, default_source: Optional[str] = None) -> None:
        # Convert an exception into a Diagnostic.
        fn = getattr(e, 'filename', None) or default_filename
        pos = getattr(e, 'pos', None)
        src = getattr(e, 'source', None)
        if not isinstance(src, str):
            src = sources.get(fn) or default_source
        _record_diag(Diagnostic(
            kind=type(e).__name__,
            message=str(e),
            filename=fn,
            pos=pos if isinstance(pos, int) else None,
            source=src if isinstance(src, str) else None,
        ))


    def _attach_filename_recursive(node: Any, filename: str, code0: str, *, _seen: Optional[set[int]] = None) -> None:
        """Attach origin metadata to AST nodes.

        In addition to ``_filename`` (used for diagnostics and package/extern
        resolution), we also attach source locations for runtime error origins:

          - _line: 1-based line number
          - _col:  1-based column number

        The native backend can then expose these as part of the built-in
        ``error`` value when an error is created (including inside builtins).
        """
        if node is None:
            return

        if _seen is None:
            _seen = set()
        nid = id(node)
        if nid in _seen:
            return
        _seen.add(nid)

        try:
            setattr(node, "_filename", filename)
        except Exception:
            pass

        # Attach line/col if possible.
        try:
            pos0 = _node_pos(node)
            if isinstance(pos0, int) and code0:
                ln, col = _pos_to_line_col(code0, pos0)
                setattr(node, "_line", ln)
                setattr(node, "_col", col)
        except Exception:
            pass

        # Recurse into child nodes.
        # The parser's node classes are simple dataclasses-like objects.
        # We iterate over __dict__ when available.
        try:
            d = getattr(node, "__dict__", None)
            if isinstance(d, dict):
                for v in d.values():
                    if isinstance(v, list):
                        for ch in v:
                            _attach_filename_recursive(ch, filename, code0, _seen=_seen)
                    else:
                        _attach_filename_recursive(v, filename, code0, _seen=_seen)
        except Exception:
            return

    def _format_edge(edge: _ImportEdge) -> str:
        imp_disp = _pretty_path(edge.importer, entry_root)
        res_disp = _pretty_path(edge.resolved, entry_root)
        loc = imp_disp
        if edge.pos is not None:
            code0 = sources.get(edge.importer, "")
            if code0:
                ln, col = _pos_to_line_col(code0, edge.pos)
                loc = f"{imp_disp}:{ln}:{col}"

        req = edge.module if edge.module else f"\"{edge.requested}\""
        as_part = f" as {edge.alias}" if edge.alias else ""
        return f"  {loc}: import {req}{as_part} -> {res_disp}"

    def load_one(path: str, *, is_main: bool, edge: Optional[_ImportEdge] = None) -> None:
        nonlocal stop_now

        if stop_now:
            return

        ap = os.path.realpath(os.path.abspath(path))

        if ap in cache or ap in failed:
            return
        # Import cycles are allowed at loader level. If a module is already in progress,
        # treat it as known and keep going without recursively re-entering it.
        # This covers both self-imports and broader A <-> B style cycles.
        if ap in visiting:
            return

        if not os.path.exists(ap):
            ce = CompileError(f"Import file not found: {ap}", filename=ap)
            if keep_going:
                _record_exc(ce, default_filename=ap)
                failed.add(ap)
                return
            raise ce

        visiting.append(ap)
        visiting_edges.append(edge)

        try:
            try:
                code, prog = parse_program(ml, ap)
            except Exception as e:
                if keep_going:
                    _record_exc(e, default_filename=ap)
                    failed.add(ap)
                    cache[ap] = []
                    order.append(ap)
                    return
                raise

            sources[ap] = code
            stmts = _flatten_program(prog)

            # Ensure every node in this module carries its origin filename.
            for st_ in stmts:
                _attach_filename_recursive(st_, ap, code)

            # Extract `package` directive if present (NamespaceDecl).
            pkg_name: Optional[str] = None
            for st0 in stmts:
                if type(st0).__name__ == "NamespaceDecl":
                    nm = getattr(st0, "name", None)
                    if isinstance(nm, str) and nm:
                        pkg_name = nm
                    break
            packages[ap] = pkg_name
            # Imported modules are libraries and must be declaration-only.
            if ap != entry_abs:
                for st in stmts:
                    try:
                        _check_decl_only_recursive(ml, st, module_path=ap)
                    except CompileError as e:
                        if keep_going:
                            _record_exc(e, default_filename=ap, default_source=code)
                            failed.add(ap)
                            cache[ap] = []
                            order.append(ap)
                            return
                        raise

            module_failed = False

            # Recurse into imports for ALL modules (needed for cycle detection)
            base_dir = os.path.dirname(ap)
            for st in stmts:
                if stop_now:
                    break
                if not _is_import_stmt(ml, st):
                    continue

                rel = _import_path(st)
                resolved, tried, matches, res_kind, res_root = _resolve_import(
                    rel,
                    base_dir=base_dir,
                    include_dirs=include_dirs_norm,
                )

                if not resolved:
                    tried_s = "\n".join("  - " + t for t in tried)
                    ce = CompileError(
                        f"Import file not found: {rel}\nSearched:\n{tried_s}",
                        pos=_node_pos(st),
                        filename=_node_filename(st) or ap,
                    )
                    if keep_going:
                        _record_exc(ce, default_filename=ap, default_source=code)
                        module_failed = True
                        continue
                    raise ce

                if len(matches) > 1:
                    matches_s = "\n".join("  - " + p for p in matches)
                    tried_s = "\n".join("  - " + t for t in tried)
                    ce = CompileError(
                        f"Ambiguous import: {rel}\nMatches:\n{matches_s}\nSearched:\n{tried_s}",
                        pos=_node_pos(st),
                        filename=_node_filename(st) or ap,
                    )
                    if keep_going:
                        _record_exc(ce, default_filename=ap, default_source=code)
                        module_failed = True
                        continue
                    raise ce

                child = resolved
                edge2 = _ImportEdge(
                    importer=ap,
                    requested=rel,
                    resolved=child,
                    pos=_node_pos(st),
                    filename=_node_filename(st) or ap,
                    module=getattr(st, "module", None),
                    alias=getattr(st, "alias", None),
                )

                load_one(child, is_main=False, edge=edge2)

                if stop_now:
                    break

                # If the imported file declares a package, enforce that its *location* matches that package
                # when the file was resolved via a stable root (importer-dir or -I include root).
                declared_pkg = packages.get(child)
                expected_pkg = _expected_package_for_file(child, resolved_kind=res_kind, resolved_root=res_root)
                if declared_pkg and expected_pkg and declared_pkg != expected_pkg:
                    root_disp = _pretty_path(res_root, entry_root) if res_root else str(res_root)
                    ce = CompileError(
                        f"File declares package {declared_pkg}, but was found as {expected_pkg} (root: {root_disp}): {child}",
                        pos=_node_pos(st),
                        filename=_node_filename(st) or ap,
                    )
                    if keep_going:
                        _record_exc(ce, default_filename=ap, default_source=code)
                        module_failed = True
                    else:
                        raise ce

                # If this was a module-style import (`import foo.bar`), and the imported file declares
                # a package, enforce that it matches the module name.
                expected_mod = getattr(st, "module", None)
                if isinstance(expected_mod, str) and expected_mod:
                    declared_pkg2 = packages.get(child)
                    if declared_pkg2 and declared_pkg2 != expected_mod:
                        ce = CompileError(
                            f"Module import {expected_mod} points to file declaring package {declared_pkg2}: {child}",
                            pos=_node_pos(st),
                            filename=_node_filename(st) or ap,
                        )
                        if keep_going:
                            _record_exc(ce, default_filename=ap, default_source=code)
                            module_failed = True
                        else:
                            raise ce

                # Handle optional import alias: `import ... as <alias>`
                alias = getattr(st, "alias", None)
                if isinstance(alias, str) and alias:
                    if alias in _RESERVED_IDENTIFIERS:
                        ce = CompileError(
                            f"import alias '{alias}' is reserved",
                            pos=_node_pos(st),
                            filename=_node_filename(st) or ap,
                        )
                        if keep_going:
                            _record_exc(ce, default_filename=ap, default_source=code)
                            module_failed = True
                            continue
                        raise ce
                    target_pkg = packages.get(child)
                    if not target_pkg:
                        ce = CompileError(
                            f"import ... as {alias} requires imported file to declare `package`: {child}",
                            pos=_node_pos(st),
                            filename=_node_filename(st) or ap,
                        )
                        if keep_going:
                            _record_exc(ce, default_filename=ap, default_source=code)
                            module_failed = True
                            continue
                        raise ce
                    prev = import_aliases.get(alias)
                    if prev is not None and prev != target_pkg:
                        ce = CompileError(
                            f"import alias {alias} refers to multiple packages: {prev} and {target_pkg}",
                            pos=_node_pos(st),
                            filename=_node_filename(st) or ap,
                        )
                        if keep_going:
                            _record_exc(ce, default_filename=ap, default_source=code)
                            module_failed = True
                            continue
                        raise ce
                    import_aliases[alias] = target_pkg

                # Implicit aliasing (quality-of-life): import std.fs => fs.delete(...)
                if not (isinstance(alias, str) and alias):
                    target_pkg = packages.get(child)
                    if isinstance(target_pkg, str) and '.' in target_pkg:
                        implicit = target_pkg.rsplit('.', 1)[1]
                        if implicit in _RESERVED_IDENTIFIERS:
                            pass
                        else:
                            prev = import_aliases.get(implicit)
                            if prev is None:
                                import_aliases[implicit] = target_pkg
                            elif prev != target_pkg:
                                ce = CompileError(
                                    f"Implicit import alias '{implicit}' is ambiguous between packages {prev} and {target_pkg}. "
                                    f"Use 'import ... as <alias>' to disambiguate.",
                                    pos=_node_pos(st),
                                    filename=_node_filename(st) or ap,
                                )
                                if keep_going:
                                    _record_exc(ce, default_filename=ap, default_source=code)
                                    module_failed = True
                                else:
                                    raise ce

            filtered = [st for st in stmts if not _is_import_stmt(ml, st)]

            if module_failed:
                failed.add(ap)
                cache[ap] = []
                order.append(ap)
                return

            cache[ap] = filtered
            order.append(ap)

        finally:
            visiting.pop()
            visiting_edges.pop()

    load_one(entry_abs, is_main=True)

    if keep_going and diags:
        raise MultiCompileError(diags)

    merged: List[Any] = []
    for ap in order:
        merged.extend(cache.get(ap, []))

    return sources.get(entry_abs, ""), merged, import_aliases, packages

@dataclass(frozen=True)
class ExternSig:
    qname: str
    dll: str
    symbol: str
    params: List[str]
    ret_ty: str


# ------------------------------------------------------------
# Extern validation (Step 3)
# ------------------------------------------------------------


# Keep in sync with CodegenExpr._emit_extern_arg_to_native / _emit_extern_ret_from_native.
_EXTERN_ABI_TYPES = {
    "int", "i64", "u64", "i32", "u32", "i16", "u16", "i8", "u8",
    "bool",
    "ptr", "pointer",
    "cstr", "cstring",
    "wstr", "wstring",
    "void", "none",
    "bytes", "buffer", "bytebuffer",
}

_EXTERN_RET_TYPES = {
    "void", "none",
    "bool",
    "int", "i64", "u64", "i32", "u32", "i16", "u16", "i8", "u8",
    "ptr", "pointer",
    "cstr", "wstr",
}



# Extern struct field types (used for out-params / ABI structs).
_EXTERN_STRUCT_FIELD_TYPES = {
    "i8", "u8",
    "i16", "u16",
    "i32", "u32",
    "i64", "u64",
    "int",
    "bool",   # treated as 32-bit BOOL for layout
    "ptr", "pointer",
}

_EXTERN_STRUCT_FIELD_SIZE = {
    "i8": 1, "u8": 1,
    "i16": 2, "u16": 2,
    "i32": 4, "u32": 4,
    "bool": 4,
    "i64": 8, "u64": 8,
    "int": 8,
    "ptr": 8, "pointer": 8,
}

def _extern_struct_layout(fields: list[tuple[str, str]]) -> dict[str, object]:
    """Compute a Win64 C-like struct layout (sequential, natural alignment, max 8)."""
    offs: list[int] = []
    types: list[str] = []
    names: list[str] = []
    offset = 0
    align = 1
    for (nm, ty) in fields:
        t = _norm_abi_ty(ty)
        sz = int(_EXTERN_STRUCT_FIELD_SIZE.get(t, 0) or 0)
        if sz <= 0:
            raise ValueError(f"invalid extern struct field type: {ty}")
        fa = min(sz, 8)
        if fa > align:
            align = fa
        # align offset
        if offset % fa:
            offset += (fa - (offset % fa))
        offs.append(offset)
        names.append(str(nm))
        types.append(str(ty))
        offset += sz
    # final padding
    if offset % align:
        offset += (align - (offset % align))
    return {"fields": names, "types": types, "offsets": offs, "size": offset, "align": align}

def _norm_abi_ty(t: Any) -> str:
    return str(t or "").strip().lower()


def _resolve_dll_candidates(dll: str, *, out_dir: str, src_dir: str, include_dirs: List[str]) -> List[str]:
    """Best-effort DLL path candidates.

    Notes:
      - The Windows loader will use its own search order when given a bare name.
      - For nicer diagnostics we try the most likely project locations first.
    """
    dll_s = str(dll or "").strip()
    if not dll_s:
        return []

    # If caller provided any directory component, treat it as a path.
    has_sep = ("/" in dll_s) or ("\\" in dll_s)
    if has_sep or _is_abs_like(dll_s):
        ap = os.path.realpath(os.path.abspath(os.path.normpath(dll_s)))
        return [ap]

    cands: List[str] = []
    for d in [out_dir, src_dir] + list(include_dirs or []):
        if not d:
            continue
        ap = os.path.realpath(os.path.abspath(os.path.join(d, dll_s)))
        if ap not in cands:
            cands.append(ap)
    # Finally, the raw name (lets LoadLibrary apply its default search order).
    cands.append(dll_s)
    return cands


def validate_extern_sigs(
    extern_sigs: Dict[str, Dict[str, Any]],
    *,
    extern_structs: Optional[Dict[str, Dict[str, Any]]] = None,
    output_exe: str,
    input_ml: str,
    include_dirs: Optional[List[str]] = None,
) -> None:
    """Validate extern declarations:

    1) ABI types must be supported (compile-time error at declaration).
    2) On Windows, try to resolve DLL + symbol using LoadLibrary/GetProcAddress
       (via ctypes) for friendlier diagnostics.
    """

    inc = list(include_dirs or [])
    out_dir = os.path.dirname(os.path.realpath(os.path.abspath(output_exe)))
    src_dir = os.path.dirname(os.path.realpath(os.path.abspath(input_ml)))

    # Type validation (always; independent of OS)
    for qn, sig in (extern_sigs or {}).items():
        if not isinstance(sig, dict):
            continue
        pos = sig.get("pos")
        fn = sig.get("filename")

        params = list(sig.get("params", []) or [])
        ext_structs = extern_structs or {}

        # Normalize params: accept legacy list[str] and new list[dict{ty,out}]
        norm_params: list[tuple[str, bool]] = []
        for i, p in enumerate(params):
            if isinstance(p, dict):
                ty = str(p.get("ty", "") or "")
                is_out = bool(p.get("out", False))
            else:
                ty = str(p or "")
                is_out = False
            nt = _norm_abi_ty(ty)
            if not nt:
                raise CompileError(
                    f"extern function {qn}: missing ABI type for parameter #{i+1}",
                    pos=pos,
                    filename=fn,
                )
            norm_params.append((ty, is_out))

        # out-params must be trailing (for implicit omission at call sites)
        seen_out = False
        for i, (ty, is_out) in enumerate(norm_params):
            nt = _norm_abi_ty(ty)
            if is_out:
                seen_out = True
            elif seen_out:
                raise CompileError(
                    f"extern function {qn}: out-parameters must appear at the end of the parameter list",
                    pos=pos,
                    filename=fn,
                )

            if is_out:
                # out-params: allow scalar ABI types or extern struct types
                if nt in _EXTERN_ABI_TYPES:
                    continue
                if ty in ext_structs:
                    continue
                raise CompileError(
                    f"extern function {qn}: unsupported out parameter type '{ty}' (expected scalar ABI type or extern struct)",
                    pos=pos,
                    filename=fn,
                )
            else:
                # normal params: scalar ABI types only
                if nt not in _EXTERN_ABI_TYPES:
                    raise CompileError(
                        f"extern function {qn}: unsupported ABI type '{ty}' (supported: {', '.join(sorted(_EXTERN_ABI_TYPES))})",
                        pos=pos,
                        filename=fn,
                    )

        rt = _norm_abi_ty(sig.get("ret_ty", "")) or "void"
        if rt not in _EXTERN_RET_TYPES:
            raise CompileError(
                f"extern function {qn}: unsupported return type '{sig.get('ret_ty')}' (supported: {', '.join(sorted(_EXTERN_RET_TYPES))})",
                pos=pos,
                filename=fn,
            )

    # DLL/symbol validation (Windows only)
    if os.name != "nt":
        return

    loaded: Dict[str, Any] = {}

    for qn, sig in (extern_sigs or {}).items():
        if not isinstance(sig, dict):
            continue
        dll = str(sig.get("dll", "") or "").strip()
        sym = str(sig.get("symbol", "") or "").strip() or str(qn).split(".")[-1]
        pos = sig.get("pos")
        fn = sig.get("filename")

        if not dll:
            raise CompileError(f"extern function {qn} missing DLL name", pos=pos, filename=fn)

        # Try candidates (project-local first), then raw name.
        cands = _resolve_dll_candidates(dll, out_dir=out_dir, src_dir=src_dir, include_dirs=inc)
        last_err: Optional[BaseException] = None
        lib = None
        used_dll = None

        for cand in cands:
            try:
                if cand in loaded:
                    lib = loaded[cand]
                else:
                    # WinDLL uses LoadLibrary under the hood.
                    lib = ctypes.WinDLL(cand)
                    loaded[cand] = lib
                used_dll = cand
                break
            except Exception as e:
                last_err = e
                lib = None

        if lib is None:
            tried = "\n  - " + "\n  - ".join([str(x) for x in cands]) if cands else ""
            hint = (
                "Hint: use an absolute path in `from \"...\"`, or place the DLL next to the produced .exe, "
                "or make sure it is discoverable via PATH/System32 search order."
            )
            msg = f"extern function {qn}: cannot load DLL '{dll}'. Tried:{tried}\n{hint}"
            if last_err is not None:
                msg += f"\nLoad error: {last_err}"
            raise CompileError(msg, pos=pos, filename=fn)

        # Symbol check.
        try:
            getattr(lib, sym)
        except AttributeError:
            used = used_dll or dll
            hint = (
                "Hint: verify the exported name (e.g. `dumpbin /exports <dll>`), "
                "and set `symbol \"...\"` if the export name differs (decorated C/C++ names, A/W suffix, etc.)."
            )
            raise CompileError(
                f"extern function {qn}: symbol '{sym}' not found in '{used}'.\n{hint}",
                pos=pos,
                filename=fn,
            )



def collect_extern_structs(ml: Any, program: List[Any], packages_by_file: Dict[str, Optional[str]]) -> Dict[str, Dict[str, Any]]:
    """Collect `extern struct` declarations.

    `extern struct` is parsed as a normal StructDef node with an extra attribute
    `_extern_field_types` holding ABI field type names.

    Returns: qname -> {layout..., pos, filename}
    """
    out: Dict[str, Dict[str, Any]] = {}

    def _pkg_parts_for(node: Any) -> List[str]:
        fn = _node_filename(node)
        if not fn:
            return []
        ap = os.path.realpath(os.path.abspath(fn))
        pkg = packages_by_file.get(ap)
        if not pkg:
            return []
        return [p for p in str(pkg).split('.') if p]

    def _join(parts: List[str]) -> str:
        return ".".join([p for p in parts if p])

    def walk_stmt(st: Any, ns_parts: List[str], pkg_parts: List[str]) -> None:
        if st is None:
            return
        n = type(st).__name__

        ns_cls = getattr(ml, "NamespaceDef", None)
        if n == "NamespaceDef" or (ns_cls is not None and isinstance(st, ns_cls)):
            nm = getattr(st, "name", None)
            parts = [p for p in str(nm).split(".") if p] if nm else []
            for ch in (getattr(st, "body", None) or []):
                walk_stmt(ch, ns_parts + parts, pkg_parts)
            return

        st_cls = getattr(ml, "StructDef", None)
        if n == "StructDef" or (st_cls is not None and isinstance(st, st_cls)):
            tys = getattr(st, "_extern_field_types", None)
            if not isinstance(tys, list) or not tys:
                return
            nm = getattr(st, "name", None)
            if not isinstance(nm, str) or not nm:
                return
            qn = _join(pkg_parts + ns_parts + [nm])
            fields = list(getattr(st, "fields", []) or [])
            if len(fields) != len(tys):
                raise CompileError(f"extern struct {qn}: field/type count mismatch", pos=_node_pos(st), filename=_node_filename(st))

            # Validate field types + compute layout.
            ft: list[tuple[str, str]] = []
            for f, t in zip(fields, tys):
                nt = _norm_abi_ty(t)
                if nt not in _EXTERN_STRUCT_FIELD_TYPES:
                    raise CompileError(
                        f"extern struct {qn}: unsupported field type '{t}' (supported: {', '.join(sorted(_EXTERN_STRUCT_FIELD_TYPES))})",
                        pos=_node_pos(st),
                        filename=_node_filename(st),
                    )
                ft.append((str(f), str(t)))

            try:
                layout = _extern_struct_layout(ft)
            except Exception as e:
                raise CompileError(f"extern struct {qn}: cannot compute layout: {e}", pos=_node_pos(st), filename=_node_filename(st))

            if qn in out:
                raise CompileError(f"Duplicate extern struct declaration: {qn}", pos=_node_pos(st), filename=_node_filename(st))

            out[qn] = {
                **layout,
                "pos": _node_pos(st),
                "filename": _node_filename(st),
            }
            return

        # Recurse into other statement containers.
        for attr in ("body", "then_body", "else_body", "default_body"):
            v = getattr(st, attr, None)
            if isinstance(v, list):
                for ch in v:
                    walk_stmt(ch, ns_parts, pkg_parts)

        elifs = getattr(st, "elifs", None)
        if isinstance(elifs, list):
            for item in elifs:
                if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], list):
                    for ch in item[1]:
                        walk_stmt(ch, ns_parts, pkg_parts)

        cases = getattr(st, "cases", None)
        if isinstance(cases, list):
            for c in cases:
                b = getattr(c, "body", None)
                if isinstance(b, list):
                    for ch in b:
                        walk_stmt(ch, ns_parts, pkg_parts)

    for st in program:
        walk_stmt(st, [], _pkg_parts_for(st))

    return out

def collect_extern_sigs(ml: Any, program: List[Any], packages_by_file: Dict[str, Optional[str]]) -> Dict[str, Dict[str, Any]]:
    """Collect `extern function` declarations into a dict keyed by qualified name.

    Key format:
      <package>.<namespace>.<name>

    Returns a plain-JSON-able mapping:
      qname -> {dll, symbol, params, ret_ty}
    """
    externs: Dict[str, Dict[str, Any]] = {}
    user_funcs: set[str] = set()

    def _pkg_parts_for(node: Any) -> List[str]:
        fn = _node_filename(node)
        if not fn:
            return []
        ap = os.path.realpath(os.path.abspath(fn))
        pkg = packages_by_file.get(ap)
        if not pkg:
            return []
        return [p for p in str(pkg).split('.') if p]

    def _join(parts: List[str]) -> str:
        return ".".join([p for p in parts if p])

    def walk_stmt(st: Any, ns_parts: List[str], pkg_parts: List[str]) -> None:
        if st is None:
            return
        n = type(st).__name__

        # Namespace blocks
        ns_cls = getattr(ml, "NamespaceDef", None)
        if n == "NamespaceDef" or (ns_cls is not None and isinstance(st, ns_cls)):
            nm = getattr(st, "name", None)
            parts = [p for p in str(nm).split(".") if p] if nm else []
            for ch in (getattr(st, "body", None) or []):
                walk_stmt(ch, ns_parts + parts, pkg_parts)
            return

        # Function defs (for conflict checking)
        fn_cls = getattr(ml, "FunctionDef", None)
        if n == "FunctionDef" or (fn_cls is not None and isinstance(st, fn_cls)):
            nm = getattr(st, "name", None)
            if isinstance(nm, str) and nm:
                user_funcs.add(_join(pkg_parts + ns_parts + [nm]))
            return

        # Extern function defs
        ex_cls = getattr(ml, "ExternFunctionDef", None)
        if n in ("ExternFunctionDef", "ExternFunctionDecl") or (ex_cls is not None and isinstance(st, ex_cls)):
            nm = getattr(st, "name", None)
            if not isinstance(nm, str) or not nm:
                return
            qn = _join(pkg_parts + ns_parts + [nm])

            dll = getattr(st, "dll", None)
            if not isinstance(dll, str) or not dll:
                raise CompileError(f"extern function {qn} missing DLL name", pos=_node_pos(st), filename=_node_filename(st))

            sym = getattr(st, "symbol", None)
            if not isinstance(sym, str) or not sym:
                sym = nm

            params0 = getattr(st, "params", None) or []
            params: List[Dict[str, Any]] = []
            for p in params0:
                ty0 = getattr(p, "ty", None)
                ty_s = str(ty0) if ty0 is not None else ""
                is_out = bool(getattr(p, "is_out", False))

                # If this is not a known scalar ABI type and not already qualified,
                # treat it as a struct type reference in the current namespace/package.
                nt = _norm_abi_ty(ty_s)
                if nt and nt not in _EXTERN_ABI_TYPES and "." not in ty_s:
                    ty_s = _join(pkg_parts + ns_parts + [ty_s])

                params.append({"ty": ty_s, "out": is_out})

            ret_ty = getattr(st, "ret_ty", None)
            ret_ty = ret_ty if isinstance(ret_ty, str) and ret_ty else "int"

            if qn in externs:
                raise CompileError(f"Duplicate extern function declaration: {qn}", pos=_node_pos(st), filename=_node_filename(st))

            externs[qn] = {
                "dll": dll,
                "symbol": sym,
                "params": params,
                "ret_ty": ret_ty,
                # for better diagnostics (Step 3)
                "pos": _node_pos(st),
                "filename": _node_filename(st),
            }
            return

        # Recurse into other statement containers (future-proof)
        for attr in ("body", "then_body", "else_body", "default_body"):
            v = getattr(st, attr, None)
            if isinstance(v, list):
                for ch in v:
                    walk_stmt(ch, ns_parts, pkg_parts)

        elifs = getattr(st, "elifs", None)
        if isinstance(elifs, list):
            for item in elifs:
                if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], list):
                    for ch in item[1]:
                        walk_stmt(ch, ns_parts, pkg_parts)

        cases = getattr(st, "cases", None)
        if isinstance(cases, list):
            for c in cases:
                b = getattr(c, "body", None)
                if isinstance(b, list):
                    for ch in b:
                        walk_stmt(ch, ns_parts, pkg_parts)

    for st in program:
        walk_stmt(st, [], _pkg_parts_for(st))

    for qn in externs.keys():
        if qn in user_funcs:
            raise CompileError(f"Name conflict: {qn} is declared as both a function and an extern function")

    return externs

def compile_to_exe(
    input_ml: str,
    output_exe: str,
    *,
    include_dirs: Optional[List[str]] = None,
    keep_going: bool = False,
    max_errors: int = 20,
    # Default: no listing unless explicitly enabled on the CLI.
    asm_listing: bool = False,
    asm_out: Optional[str] = None,
    asm_show_addr: bool = True,
    asm_show_bytes: bool = True,
    asm_show_text: bool = True,
    asm_dump_data: bool = False,
    asm_dump_pe: bool = False,
    heap_config: Optional[Dict[str, Any]] = None,
    call_profile: bool = False,
    trace_calls: bool = False,
) -> None:
    ml = load_minilang_frontend(input_ml)
    source, program, import_aliases, packages_by_file = load_modules_recursive(ml, input_ml, include_dirs=include_dirs, keep_going=keep_going, max_errors=max_errors)

    extern_sigs = collect_extern_sigs(ml, program, packages_by_file)

    extern_structs = collect_extern_structs(ml, program, packages_by_file)

    # Step 3: validate extern declarations early (friendly diagnostics)
    validate_extern_sigs(extern_sigs, extern_structs=extern_structs, output_exe=output_exe, input_ml=input_ml, include_dirs=include_dirs)

    cg = Codegen(
        ml,
        source,
        input_ml,
        heap_config=heap_config,
        import_aliases=import_aliases,
        extern_sigs=extern_sigs,
        extern_structs=extern_structs,
        call_profile=bool(call_profile),
        trace_calls=bool(trace_calls),
    )

    asm_listing_path: Optional[str] = None
    if asm_listing:
        asm_listing_path = asm_out or (os.path.splitext(output_exe)[0] + '.asm')
        cg.asm.enable_listing(
            asm_listing_path,
            show_addr=asm_show_addr,
            show_bytes=asm_show_bytes,
            show_text=asm_show_text,
        )

    cg.emit_program(program)

    # Build PE with 2-pass layout (important!)
    pe = PEBuilder()

    text_sec = pe.add_section('.text', bytes(cg.asm.buf), 0x60000020)
    rdata_sec = pe.add_section('.rdata', bytes(cg.rdata.data), 0x40000040)
    data_sec = pe.add_section('.data', bytes(cg.data.data), 0xC0000040)

    # Uninitialized scratch space (keeps EXE size small; loader zero-fills).
    # Typical flags: UNINITIALIZED_DATA | READ | WRITE
    bss_sec = pe.add_section('.bss', b'', 0xC0000080)
    bss_sec.virt_size = int(getattr(cg, 'bss', None).size) if getattr(cg, 'bss', None) is not None else 0

    idata_sec = pe.add_section('.idata', b'', 0xC0000040)

    # First layout
    pe.layout()

    # Build .idata with base RVA
    idata_base_rva = idata_sec.virt_addr
    idata_bytes, import_dir_rva, import_size, iat_symbol_rva = build_idata(cg.imports, idata_base_rva)
    idata_sec.data = bytearray(idata_bytes)
    pe.import_rva = import_dir_rva
    pe.import_size = import_size

    # Re-layout after idata size known
    pe.layout()

    text_rva = text_sec.virt_addr
    rdata_rva = rdata_sec.virt_addr
    data_rva = data_sec.virt_addr
    bss_rva = bss_sec.virt_addr

    # Entry is start of .text
    pe.entry_rva = text_rva

    # Patch labels (rip32 + rel32)
    label_rva_map: Dict[str, int] = {}

    # .text internal labels
    for name, off in cg.asm.labels.items():
        label_rva_map[name] = text_rva + off

    # rdata labels
    for name, (off, ln) in cg.rdata.labels.items():
        label_rva_map[name] = rdata_rva + off

    # data labels
    for name, off in cg.data.labels.items():
        label_rva_map[name] = data_rva + off

    # bss labels (uninitialized data)
    if getattr(cg, 'bss', None) is not None:
        for name, off in cg.bss.labels.items():
            label_rva_map[name] = bss_rva + off

    # IAT symbols (generalized)
    #
    # build_idata() returns a mapping (dll, symbol) -> IAT entry RVA.
    #
    # We expose two label spellings:
    #   iat_<symbol>                 (backwards compatible with existing codegen)
    #   iat_<dllbase>_<symbol>       (disambiguated; recommended for extern calls)
    def _dll_base(dll: str) -> str:
        base = os.path.basename(dll).lower()
        if base.endswith('.dll'):
            base = base[:-4]
        # make it label-friendly (keep alnum + underscore)
        base = re.sub(r'[^a-z0-9_]', '_', base)
        return base or 'dll'

    for (dll, sym), rva in iat_symbol_rva.items():
        # Back-compat label
        label_rva_map.setdefault(f'iat_{sym}', rva)
        # Disambiguated label
        label_rva_map[f'iat_{_dll_base(dll)}_{sym}'] = rva
    # apply patches
    for pos, target, kind in cg.asm.patches:
        if target not in label_rva_map:
            raise RuntimeError(f"Unknown patch target: {target}")
        target_rva = label_rva_map[target]

        if kind == 'rip32':
            patch_end = pos + 4
            rip_at = text_rva + patch_end
            disp = (target_rva - rip_at) & 0xFFFFFFFF
            cg.asm.buf[pos:pos + 4] = u32(disp)

        elif kind == 'rel32':
            patch_end = pos + 4
            src_next = text_rva + patch_end
            disp = (target_rva - src_next) & 0xFFFFFFFF
            cg.asm.buf[pos:pos + 4] = u32(disp)

        else:
            raise RuntimeError(f"Unknown patch kind: {kind}")

    # update .text with patched bytes
    text_sec.data = bytearray(cg.asm.buf)

    exe = pe.build()
    with open(output_exe, 'wb') as f:
        f.write(exe)

    # Write combined listing for debugging (optional).
    # Order: optional PE header -> .text listing -> optional data dumps.
    if asm_listing and asm_listing_path:
        _write_combined_listing(
            asm_listing_path,
            cg=cg,
            pe=pe,
            exe_bytes=exe,
            text_rva=text_rva,
            rdata_rva=rdata_rva,
            data_rva=data_rva,
            idata_blob=bytes(idata_sec.data),
            idata_rva=idata_sec.virt_addr,
            label_rva_map=label_rva_map,
            show_addr=asm_show_addr,
            show_bytes=asm_show_bytes,
            show_text=asm_show_text,
            dump_data=asm_dump_data,
            dump_pe=asm_dump_pe,
        )

# ============================================================
# Listing extras (.rdata/.data dumps + PE header)
# ============================================================

def _hex_bytes(bs: bytes) -> str:
    return ' '.join(f'{b:02X}' for b in bs)

def _ascii_preview(bs: bytes) -> str:
    # printable ASCII preview ('.' for non-printable)
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in bs)

def _append_blob_dump(
    f,
    *,
    title: str,
    blob: bytes,
    base_addr: int,
    labels_at: Optional[Dict[int, List[str]]] = None,
    label_addr_map: Optional[Dict[str, int]] = None,
    show_addr: bool = True,
    show_bytes: bool = True,
    show_text: bool = True,
    addr_label: str = "RVA",
) -> None:
    if labels_at is None:
        labels_at = {}

    f.write('\n')
    f.write('; ============================================================\n')
    f.write(f'; {title}\n')
    f.write('; ============================================================\n')
    f.write(f'; base {addr_label}: 0x{base_addr:X}\n')
    f.write(f'; size: 0x{len(blob):X} bytes\n\n')

    if not (show_addr or show_bytes or show_text):
        show_text = True

    def emit_labels(off: int) -> None:
        if off not in labels_at:
            return
        for lab in labels_at[off]:
            a = label_addr_map.get(lab) if label_addr_map else None
            if a is None:
                f.write(f'{lab}: ; off=0x{off:X}\n')
            else:
                f.write(f'{lab}: ; off=0x{off:X} {addr_label.lower()}=0x{a:X}\n')

    for off in range(0, len(blob), 16):
        emit_labels(off)
        chunk = blob[off:off + 16]
        parts: List[str] = []
        if show_addr:
            parts.append(f'{(base_addr + off):08X}')
        if show_bytes:
            parts.append(f'{_hex_bytes(chunk):<48}')
        if show_text:
            db = ', '.join(f'0x{b:02X}' for b in chunk)
            parts.append(f'db {db}  ; |{_ascii_preview(chunk)}|')
        f.write('  '.join(parts) + '\n')

def _append_pe_dump(
    f,
    *,
    pe: "PEBuilder",
    exe_bytes: bytes,
    show_addr: bool = True,
    show_bytes: bool = True,
    show_text: bool = True,
) -> None:
    f.write('; ============================================================\n')
    f.write('; PE32+ HEADER (Windows x64)\n')
    f.write('; ============================================================\n')
    f.write(f'; image_base:        0x{pe.image_base:X}\n')
    f.write(f'; entry_rva:         0x{pe.entry_rva:X}\n')
    f.write(f'; section_alignment: 0x{pe.section_alignment:X}\n')
    f.write(f'; file_alignment:    0x{pe.file_alignment:X}\n')
    f.write(f'; import_dir:        rva=0x{pe.import_rva:X} size=0x{pe.import_size:X}\n')
    f.write('; sections:\n')
    for s in pe.sections:
        f.write(
            f';   {s.name:<7} rva=0x{s.virt_addr:X} vsz=0x{s.virt_size:X} '
            f'raw=0x{s.raw_addr:X} rsz=0x{s.raw_size:X} chars=0x{s.characteristics:X}\n'
        )

    # dump raw header bytes (file offsets)
    hdr_size = min((s.raw_addr for s in pe.sections), default=0x200)
    hdr_size = max(hdr_size, 0x80)  # at least DOS stub
    hdr = exe_bytes[:hdr_size]

    f.write('\n; --- raw headers hexdump (file offsets) ---\n\n')
    _append_blob_dump(
        f,
        title='PE FILE HEADERS (RAW)',
        blob=hdr,
        base_addr=0,
        labels_at=None,
        label_addr_map=None,
        show_addr=show_addr,
        show_bytes=show_bytes,
        show_text=show_text,
        addr_label='FILE',
    )

# ============================================================
# Combined listing writer
# ============================================================

def _write_combined_listing(
    path: str,
    *,
    cg: "Codegen",
    pe: "PEBuilder",
    exe_bytes: bytes,
    text_rva: int,
    rdata_rva: int,
    data_rva: int,
    idata_blob: bytes,
    idata_rva: int,
    label_rva_map: Dict[str, int],
    show_addr: bool,
    show_bytes: bool,
    show_text: bool,
    dump_data: bool,
    dump_pe: bool,
) -> None:
    """Write the final listing file in a stable, readable order.

    Order:
      1) Optional PE header + section table (+ raw header hexdump)
      2) .text instruction listing (+ patch list)
      3) Optional section dumps (.rdata/.data/.idata)
    """
    out = io.StringIO()

    if dump_pe:
        _append_pe_dump(
            out,
            pe=pe,
            exe_bytes=exe_bytes,
            show_addr=show_addr,
            show_bytes=show_bytes,
            show_text=show_text,
        )
        out.write('\n')

    # Render the .text listing into a temporary file, then splice it into our final output.
    fd, tmp_path = tempfile.mkstemp(prefix='mlc_text_', suffix='.asm')
    os.close(fd)
    try:
        cg.asm.write_listing(
            tmp_path,
            base_addr=text_rva,
            label_addr_map=label_rva_map,
            show_addr=show_addr,
            show_bytes=show_bytes,
            show_text=show_text,
        )
        with open(tmp_path, 'r', encoding='utf-8') as tf:
            out.write(tf.read())
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    if dump_data:
        # .rdata labels: offset -> [names]
        rdata_labels_at: Dict[int, List[str]] = {}
        for name, (off, _ln) in cg.rdata.labels.items():
            rdata_labels_at.setdefault(off, []).append(name)

        data_labels_at: Dict[int, List[str]] = {}
        for name, off in cg.data.labels.items():
            data_labels_at.setdefault(off, []).append(name)

        _append_blob_dump(
            out,
            title='.rdata (constants, strings, boxed consts)',
            blob=bytes(cg.rdata.data),
            base_addr=rdata_rva,
            labels_at=rdata_labels_at,
            label_addr_map=label_rva_map,
            show_addr=show_addr,
            show_bytes=show_bytes,
            show_text=show_text,
            addr_label='RVA',
        )
        _append_blob_dump(
            out,
            title='.data (writable globals, heap/gc state)',
            blob=bytes(cg.data.data),
            base_addr=data_rva,
            labels_at=data_labels_at,
            label_addr_map=label_rva_map,
            show_addr=show_addr,
            show_bytes=show_bytes,
            show_text=show_text,
            addr_label='RVA',
        )
        _append_blob_dump(
            out,
            title='.idata (imports/IAT)',
            blob=idata_blob,
            base_addr=idata_rva,
            labels_at={},
            label_addr_map=label_rva_map,
            show_addr=show_addr,
            show_bytes=show_bytes,
            show_text=show_text,
            addr_label='RVA',
        )

    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(out.getvalue())




# ============================================================
# CLI
# ============================================================

def _parse_asm_cols(spec: Optional[str]) -> tuple[bool, bool, bool]:
    # returns (show_addr, show_bytes, show_text)
    if spec is None:
        return True, True, True

    show_addr = show_bytes = show_text = False
    toks = [t.strip().lower() for t in spec.split(',') if t.strip()]
    for t in toks:
        if t in ('addr', 'address', 'a'):
            show_addr = True
        elif t in ('opcodes', 'bytes', 'b', 'opc'):
            show_bytes = True
        elif t in ('code', 'asm', 'text', 'c'):
            show_text = True
        else:
            raise ValueError(f"Unknown --asm-cols token: {t!r} (use addr,opcodes,code)")
    if not (show_addr or show_bytes or show_text):
        show_text = True
    return show_addr, show_bytes, show_text


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        prog='mlc_win64.py',
        description='MiniLang native compiler (Windows x64)',
    )
    parser.add_argument('input', help='input .ml file')
    parser.add_argument('output', help='output .exe file')

    parser.add_argument('-I', '--import-path', dest='include_dirs', action='append', default=[], metavar='DIR',
                        help='Add DIR to import search paths (may be repeated).')

    parser.add_argument('--keep-going', action='store_true', help='continue after errors and report multiple diagnostics')
    parser.add_argument('--max-errors', type=int, default=20, help='maximum diagnostics to report with --keep-going (default: 20)')

    g = parser.add_mutually_exclusive_group()
    g.add_argument('--asm', dest='asm', action='store_true', help='write .asm listing')
    g.add_argument('--no-asm', dest='asm', action='store_false', help='disable .asm listing (default)')
    # Default: no listing output unless --asm is passed.
    parser.set_defaults(asm=False)

    parser.add_argument('--asm-out', default=None, help='path for the .asm listing (default: output basename + .asm)')
    parser.add_argument('--asm-cols', default=None, help='comma-separated subset of addr,opcodes,code')
    parser.add_argument('--asm-no-addr', action='store_true', help='hide address column in listing')
    parser.add_argument('--asm-no-opcodes', action='store_true', help='hide opcode bytes column in listing')
    parser.add_argument('--asm-no-code', action='store_true', help='hide pseudo-assembly column in listing')
    parser.add_argument('--asm-data', action='store_true', help='include .rdata/.data/.idata dumps in the listing')
    parser.add_argument('--asm-pe', action='store_true', help='include PE header + section table dump in the listing')


    # Heap/GC configuration (optional)
    parser.add_argument('--heap-reserve', type=parse_size, default=None, help='reserve heap address space (e.g. 256m)')
    parser.add_argument('--heap-commit', type=parse_size, default=None, help='initial committed heap bytes (e.g. 16m)')
    parser.add_argument('--heap-grow', type=parse_size, default=None, help='minimum commit growth step (e.g. 1m)')
    parser.add_argument('--heap-shrink', action='store_true', help='enable decommit after GC (trim-from-top)')
    parser.add_argument('--heap-shrink-min', type=parse_size, default=None, help='minimum committed heap when shrinking (default: initial commit)')

    # GC configuration (optional)
    parser.add_argument('--gc-limit', type=parse_size, default=None, help='bytes allocated between GC collections (e.g. 16m)')
    parser.add_argument('--no-gc-periodic', action='store_true', help='disable periodic GC trigger (collect only on OOM)')


    # Call profiling (optional)
    parser.add_argument('--profile-calls', action='store_true', help='instrument user functions with call counters; enable callStats() builtin')

    # Debug tracing (optional)
    parser.add_argument('--trace-calls', action='store_true', help='print each entered function name to stderr (runtime trace)')

    args = parser.parse_args(argv[1:])

    inp = args.input
    out = args.output

    include_dirs: List[str] = []
    for d in getattr(args, 'include_dirs', []) or []:
        if not d:
            continue
        dp = os.path.realpath(os.path.abspath(d))
        if not os.path.isdir(dp):
            print(f'Import path not found or not a directory: {d}')
            return 1
        include_dirs.append(dp)

    if not os.path.isfile(inp):
        print(f'Input file not found: {inp}')
        return 1

    # resolve listing columns
    try:
        show_addr, show_bytes, show_text = _parse_asm_cols(args.asm_cols)
    except ValueError as e:
        print(f'Error: {e}')
        return 1

    if args.asm_no_addr:
        show_addr = False
    if args.asm_no_opcodes:
        show_bytes = False
    if args.asm_no_code:
        show_text = False
    if not (show_addr or show_bytes or show_text):
        show_text = True


    heap_config: Dict[str, Any] = {}
    if args.heap_reserve is not None:
        heap_config['reserve_bytes'] = int(args.heap_reserve)
    if args.heap_commit is not None:
        heap_config['commit_bytes'] = int(args.heap_commit)
    if args.heap_grow is not None:
        heap_config['grow_min_bytes'] = int(args.heap_grow)
    if args.heap_shrink:
        heap_config['shrink_enabled'] = True
    if args.heap_shrink_min is not None:
        heap_config['shrink_min_bytes'] = int(args.heap_shrink_min)


    # GC config
    if args.gc_limit is not None:
        heap_config['gc_bytes_limit'] = int(args.gc_limit)
    if getattr(args, 'no_gc_periodic', False):
        heap_config['gc_disable_periodic'] = True

    try:
        compile_to_exe(
            inp,
            out,
            include_dirs=include_dirs,
            asm_listing=bool(args.asm),
            asm_out=args.asm_out,
            asm_show_addr=show_addr,
            asm_show_bytes=show_bytes,
            asm_show_text=show_text,
            asm_dump_data=bool(args.asm_data),
            asm_dump_pe=bool(args.asm_pe),
            heap_config=heap_config,
            call_profile=bool(getattr(args, "profile_calls", False)),
            trace_calls=bool(getattr(args, "trace_calls", False)),
            keep_going=bool(getattr(args, "keep_going", False)),
            max_errors=int(getattr(args, "max_errors", 20) or 20),
        )

    except MultiCompileError as me:
        try:
            ml = load_minilang_frontend(inp)
            fmt = getattr(ml, "format_error", None)
        except Exception:
            fmt = None

        for d in me.diags:
            fn = d.filename or inp
            pos = d.pos
            if callable(fmt) and pos is not None:
                try:
                    src = d.source
                    if not isinstance(src, str):
                        src = open(fn, "r", encoding="utf-8").read()
                        src = normalize_code_for_tokenizer(src)
                    print(fmt(src, fn, pos, d.message, d.kind))
                    continue
                except Exception:
                    pass

            # Fallback (no caret formatting)
            if pos is not None:
                print(f"{d.kind}: {d.message}\n  at {fn} pos={pos}")
            else:
                if d.filename:
                    print(f"{d.kind}: {d.message}\n  at {fn}")
                else:
                    print(f"{d.kind}: {d.message}")

        if len(me.diags) >= int(getattr(args, "max_errors", 20) or 20):
            print(f"Note: stopped after {len(me.diags)} diagnostics (max-errors).")
        return 2

    except CompileError as e:
        try:
            ml = load_minilang_frontend(inp)
            fmt = getattr(ml, "format_error", None)
            fn = getattr(e, "filename", None) or inp
            pos = getattr(e, "pos", None)
            if callable(fmt) and pos is not None:
                src = open(fn, "r", encoding="utf-8").read()
                # Positions are computed on the normalized source (see frontend.normalize_code_for_tokenizer).
                src = normalize_code_for_tokenizer(src)
                print(fmt(src, fn, pos, str(e), "CompileError"))
            else:
                # still show something useful even without caret formatting
                if pos is not None:
                    print(f"CompileError: {e}\n  at {fn} pos={pos}")
                else:
                    print(f"CompileError: {e}")

        except Exception:
            # last-resort fallback
            fn = getattr(e, "filename", None) or inp
            pos = getattr(e, "pos", None)
            if pos is not None:
                print(f"CompileError: {e}\n  at {fn} pos={pos}")
            else:
                print(f"CompileError: {e}")
        return 2

    except Exception as e:
        # Catch ParseError (and similar position-bearing frontend errors) nicely.
        pos = getattr(e, "pos", None)
        fn = getattr(e, "filename", None) or inp
        kind = type(e).__name__

        if pos is not None:
            try:
                ml = load_minilang_frontend(inp)
                fmt = getattr(ml, "format_error", None)
                if callable(fmt):
                    # If the exception already carries the normalized source (set by frontend.parse_program),
                    # prefer that; otherwise normalize the on-disk text so caret positions match.
                    src = getattr(e, "source", None)
                    if not isinstance(src, str):
                        src = open(fn, "r", encoding="utf-8").read()
                        src = normalize_code_for_tokenizer(src)
                    print(fmt(src, fn, pos, str(e), kind))
                    return 2
            except Exception:
                pass

            # Fallback if formatter fails
            print(f"{kind}: {e}\n  at {fn} pos={pos}")
            return 2

        # Non-position exceptions: keep it clean (or print traceback if you have a flag)
        print(f"{kind}: {e}")
        return 2

    print(f"OK: wrote {out} (native x64 PE, MiniLang python compiler version v1.0)")
    if args.asm:
        asm_path = args.asm_out or (os.path.splitext(out)[0] + ".asm")
        print(f"OK: wrote {asm_path}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))