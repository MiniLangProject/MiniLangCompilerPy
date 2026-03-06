"""
MiniLang -> x86-64 machine code generation for Windows (PE32+).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .codegen_scope import VarBinding
from ..constants import (TAG_PTR, TAG_INT, TAG_VOID, TAG_ENUM, OBJ_STRING, OBJ_ARRAY, OBJ_BYTES, OBJ_FUNCTION,
                         OBJ_FLOAT, OBJ_STRUCT, OBJ_STRUCTTYPE, OBJ_BUILTIN, OBJ_ENV, OBJ_BOX, ERROR_STRUCT_ID,
                         ERR_VOID_OP, ERR_INDEX_OOB, ERR_INDEX_TYPE, ERR_INDEX_TARGET_TYPE,
                         ERR_PRINT_UNSUPPORTED, )
from ..context import BreakableCtx
from ..tools import align_up, enc_int, enc_bool, enc_void, align_to_mod

# ============================================================
# Constexpr / consteval helpers (Step 3)
# ============================================================

_CE_BINOPS = {'or', 'and', '|', '^', '&', '==', '!=', '>', '<', '>=', '<=', '<<', '>>', '+', '-', '*', '/', '%', }

_CE_UNOPS = {'-', '~', 'not'}


def _expr_to_qualname(ml: Any, expr: Any) -> Optional[str]:
    var_cls = getattr(ml, 'Var', None)
    mem_cls = getattr(ml, 'Member', None)
    if var_cls is not None and isinstance(expr, var_cls):
        nm = getattr(expr, 'name', None)
        return nm if isinstance(nm, str) else None
    if mem_cls is not None and isinstance(expr, mem_cls):
        base = _expr_to_qualname(ml, getattr(expr, 'target', None))
        seg = getattr(expr, 'name', None)
        if base is None or not isinstance(seg, str):
            return None
        return f"{base}.{seg}"
    return None


def _is_constexpr_expr(ml: Any, expr: Any) -> bool:
    if expr is None:
        return False
    for lit in ('Num', 'Str', 'Bool'):
        cls = getattr(ml, lit, None)
        if cls is not None and isinstance(expr, cls):
            return True
    var_cls = getattr(ml, 'Var', None)
    if var_cls is not None and isinstance(expr, var_cls):
        return True
    if _expr_to_qualname(ml, expr) is not None:
        return True
    un_cls = getattr(ml, 'Unary', None)
    if un_cls is not None and isinstance(expr, un_cls):
        op = getattr(expr, 'op', None)
        return (op in _CE_UNOPS) and _is_constexpr_expr(ml, getattr(expr, 'right', None))
    bin_cls = getattr(ml, 'Bin', None)
    if bin_cls is not None and isinstance(expr, bin_cls):
        op = getattr(expr, 'op', None)
        if op not in _CE_BINOPS:
            return False
        return _is_constexpr_expr(ml, getattr(expr, 'left', None)) and _is_constexpr_expr(ml,
                                                                                          getattr(expr, 'right', None))
    return False


class _ConstEvalError(Exception):
    pass


def _truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v != ''
    return bool(v)


def _eval_constexpr(ml: Any, expr: Any, env: Dict[str, Any]) -> Any:
    """Evaluate a constexpr expression to a Python value.

    This is intentionally conservative: if something cannot be resolved
    deterministically at compile-time, we raise _ConstEvalError.
    """
    if expr is None:
        raise _ConstEvalError('missing expr')

    num_cls = getattr(ml, 'Num', None)
    str_cls = getattr(ml, 'Str', None)
    bool_cls = getattr(ml, 'Bool', None)
    var_cls = getattr(ml, 'Var', None)
    mem_cls = getattr(ml, 'Member', None)
    un_cls = getattr(ml, 'Unary', None)
    bin_cls = getattr(ml, 'Bin', None)

    if num_cls is not None and isinstance(expr, num_cls):
        return getattr(expr, 'value', None)
    if str_cls is not None and isinstance(expr, str_cls):
        return getattr(expr, 'value', None)
    if bool_cls is not None and isinstance(expr, bool_cls):
        return bool(getattr(expr, 'value', False))

    if var_cls is not None and isinstance(expr, var_cls):
        nm = getattr(expr, 'name', None)
        if isinstance(nm, str) and nm in env:
            return env[nm]
        raise _ConstEvalError(f"unknown const '{nm}'")

    if mem_cls is not None and isinstance(expr, mem_cls):
        qn = _expr_to_qualname(ml, expr)
        if qn is not None and qn in env:
            return env[qn]
        raise _ConstEvalError(f"unknown const '{qn}'")

    if un_cls is not None and isinstance(expr, un_cls):
        op = getattr(expr, 'op', None)
        v = _eval_constexpr(ml, getattr(expr, 'right', None), env)
        if op == '-':
            if isinstance(v, bool):
                v = int(v)
            if isinstance(v, (int, float)):
                return -v
            raise _ConstEvalError('unary - expects number')
        if op == '~':
            if isinstance(v, bool):
                v = int(v)
            if isinstance(v, int):
                return (~v)
            raise _ConstEvalError('~ expects int')
        if op == 'not':
            return (not _truthy(v))
        raise _ConstEvalError(f"unsupported unary op {op}")

    if bin_cls is not None and isinstance(expr, bin_cls):
        # Special-case: enum auto-increment placeholders.
        # These are synthesized as (Prev + 1) with a marker attribute.
        # We must validate the previous value type BEFORE attempting '+'
        # so we can emit a stable, user-friendly error message.
        prev_qn = getattr(expr, '_ml_enum_autoinc_prev', None)
        if isinstance(prev_qn, str) and prev_qn:
            if prev_qn not in env:
                raise _ConstEvalError(f"enum auto-increment previous value not resolved: {prev_qn}")
            pv = env[prev_qn]
            if isinstance(pv, bool):
                pv = int(pv)
            if not isinstance(pv, int):
                # Marker string expected by Step-6 regression tests.
                raise _ConstEvalError(f"cannot auto-increment after non-int ({prev_qn})")
            return int(pv) + 1

        op = getattr(expr, 'op', None)
        a = _eval_constexpr(ml, getattr(expr, 'left', None), env)
        b = _eval_constexpr(ml, getattr(expr, 'right', None), env)

        # boolean ops
        if op == 'and':
            return _truthy(a) and _truthy(b)
        if op == 'or':
            return _truthy(a) or _truthy(b)

        # comparisons
        if op in ('==', '!=', '>', '<', '>=', '<='):
            if op == '==':
                return a == b
            if op == '!=':
                return a != b
            if op == '>':
                return a > b
            if op == '<':
                return a < b
            if op == '>=':
                return a >= b
            if op == '<=':
                return a <= b

        # arithmetic / bitwise
        if op in ('+', '-', '*', '/', '%', '|', '^', '&', '<<', '>>'):
            # normalize bool -> int for numeric contexts
            if isinstance(a, bool):
                a = int(a)
            if isinstance(b, bool):
                b = int(b)

            if op == '+':
                if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                    r = a + b
                    # normalize exact integral float to int (matches runtime normalize)
                    if isinstance(r, float) and r.is_integer():
                        return int(r)
                    return r
                if isinstance(a, str) and isinstance(b, str):
                    return a + b
                raise _ConstEvalError('+ expects both numbers or both strings')
            if op == '-':
                if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                    r = a - b
                    if isinstance(r, float) and r.is_integer():
                        return int(r)
                    return r
                raise _ConstEvalError('- expects numbers')
            if op == '*':
                if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                    r = a * b
                    if isinstance(r, float) and r.is_integer():
                        return int(r)
                    return r
                raise _ConstEvalError('* expects numbers')
            if op == '/':
                if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                    if b == 0:
                        raise _ConstEvalError('division by zero')
                    r = float(a) / float(b)
                    if r.is_integer():
                        return int(r)
                    return r
                raise _ConstEvalError('/ expects numbers')
            if op == '%':
                if isinstance(a, int) and isinstance(b, int):
                    if b == 0:
                        raise _ConstEvalError('mod by zero')
                    return a % b
                raise _ConstEvalError('% expects ints')
            if op in ('|', '^', '&'):
                if isinstance(a, int) and isinstance(b, int):
                    if op == '|':
                        return a | b
                    if op == '^':
                        return a ^ b
                    return a & b
                raise _ConstEvalError(f"{op} expects ints")
            if op in ('<<', '>>'):
                if isinstance(a, int) and isinstance(b, int):
                    if b < 0:
                        raise _ConstEvalError('negative shift')
                    if op == '<<':
                        return a << b
                    return a >> b
                raise _ConstEvalError('shift expects ints')

        raise _ConstEvalError(f"unsupported binop {op}")

    raise _ConstEvalError(f"unsupported expr {type(expr).__name__}")


def _pyval_to_lit_expr(ml: Any, v: Any) -> Any:
    """Convert a Python value from _eval_constexpr into a MiniLang literal Expr node."""
    if isinstance(v, bool):
        cls = getattr(ml, 'Bool', None)
        return cls(bool(v)) if cls is not None else v
    if isinstance(v, int) or isinstance(v, float):
        cls = getattr(ml, 'Num', None)
        return cls(v) if cls is not None else v
    if isinstance(v, str):
        cls = getattr(ml, 'Str', None)
        return cls(v) if cls is not None else v
    raise _ConstEvalError(f"unsupported const value type: {type(v).__name__}")


# ============================================================
# Const resolution for constexpr (Step 4)
# ============================================================

def _collect_constexpr_refs(ml: Any, expr: Any, out: set[str]) -> None:
    if expr is None:
        return
    var_cls = getattr(ml, 'Var', None)
    mem_cls = getattr(ml, 'Member', None)
    un_cls = getattr(ml, 'Unary', None)
    bin_cls = getattr(ml, 'Bin', None)

    if var_cls is not None and isinstance(expr, var_cls):
        nm = getattr(expr, 'name', None)
        if isinstance(nm, str) and nm:
            out.add(nm)
        return

    if mem_cls is not None and isinstance(expr, mem_cls):
        qn = _expr_to_qualname(ml, expr)
        if isinstance(qn, str) and qn:
            out.add(qn)
        return

    if un_cls is not None and isinstance(expr, un_cls):
        _collect_constexpr_refs(ml, getattr(expr, 'right', None), out)
        return

    if bin_cls is not None and isinstance(expr, bin_cls):
        _collect_constexpr_refs(ml, getattr(expr, 'left', None), out)
        _collect_constexpr_refs(ml, getattr(expr, 'right', None), out)
        return


def _resolve_const_binding_for_ref(cg: Any, ref: str, node: Any) -> tuple[str, Optional[VarBinding]]:
    'Resolve a constexpr identifier (possibly dotted) to a binding in current context.'
    try:
        ref0 = cg._apply_import_alias(str(ref))
    except Exception:
        ref0 = str(ref)

    cands: list[str] = []

    def add(x: str) -> None:
        if isinstance(x, str) and x and x not in cands:
            cands.append(x)

    add(ref0)

    qpref = getattr(cg, 'current_qname_prefix', '') or ''
    fpref = getattr(cg, 'current_file_prefix', '') or ''

    if isinstance(qpref, str) and qpref and not qpref.endswith('.'):
        qpref = qpref + '.'
    if isinstance(fpref, str) and fpref and not fpref.endswith('.'):
        fpref = fpref + '.'

    if '.' in ref0:
        if qpref and not ref0.startswith(qpref):
            add(qpref + ref0)
        if fpref and not ref0.startswith(fpref):
            add(fpref + ref0)
    else:
        try:
            qn = cg._qualify_identifier(ref0, node)
            add(qn)
        except Exception:
            pass
        if qpref:
            add(qpref + ref0)
        if fpref:
            add(fpref + ref0)

    b = None
    for cand in cands:
        try:
            b = cg.resolve_binding(cand)
        except Exception:
            b = None
        if b is not None:
            return cand, b
    return ref0, None


def _build_constexpr_env(cg: Any, expr: Any) -> Dict[str, Any]:
    'Build env mapping raw source refs -> python values from already-evaluated consts.'
    refs: set[str] = set()
    _collect_constexpr_refs(cg.ml, expr, refs)

    env: Dict[str, Any] = {}
    for ref in refs:
        _qn, b = _resolve_const_binding_for_ref(cg, ref, expr)
        if b is None:
            raise _ConstEvalError(f"unknown const '{ref}'")
        if not getattr(b, 'is_const', False):
            raise _ConstEvalError(f"'{ref}' is not const")
        pyv = getattr(b, 'const_value_py', None)
        if pyv is None:
            raise _ConstEvalError(f"const '{ref}' is not yet initialized")
        env[ref] = pyv
    return env


def _set_const_binding_value(cg: Any, b: VarBinding, pyv: Any) -> None:
    'Store compile-time constant value into a binding (for inlining).'
    b.const_value_py = pyv
    b.const_value_encoded = None
    b.const_value_label = None

    if isinstance(pyv, bool):
        b.const_value_encoded = int(enc_bool(bool(pyv)))
        return
    if isinstance(pyv, int):
        b.const_value_encoded = int(enc_int(int(pyv)))
        return

    if isinstance(pyv, float):
        lbl = f"cflt_{len(cg.rdata.labels)}"
        cg.rdata.add_obj_float(lbl, float(pyv))
        b.const_value_label = lbl
        return

    if isinstance(pyv, str):
        lbl = f"cstr_{len(cg.rdata.labels)}"
        cg.rdata.add_obj_string(lbl, str(pyv))
        b.const_value_label = lbl
        return

    raise _ConstEvalError(f"unsupported const value type: {type(pyv).__name__}")


class CodegenStmt:

    # ------------------------------------------------------------
    # Optimizer Step 4 helpers
    # ------------------------------------------------------------
    def _opt_try_truthy(self, expr: Any) -> Optional[bool]:
        """Return truthiness if `expr` is a foldable constant, else None."""
        try:
            v = self._opt_try_const_value(expr)  # provided by CodegenExpr mixin
        except Exception:
            return None
        if v is getattr(self, '_OPT_NO', object()):
            return None
        try:
            return bool(self._opt_truthy(v))
        except Exception:
            return None

    def _emit_stmt_list(self, stmts: list[Any]) -> None:
        """Emit a statement list and stop after an unconditional terminator."""
        ml = self.ml
        for st in stmts:
            self.emit_stmt(st)
            # Dead code elimination in the same block:
            # after return/break/continue nothing is reachable.
            if (hasattr(ml, 'Return') and isinstance(st, ml.Return)) or \
               (hasattr(ml, 'Break') and isinstance(st, ml.Break)) or \
               (hasattr(ml, 'Continue') and isinstance(st, ml.Continue)):
                break

    def _is_foreach_stmt(self, s: Any) -> bool:
        """Best-effort detection of 'for each' statements across frontend variants.

        Some frontends expose a dedicated class (ForEach/ForEachString/ForEachArray),
        others reuse a generic node. We detect by class name and by required fields.
        """
        tname = type(s).__name__
        tlow = tname.lower()
        if "foreach" in tlow:
            return True

        # Field-based heuristic: must have var + iterable + body
        if hasattr(s, "var") and hasattr(s, "iterable") and hasattr(s, "body"):
            # Exclude range-for variants that also have start/end/step
            if hasattr(s, "start") or hasattr(s, "end") or hasattr(s, "step"):
                return False
            return True

        return False

    def _foreach_var_name(self, s: Any) -> str:
        v = getattr(s, "var", None)
        # Prefer the scope normalizer if present
        if hasattr(self, "_coerce_name"):
            try:
                return self._coerce_name(v)  # type: ignore[attr-defined]
            except Exception:
                pass
        if isinstance(v, str):
            return v
        # Common token/ast fields
        for attr in ("name", "value", "text", "lexeme", "ident", "id", "var"):
            vv = getattr(v, attr, None)
            if isinstance(vv, str):
                return vv
        return str(v)

    # ------------------------------------------------------------
    # Step 6 (Closures) — Analysis only (6.0/6.1)
    #
    # We currently DO NOT generate closure environments yet, but we:
    #   - detect nested function definitions (so they aren't silently ignored)
    #   - compute per-function capture sets (free vars resolved to outer locals)
    #
    # The metadata is attached to FunctionDef nodes:
    #   _ml_locals: set[str]
    #   _ml_globals_declared: set[str]
    #   _ml_captures: set[str]
    #   _ml_capture_depth: dict[str,int]   # 1 = immediate parent, 2 = grandparent, ...
    #   _ml_nested_functions: list[FunctionDef]
    # ------------------------------------------------------------

    def _closure_collect_locals_and_nested(self, fn: Any) -> tuple[set[str], set[str], list[Any]]:
        """Collect locals (writes/loop vars/nested def names), global decls, and direct nested FunctionDef nodes."""
        ml = self.ml
        locals_set: set[str] = set(getattr(fn, 'params', []) or [])
        globals_decl: set[str] = set()
        nested: list[Any] = []

        def stmt_list(stmts: list[Any]) -> None:
            for st in stmts:
                if hasattr(ml, 'GlobalDecl') and isinstance(st, ml.GlobalDecl):
                    for nm in getattr(st, 'names', []) or []:
                        if isinstance(nm, str):
                            globals_decl.add(nm)
                    continue

                if hasattr(ml, 'Assign') and isinstance(st, ml.Assign):
                    name = getattr(st, 'name', None)
                    if isinstance(name, str) and name not in globals_decl:
                        locals_set.add(name)

                if hasattr(ml, 'For') and isinstance(st, ml.For):
                    v = getattr(st, 'var', None)
                    if isinstance(v, str):
                        locals_set.add(v)

                if self._is_foreach_stmt(st):
                    v = self._foreach_var_name(st)
                    if isinstance(v, str):
                        locals_set.add(v)

                if hasattr(ml, 'FunctionDef') and isinstance(st, ml.FunctionDef):
                    # direct nested function definition
                    nested.append(st)
                    nm = getattr(st, 'name', None)
                    if isinstance(nm, str):
                        locals_set.add(nm)
                    continue

                # descend into blocks (but NOT into nested function bodies)
                if hasattr(ml, 'If') and isinstance(st, ml.If):
                    stmt_list(getattr(st, 'then_body', []) or [])
                    for _, eb in (getattr(st, 'elifs', []) or []):
                        stmt_list(eb or [])
                    stmt_list(getattr(st, 'else_body', []) or [])
                elif hasattr(ml, 'While') and isinstance(st, ml.While):
                    stmt_list(getattr(st, 'body', []) or [])
                elif hasattr(ml, 'DoWhile') and isinstance(st, ml.DoWhile):
                    stmt_list(getattr(st, 'body', []) or [])
                elif hasattr(ml, 'For') and isinstance(st, ml.For):
                    stmt_list(getattr(st, 'body', []) or [])
                elif self._is_foreach_stmt(st):
                    stmt_list(getattr(st, 'body', []) or [])
                elif hasattr(ml, 'Switch') and isinstance(st, ml.Switch):
                    for cs in getattr(st, 'cases', []) or []:
                        stmt_list(getattr(cs, 'body', []) or [])
                    stmt_list(getattr(st, 'default_body', []) or [])

        stmt_list(list(getattr(fn, 'body', []) or []))
        return locals_set, globals_decl, nested

    def _closure_collect_uses(self, stmts: list[Any]) -> set[str]:
        """Collect variable reads in this statement list (does not descend into nested function bodies)."""
        ml = self.ml
        used: set[str] = set()

        def expr(e: Any) -> None:
            if e is None:
                return
            if hasattr(ml, 'Var') and isinstance(e, ml.Var):
                nm = getattr(e, 'name', None)
                if isinstance(nm, str):
                    used.add(nm)
                return
            if hasattr(ml, 'Unary') and isinstance(e, ml.Unary):
                expr(getattr(e, 'right', None))
                return
            if hasattr(ml, 'Bin') and isinstance(e, ml.Bin):
                expr(getattr(e, 'left', None))
                expr(getattr(e, 'right', None))
                return
            if hasattr(ml, 'Call') and isinstance(e, ml.Call):
                expr(getattr(e, 'callee', None))
                for aa in getattr(e, 'args', []) or []:
                    expr(aa)
                return
            if hasattr(ml, 'Index') and isinstance(e, ml.Index):
                expr(getattr(e, 'target', None))
                expr(getattr(e, 'index', None))
                return
            if hasattr(ml, 'Member') and isinstance(e, ml.Member):
                expr(getattr(e, 'target', None) or getattr(e, 'obj', None))
                return
            if hasattr(ml, 'ArrayLit') and isinstance(e, ml.ArrayLit):
                for it in getattr(e, 'items', []) or []:
                    expr(it)
                return
            # StructInit support (older frontends)
            if hasattr(ml, 'StructInit') and isinstance(e, ml.StructInit):
                for v in getattr(e, 'values', []) or []:
                    expr(v)
                return  # literals: Num/Str/Bool

        def stmt_list(sts: list[Any]) -> None:
            for st in sts:
                if hasattr(ml, 'FunctionDef') and isinstance(st, ml.FunctionDef):
                    # do NOT descend into nested function body for outer-use collection
                    continue
                if hasattr(ml, 'Assign') and isinstance(st, ml.Assign):
                    expr(getattr(st, 'expr', None))
                elif hasattr(ml, 'Print') and isinstance(st, ml.Print):
                    expr(getattr(st, 'expr', None))
                elif hasattr(ml, 'ExprStmt') and isinstance(st, ml.ExprStmt):
                    expr(getattr(st, 'expr', None))
                elif hasattr(ml, 'SetMember') and isinstance(st, ml.SetMember):
                    expr(getattr(st, 'obj', None) or getattr(st, 'target', None))
                    expr(getattr(st, 'expr', None))
                elif hasattr(ml, 'SetIndex') and isinstance(st, ml.SetIndex):
                    expr(getattr(st, 'target', None))
                    expr(getattr(st, 'index', None))
                    expr(getattr(st, 'expr', None))
                elif hasattr(ml, 'If') and isinstance(st, ml.If):
                    expr(getattr(st, 'cond', None))
                    stmt_list(getattr(st, 'then_body', []) or [])
                    for ec, eb in (getattr(st, 'elifs', []) or []):
                        expr(ec)
                        stmt_list(eb or [])
                    stmt_list(getattr(st, 'else_body', []) or [])
                elif hasattr(ml, 'While') and isinstance(st, ml.While):
                    expr(getattr(st, 'cond', None))
                    stmt_list(getattr(st, 'body', []) or [])
                elif hasattr(ml, 'DoWhile') and isinstance(st, ml.DoWhile):
                    stmt_list(getattr(st, 'body', []) or [])
                    expr(getattr(st, 'cond', None))
                elif hasattr(ml, 'For') and isinstance(st, ml.For):
                    expr(getattr(st, 'start', None))
                    expr(getattr(st, 'end', None))
                    stmt_list(getattr(st, 'body', []) or [])
                elif self._is_foreach_stmt(st):
                    expr(getattr(st, 'iterable', None))
                    stmt_list(getattr(st, 'body', []) or [])
                elif hasattr(ml, 'Switch') and isinstance(st, ml.Switch):
                    expr(getattr(st, 'expr', None))
                    for cs in getattr(st, 'cases', []) or []:
                        if getattr(cs, 'kind', None) == 'values':
                            for v in getattr(cs, 'values', []) or []:
                                expr(v)
                        else:
                            expr(getattr(cs, 'range_start', None))
                            expr(getattr(cs, 'range_end', None))
                        stmt_list(getattr(cs, 'body', []) or [])
                    stmt_list(getattr(st, 'default_body', []) or [])
                elif hasattr(ml, 'Return') and isinstance(st, ml.Return):
                    expr(getattr(st, 'expr', None))

        stmt_list(stmts)
        return used

    def _closure_collect_writes(self, stmts: list[Any]) -> set[str]:
        """Collect variable writes (Assign targets) in this statement list.

        Does not descend into nested function bodies.
        """
        ml = self.ml
        written: set[str] = set()

        def stmt_list(sts: list[Any]) -> None:
            for st in sts:
                if hasattr(ml, 'FunctionDef') and isinstance(st, ml.FunctionDef):
                    continue
                if hasattr(ml, 'Assign') and isinstance(st, ml.Assign):
                    nm = getattr(st, 'name', None)
                    if isinstance(nm, str):
                        written.add(nm)
                elif hasattr(ml, 'If') and isinstance(st, ml.If):
                    stmt_list(getattr(st, 'then_body', []) or [])
                    for _, eb in (getattr(st, 'elifs', []) or []):
                        stmt_list(eb or [])
                    stmt_list(getattr(st, 'else_body', []) or [])
                elif hasattr(ml, 'While') and isinstance(st, ml.While):
                    stmt_list(getattr(st, 'body', []) or [])
                elif hasattr(ml, 'DoWhile') and isinstance(st, ml.DoWhile):
                    stmt_list(getattr(st, 'body', []) or [])
                elif hasattr(ml, 'For') and isinstance(st, ml.For):
                    # loop var is a fresh local; do not treat it as a write-candidate for capture.
                    stmt_list(getattr(st, 'body', []) or [])
                elif self._is_foreach_stmt(st):
                    stmt_list(getattr(st, 'body', []) or [])
                elif hasattr(ml, 'Switch') and isinstance(st, ml.Switch):
                    for cs in getattr(st, 'cases', []) or []:
                        stmt_list(getattr(cs, 'body', []) or [])
                    stmt_list(getattr(st, 'default_body', []) or [])

        stmt_list(stmts)
        return written

    def _closure_collect_read_before_first_write(self, stmts: list[Any], params_set: set[str]) -> set[str]:
        """Collect names that are read before their first write within this function body.

        This is used to disambiguate "lexical assignment" (mutating an outer captured variable)
        from intentional shadowing via an initializing write in a nested function.

        Notes:
        - Does not descend into nested function bodies.
        - For assignments, reads from the RHS are considered to happen before the LHS write.
        """
        ml = self.ml
        read_before: set[str] = set()
        written_yet: set[str] = set(params_set)  # params count as already defined

        def note_reads(names: set[str]) -> None:
            for nm in names:
                if not isinstance(nm, str) or not nm:
                    continue
                if nm in written_yet:
                    continue
                read_before.add(nm)

        def expr_reads(e: Any, out: set[str]) -> None:
            if e is None:
                return
            if hasattr(ml, 'Var') and isinstance(e, ml.Var):
                nm = getattr(e, 'name', None)
                if isinstance(nm, str):
                    out.add(nm)
                return
            if hasattr(ml, 'Unary') and isinstance(e, ml.Unary):
                expr_reads(getattr(e, 'right', None), out)
                return
            if hasattr(ml, 'Bin') and isinstance(e, ml.Bin):
                expr_reads(getattr(e, 'left', None), out)
                expr_reads(getattr(e, 'right', None), out)
                return
            if hasattr(ml, 'Call') and isinstance(e, ml.Call):
                expr_reads(getattr(e, 'callee', None), out)
                for aa in getattr(e, 'args', []) or []:
                    expr_reads(aa, out)
                return
            if hasattr(ml, 'Index') and isinstance(e, ml.Index):
                expr_reads(getattr(e, 'target', None), out)
                expr_reads(getattr(e, 'index', None), out)
                return
            if hasattr(ml, 'Member') and isinstance(e, ml.Member):
                expr_reads(getattr(e, 'target', None) or getattr(e, 'obj', None), out)
                return
            if hasattr(ml, 'ArrayLit') and isinstance(e, ml.ArrayLit):
                for it in getattr(e, 'items', []) or []:
                    expr_reads(it, out)
                return
            if hasattr(ml, 'StructInit') and isinstance(e, ml.StructInit):
                for v in getattr(e, 'values', []) or []:
                    expr_reads(v, out)
                return  # literals: Num/Str/Bool

        def stmt_list(sts: list[Any]) -> None:
            for st in sts:
                if hasattr(ml, 'FunctionDef') and isinstance(st, ml.FunctionDef):
                    continue

                if hasattr(ml, 'Assign') and isinstance(st, ml.Assign):
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'expr', None), rr)
                    note_reads(rr)
                    nm = getattr(st, 'name', None)
                    if isinstance(nm, str):
                        written_yet.add(nm)
                    continue

                if hasattr(ml, 'Print') and isinstance(st, ml.Print):
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'expr', None), rr)
                    note_reads(rr)
                    continue

                if hasattr(ml, 'ExprStmt') and isinstance(st, ml.ExprStmt):
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'expr', None), rr)
                    note_reads(rr)
                    continue

                if hasattr(ml, 'SetMember') and isinstance(st, ml.SetMember):
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'obj', None) or getattr(st, 'target', None), rr)
                    expr_reads(getattr(st, 'expr', None), rr)
                    note_reads(rr)
                    continue

                if hasattr(ml, 'SetIndex') and isinstance(st, ml.SetIndex):
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'target', None), rr)
                    expr_reads(getattr(st, 'index', None), rr)
                    expr_reads(getattr(st, 'expr', None), rr)
                    note_reads(rr)
                    continue

                if hasattr(ml, 'If') and isinstance(st, ml.If):
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'cond', None), rr)
                    note_reads(rr)
                    stmt_list(getattr(st, 'then_body', []) or [])
                    for ec, eb in (getattr(st, 'elifs', []) or []):
                        rr2: set[str] = set()
                        expr_reads(ec, rr2)
                        note_reads(rr2)
                        stmt_list(eb or [])
                    stmt_list(getattr(st, 'else_body', []) or [])
                    continue

                if hasattr(ml, 'While') and isinstance(st, ml.While):
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'cond', None), rr)
                    note_reads(rr)
                    stmt_list(getattr(st, 'body', []) or [])
                    continue

                if hasattr(ml, 'DoWhile') and isinstance(st, ml.DoWhile):
                    stmt_list(getattr(st, 'body', []) or [])
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'cond', None), rr)
                    note_reads(rr)
                    continue

                if hasattr(ml, 'For') and isinstance(st, ml.For):
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'start', None), rr)
                    expr_reads(getattr(st, 'end', None), rr)
                    note_reads(rr)
                    v = getattr(st, 'var', None)
                    if isinstance(v, str):
                        written_yet.add(v)
                    stmt_list(getattr(st, 'body', []) or [])
                    continue

                if self._is_foreach_stmt(st):
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'iterable', None), rr)
                    note_reads(rr)
                    v = self._foreach_var_name(st)
                    if isinstance(v, str):
                        written_yet.add(v)
                    stmt_list(getattr(st, 'body', []) or [])
                    continue

                if hasattr(ml, 'Switch') and isinstance(st, ml.Switch):
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'expr', None), rr)
                    note_reads(rr)
                    for cs in getattr(st, 'cases', []) or []:
                        if getattr(cs, 'kind', None) == 'values':
                            for v in getattr(cs, 'values', []) or []:
                                rr2: set[str] = set()
                                expr_reads(v, rr2)
                                note_reads(rr2)
                        else:
                            rr2: set[str] = set()
                            expr_reads(getattr(cs, 'range_start', None), rr2)
                            expr_reads(getattr(cs, 'range_end', None), rr2)
                            note_reads(rr2)
                        stmt_list(getattr(cs, 'body', []) or [])
                    stmt_list(getattr(st, 'default_body', []) or [])
                    continue

                if hasattr(ml, 'Return') and isinstance(st, ml.Return):
                    rr: set[str] = set()
                    expr_reads(getattr(st, 'expr', None), rr)
                    note_reads(rr)
                    continue

        stmt_list(stmts)
        return read_before

    def _closure_analyze_function(self, fn: Any, outer_scopes: list[set[str]]) -> list[Any]:
        """Attach capture metadata to `fn` and recursively analyze nested functions.

        Returns a flat list of nested function nodes discovered under this function.
        """
        locals_set, globals_decl, nested = self._closure_collect_locals_and_nested(fn)
        body_stmts = list(getattr(fn, 'body', []) or [])
        uses = self._closure_collect_uses(body_stmts)
        writes = self._closure_collect_writes(body_stmts)

        params_set: set[str] = set(getattr(fn, 'params', []) or [])
        read_before_write = self._closure_collect_read_before_first_write(body_stmts, params_set)

        captures: set[str] = set()
        capture_depth: dict[str, int] = {}

        # If a nested function assigns to a name that exists in an outer lexical scope,
        # treat that as a capture (lexical assignment) rather than creating a new local.
        #
        # 6.2d-2 (Shadowing): allow intentional shadowing when the name is NOT read
        # before its first write in this function body.
        for name in list(writes):
            if not isinstance(name, str) or not name:
                continue
            if name in params_set:
                continue  # parameters always shadow
            if name in globals_decl:
                continue
            if '.' in name:
                continue
            if name not in read_before_write:
                continue  # initializing write => local shadowing
            for depth, scope in enumerate(outer_scopes, start=1):
                if name in scope:
                    locals_set.discard(name)
                    captures.add(name)
                    capture_depth[name] = depth
                    break

        for name in (uses | writes):
            if not isinstance(name, str) or not name:
                continue
            if name in locals_set:
                continue
            if name in globals_decl:
                continue
            if '.' in name:
                continue  # namespaced global

            if name in captures:
                continue

            # resolve into outer scopes
            for depth, scope in enumerate(outer_scopes, start=1):
                if name in scope:
                    captures.add(name)
                    capture_depth[name] = depth
                    break

        # attach metadata
        setattr(fn, '_ml_locals', locals_set)
        setattr(fn, '_ml_globals_declared', globals_decl)
        setattr(fn, '_ml_captures', captures)
        setattr(fn, '_ml_capture_depth', capture_depth)
        setattr(fn, '_ml_nested_functions', nested)

        found: list[Any] = []
        # recurse into nested functions (they see this function's locals as their nearest outer scope)
        for nf in nested:
            setattr(nf, '_ml_parent_fn', fn)
            found.append(nf)
            found.extend(self._closure_analyze_function(nf, [locals_set, *outer_scopes]))

        return found

    def _closure_analyze_program(self) -> list[Any]:
        """Analyze all top-level functions for nested defs and captures.

        Returns a flat list of ALL nested function nodes in the program.
        """
        nested_all: list[Any] = []
        for _, fn in list(getattr(self, 'user_functions', {}).items()):
            nested_all.extend(self._closure_analyze_function(fn, []))
        return nested_all

    def _closure_assign_env_layout(self, nested_fns: list[Any]) -> None:
        """Compute boxed vars and env slot indices for closure codegen.

        This is a *metadata-only* step (6.2b-2b-1):
        - For each function, determine which locals/params must be boxed because they are captured by nested functions.
        - Assign stable indices for those boxed variables in the owning function's environment frame.
        - For each nested function, compute the resolved capture_index for each captured name.
        """
        # initialize defaults on all known functions
        for fn in list(getattr(self, "user_functions", {}).values()) + list(
                getattr(self, "nested_user_functions", {}).values()):
            if not hasattr(fn, "_ml_boxed"):
                setattr(fn, "_ml_boxed", set())
            if not hasattr(fn, "_ml_env_slots"):
                setattr(fn, "_ml_env_slots", [])
            if not hasattr(fn, "_ml_env_index"):
                setattr(fn, "_ml_env_index", {})

        def _as_name(x: object) -> str:
            try:
                return self._coerce_name(x)  # provided by CodegenScope
            except Exception:
                return x if isinstance(x, str) else str(x)

        def _owner_for(nf: Any, depth: int) -> Any:
            # depth=1 => immediate parent; depth=2 => grandparent; etc.
            cur = getattr(nf, "_ml_parent_fn", None)
            if cur is None:
                return None
            for _ in range(max(0, depth - 1)):
                cur = getattr(cur, "_ml_parent_fn", None)
                if cur is None:
                    return None
            return cur

        # 1) mark boxed vars on owner functions
        for nf in nested_fns or []:
            caps = getattr(nf, "_ml_captures", set()) or set()
            cap_depth = getattr(nf, "_ml_capture_depth", {}) or {}
            for nm in caps:
                name = _as_name(nm)
                depth = int(cap_depth.get(name, 0) or 0)
                if depth <= 0:
                    continue
                owner = _owner_for(nf, depth)
                if owner is None:
                    raise self.error(f"Internal error: could not resolve owner for capture '{name}' (depth={depth})",
                                     nf)
                boxed = getattr(owner, "_ml_boxed", None)
                if not isinstance(boxed, set):
                    boxed = set()
                    setattr(owner, "_ml_boxed", boxed)
                boxed.add(name)

        # 2) assign env slot order/index per function
        for fn in list(getattr(self, "user_functions", {}).values()) + list(
                getattr(self, "nested_user_functions", {}).values()):
            boxed = getattr(fn, "_ml_boxed", set()) or set()
            if not isinstance(boxed, set):
                boxed = set(boxed)
            slots = sorted(_as_name(n) for n in boxed)
            setattr(fn, "_ml_env_slots", slots)
            setattr(fn, "_ml_env_index", {n: i for i, n in enumerate(slots)})

        # 3) compute resolved capture_index per nested function
        for nf in nested_fns or []:
            caps = getattr(nf, "_ml_captures", set()) or set()
            cap_depth = getattr(nf, "_ml_capture_depth", {}) or {}
            cap_idx: dict[str, int] = {}
            for nm in caps:
                name = _as_name(nm)
                depth = int(cap_depth.get(name, 0) or 0)
                owner = _owner_for(nf, depth)
                if owner is None:
                    raise self.error(f"Internal error: could not resolve owner for capture '{name}'", nf)
                env_index = getattr(owner, "_ml_env_index", {}) or {}
                if name not in env_index:
                    raise self.error(f"Internal error: capture '{name}' missing env index in owner function", nf)
                cap_idx[name] = int(env_index[name])
            setattr(nf, "_ml_capture_index", cap_idx)

        # 4) mark "env hop" functions
        #
        # Capture access codegen assumes that *every* function invocation has a current
        # environment object in r15, whose [env+8] points to the parent env.
        #
        # With env elision (6.2d-1), we may skip creating env objects for functions that
        # are not involved in closures. However, when a nested function captures a variable
        # from a grandparent or higher (capture_depth >= 2), every intermediate function on
        # that lexical chain MUST still materialize an (empty) env frame so capture_depth
        # hops remain correct.
        #
        # We mark those intermediate functions as _ml_env_hop.
        all_fns = list(getattr(self, "user_functions", {}).values()) + list(
            getattr(self, "nested_user_functions", {}).values())
        for fn in all_fns:
            setattr(fn, "_ml_env_hop", False)

        for nf in nested_fns or []:
            cap_depth = getattr(nf, "_ml_capture_depth", {}) or {}
            parent = getattr(nf, "_ml_parent_fn", None)
            if not isinstance(cap_depth, dict):
                continue
            for _, depth0 in cap_depth.items():
                try:
                    depth = int(depth0 or 0)
                except Exception:
                    depth = 0
                if depth <= 1:
                    continue
                cur = parent
                # mark depth-1 ancestors (exclude the owner at depth)
                for _i in range(depth - 1):
                    if cur is None:
                        break
                    setattr(cur, "_ml_env_hop", True)
                    cur = getattr(cur, "_ml_parent_fn", None)

    def _closure_declare_capture_bindings(self, fn: Any) -> None:
        """Install 'capture' bindings for this function into the current scope stack.

        This makes reads/writes of captured variables resolve to a synthetic VarBinding with:
          kind='capture', capture_depth, capture_index.
        Actual runtime behavior is implemented in Step 6.2b-2 (env objects + boxing).
        """
        caps = getattr(fn, "_ml_captures", set()) or set()
        if not isinstance(caps, set) or not caps:
            return
        cap_depth = getattr(fn, "_ml_capture_depth", {}) or {}
        cap_index = getattr(fn, "_ml_capture_index", {}) or {}

        # place in the current (function root) scope, but do not add to cleanup list
        for nm in sorted(caps):
            try:
                name = self._coerce_name(nm)
            except Exception:
                name = nm if isinstance(nm, str) else str(nm)

            depth = int(cap_depth.get(name, 0) or 0)
            idx = cap_index.get(name, None)
            if idx is None:
                raise self.error(f"Internal error: capture '{name}' missing index (Step 6.2b-2b-1)", fn)

            b = VarBinding(id=self._next_binding_id(), name=name, kind="capture", label=None, offset=None,
                depth=self.scope_depth, boxed=True,  # capture always points to a cell
                capture_depth=depth, capture_index=int(idx), decl_node=fn, )
            # make visible (do NOT add to declared/cleanup list)
            if not hasattr(self, "_scope_stack") or not self._scope_stack:
                raise self.error("Internal error: scope stack not initialized", fn)
            self._scope_stack[-1][name] = b

    def emit_stmt(self, s: Any) -> None:
        ml = self.ml

        # Track per-file package prefix for implicit name resolution.
        #
        # Declarations in `package X` files are qualified as `X.<name>` by the decl collector.
        # For ergonomics, unqualified references inside the same file should resolve to that
        # qualified symbol (unless shadowed by a local).
        try:
            fn = getattr(s, '_filename', None)
            if not (isinstance(fn, str) and fn):
                fn = getattr(self, '_current_fn_file', None)
            mp = getattr(self, 'file_prefix_map', None)
            if isinstance(fn, str) and fn and isinstance(mp, dict):
                self.current_file_prefix = mp.get(fn, '') or ''
                # Keep CodegenCore context aligned for package-local resolution.
                self._current_fn_file = fn
            else:
                self.current_file_prefix = ''
        except Exception:
            self.current_file_prefix = ''

        # Step 4: for top-level statements inside package/namespace,
        # apply the active prefix so unqualified name resolution works.
        try:
            if not bool(getattr(self, 'in_function', False)):
                ns_pref = getattr(s, '_ml_ns_prefix', None)
                if isinstance(ns_pref, str):
                    self.current_qname_prefix = ns_pref
                    if ns_pref:
                        self._current_fn_qname = ns_pref + '__toplevel__'
                    else:
                        self._current_fn_qname = None
        except Exception:
            pass
        # global x, y, z  (function-only; compile-time declaration)
        if hasattr(ml, 'GlobalDecl') and isinstance(s, ml.GlobalDecl):
            if not bool(getattr(self, "in_function", False)):
                raise self.error("'global' is only allowed inside functions", s)
            for nm in getattr(s, 'names', []) or []:
                if hasattr(self, 'declare_function_global'):
                    self.declare_function_global(nm, node=s)
                else:
                    raise self.error(
                        "Internal compiler error: missing declare_function_global (update codegen_scope.py).", s)
            return
        # struct Name are a,b,c end struct  (top-level only)
        if hasattr(ml, 'StructDef') and isinstance(s, ml.StructDef):
            if bool(getattr(self, 'in_function', False)):
                raise self.error('struct definitions are only allowed at top-level', s)
            # Structs are collected in emit_program(); nothing to emit here.
            return

        # enum Name are A,B,C end enum  (top-level only)
        if hasattr(ml, 'EnumDef') and isinstance(s, ml.EnumDef):
            if bool(getattr(self, 'in_function', False)):
                raise self.error('enum definitions are only allowed at top-level', s)
            # Enums are collected in emit_program(); nothing to emit here.
            return
        a = self.asm

        if hasattr(ml, 'NamespaceDecl') and isinstance(s, ml.NamespaceDecl):
            return

        if hasattr(ml, 'NamespaceDef') and isinstance(s, ml.NamespaceDef):
            return

        if hasattr(ml, 'ImportStmt') and isinstance(s, ml.ImportStmt):
            return

        if hasattr(ml, 'Import') and isinstance(s, ml.Import):
            return

        # const name = expr
        if hasattr(ml, 'ConstDecl') and isinstance(s, ml.ConstDecl):
            nm = getattr(s, 'name', None)
            if nm is None:
                nm = getattr(s, 'ident', None)
            nm_s = str(nm)
            # Qualify by current package/namespace context (if any)
            try:
                nm_q = self._qualify_identifier(nm_s, s)
            except Exception:
                nm_q = nm_s
            try:
                setattr(s, 'name', nm_q)
            except Exception:
                pass

            ex = getattr(s, 'expr', None)

            # Top-level/namespace const initializers must be constexpr.
            if not bool(getattr(self, 'in_function', False)):
                if not _is_constexpr_expr(self.ml, ex):
                    raise self.error(f"const initializer must be constexpr: {nm_q}", s)

            # Predeclare and mark const
            if hasattr(self, 'ensure_binding_for_write') and callable(getattr(self, 'ensure_binding_for_write')):
                b = self.ensure_binding_for_write(nm_q, node=s)
                setattr(b, 'is_const', True)
                setattr(b, 'const_expr', ex)

                # duplicate const in same scope
                if not bool(getattr(self, 'in_function', False)) and getattr(b, 'const_initialized', False):
                    raise self.error(f"duplicate const '{nm_q}'", s)

                # Step 4: evaluate compile-time const at top-level/namespace
                if not bool(getattr(self, 'in_function', False)):
                    try:
                        env = _build_constexpr_env(self, ex)
                        pyv = _eval_constexpr(self.ml, ex, env)

                        # Enforce stricter enum auto-increment semantics (must follow an int)
                        prev = getattr(ex, '_ml_enum_autoinc_prev', None)
                        if isinstance(prev, str) and prev:
                            _qn_prev, bprev = _resolve_const_binding_for_ref(self, prev, ex)
                            if bprev is None or getattr(bprev, 'const_value_py', None) is None:
                                raise _ConstEvalError(f"enum auto-increment previous value not resolved: {prev}")
                            if not isinstance(getattr(bprev, 'const_value_py', None), int):
                                raise _ConstEvalError(
                                    f"enum missing value cannot auto-increment after non-int ({prev})")

                        _set_const_binding_value(self, b, pyv)
                        b.const_initialized = True

                        # Replace initializer with a literal (for diagnostics / consistency)
                        try:
                            s.expr = _pyval_to_lit_expr(self.ml, pyv)
                        except Exception:
                            pass

                        # No runtime code needed for compile-time const
                        return
                    except _ConstEvalError as ex2:
                        raise self.error(f"const '{nm_q}' is not constexpr-evaluable: {ex2}", s)

            # Inside functions: const behaves like immutable variable (runtime init)
            self.emit_expr(ex)
            self.emit_store_var(nm_q, s)
            return

        if isinstance(s, ml.Assign):
            # Step 4: if this is a top-level/namespace initializer and constexpr-evaluable, fold it
            if not bool(getattr(self, 'in_function', False)) and _is_constexpr_expr(self.ml, getattr(s, 'expr', None)):
                try:
                    env = _build_constexpr_env(self, getattr(s, 'expr', None))
                    pyv = _eval_constexpr(self.ml, getattr(s, 'expr', None), env)
                    try:
                        s.expr = _pyval_to_lit_expr(self.ml, pyv)
                    except Exception:
                        pass
                except Exception:
                    pass
            self.emit_expr(s.expr)
            self.emit_store_var(s.name, s)
            return

        if isinstance(s, ml.Print):
            # If literal string: print directly
            if isinstance(s.expr, ml.Str):
                lbl = f"str_{len(self.rdata.labels)}"
                self.rdata.add_str(lbl, s.expr.value, add_newline=True)
                off, ln = self.rdata.labels[lbl]
                self.emit_writefile(lbl, ln)
                return

            # Otherwise evaluate expression into RAX and print int/bool
            self.emit_expr(s.expr)

            # Determine tag: r10 = rax & 7
            a.mov_r10_rax()
            a.and_r64_imm("r10", 7)

            lbl_int = f"print_int_{a.pos}"
            lbl_bool = f"print_bool_{a.pos}"
            lbl_enum = f"print_enum_{a.pos}"
            lbl_ptr = f"print_ptr_{a.pos}"
            lbl_void = f"print_void_{a.pos}"
            lbl_uns = f"print_uns_{a.pos}"
            lbl_end = f"print_end_{a.pos}"

            # tag == VOID?
            a.cmp_r64_imm("r10", TAG_VOID)
            a.jcc('e', lbl_void)

            # tag == INT?
            a.cmp_r64_imm("r10", 1)
            a.jcc('e', lbl_int)
            # tag == BOOL?
            a.cmp_r64_imm("r10", 2)
            a.jcc('e', lbl_bool)
            # tag == ENUM?
            a.cmp_r64_imm("r10", TAG_ENUM)
            a.jcc('e', lbl_enum)
            # tag == PTR?
            a.cmp_r64_imm("r10", 0)
            a.jcc('e', lbl_ptr)

            a.jmp(lbl_uns)

            # ---- void print ----
            a.mark(lbl_void)
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(s)
                except Exception:
                    pass
            self._emit_make_error_const(ERR_PRINT_UNSUPPORTED, "Cannot print void")
            self._emit_auto_errprop()
            a.jmp(lbl_end)

            # ---- enum print (convert to string) ----
            a.mark(lbl_enum)
            # rcx = enum value; call fn_value_to_string -> rax=OBJ_STRING*
            a.mov_r64_r64("rcx", "rax")
            a.call('fn_value_to_string')
            # print as string (no need to check type)
            # r8d = [rax+4] (len)
            a.mov_r32_membase_disp("r8d", "rax", 4)
            # rdx = rax+8 (ptr to bytes)
            a.lea_r64_membase_disp("rdx", "rax", 8)
            self.emit_writefile_ptr_len()
            self.emit_writefile('nl', 1)
            a.jmp(lbl_end)

            # ---- ptr print (boxed string / array) ----
            a.mark(lbl_ptr)
            # edx = [rax] (obj type)
            a.mov_r32_membase_disp("edx", "rax", 0)
            lbl_ptr_str = f"print_ptr_str_{a.pos}"
            lbl_ptr_arr = f"print_ptr_arr_{a.pos}"
            lbl_ptr_flt = f"print_ptr_flt_{a.pos}"
            lbl_ptr_bytes = f"print_ptr_bytes_{a.pos}"
            lbl_ptr_stt = f"print_ptr_stt_{a.pos}"

            # if type == OBJ_STRING
            a.cmp_r32_imm("edx", OBJ_STRING)
            a.jcc('e', lbl_ptr_str)

            # if type == OBJ_ARRAY
            a.cmp_r32_imm("edx", OBJ_ARRAY)
            a.jcc('e', lbl_ptr_arr)

            # if type == OBJ_FLOAT
            a.cmp_r32_imm("edx", OBJ_FLOAT)
            a.jcc('e', lbl_ptr_flt)

            # if type == OBJ_BYTES -> print "<bytes>"
            a.cmp_r32_imm("edx", OBJ_BYTES)
            a.jcc('e', lbl_ptr_bytes)

            # if type == OBJ_STRUCTTYPE (struct type / constructor value)
            a.cmp_r32_imm("edx", OBJ_STRUCTTYPE)
            a.jcc('e', lbl_ptr_stt)

            # unknown heap object
            a.jmp(lbl_uns)

            # ---- ptr structtype print ----
            a.mark(lbl_ptr_stt)
            a.lea_rax_rip('obj_type_struct')
            a.jmp(lbl_ptr_str)

            # ---- ptr string print ----
            a.mark(lbl_ptr_str)
            # r8d = [rax+4] (len)
            a.mov_r32_membase_disp("r8d", "rax", 4)
            # rdx = rax+8 (ptr to bytes)
            a.lea_r64_membase_disp("rdx", "rax", 8)
            self.emit_writefile_ptr_len()
            self.emit_writefile('nl', 1)
            a.jmp(lbl_end)

            # ---- ptr float print ----
            a.mark(lbl_ptr_flt)
            # xmm0 = double value
            a.movsd_xmm_membase_disp("xmm0", "rax", 8)  # movsd xmm0,[rax+8]
            # edx = digits
            a.mov_r32_imm32("edx", 15)  # mov edx,15
            # r8 = &floatbuf
            a.lea_rax_rip('floatbuf')
            a.mov_r64_r64("r8", "rax")  # mov r8,rax
            # call _gcvt(double, digits, buf)
            a.mov_rax_rip_qword('iat__gcvt')
            a.call_rax()
            # rax = c-string pointer
            a.mov_r11_rax()
            a.mov_r64_r64("rcx", "rax")  # mov rcx,rax
            a.call('fn_strlen')  # edx=len
            a.mov_r8d_edx()
            a.mov_r64_r64("rdx", "r11")  # mov rdx,r11
            self.emit_writefile_ptr_len()
            self.emit_writefile('nl', 1)
            a.jmp(lbl_end)

            # ---- ptr bytes print ----
            a.mark(lbl_ptr_bytes)
            a.lea_rax_rip('obj_bytes')
            a.jmp(lbl_ptr_str)

            # ---- ptr array print ----
            a.mark(lbl_ptr_arr)

            # r14 = array base (nonvolatile)
            a.mov_r64_r64("r14", "rax")  # mov r14,rax

            # print '['
            self.emit_writefile('lbrack', 1)

            # r13d = len  (nonvolatile)
            a.mov_r32_membase_disp("r13d", "r14", 4)  # mov r13d,[r14+4]
            # r12d = 0
            a.xor_r32_r32("r12d", "r12d")  # xor r12d,r12d

            lid2 = self.new_label_id()
            l_top = f"arrprint_top_{lid2}"
            l_done = f"arrprint_done_{lid2}"
            l_skip_comma = f"arrprint_skipcomma_{lid2}"

            a.mark(l_top)
            # if r12d >= r13d => done
            a.cmp_r32_r32("r12d", "r13d")  # cmp r12d,r13d
            a.jcc('ge', l_done)

            # rax = element [r14 + r12*8 + 8]
            # disp8 addressing requires ModRM mod=01 (0x44)
            a.mov_r64_r64("r11", "r12")  # r11 = index (r12 cannot be SIB index)
            a.mov_r64_mem_bis("rax", "r14", "r11", 8, 8)  # rax = [r14 + r11*8 + 8]
            # ---- print element (no newline) ----
            elem_id = self.new_label_id()
            el_int = f"arr_el_int_{elem_id}"
            el_bool = f"arr_el_bool_{elem_id}"
            el_enum = f"arr_el_enum_{elem_id}"
            el_ptr = f"arr_el_ptr_{elem_id}"
            el_uns = f"arr_el_uns_{elem_id}"
            el_end = f"arr_el_end_{elem_id}"

            # r10 = rax & 7
            a.mov_r10_rax()
            a.and_r64_imm("r10", 7)
            # int?
            a.cmp_r64_imm("r10", 1)
            a.jcc('e', el_int)
            # bool?
            a.cmp_r64_imm("r10", 2)
            a.jcc('e', el_bool)
            # enum?
            a.cmp_r64_imm("r10", TAG_ENUM)
            a.jcc('e', el_enum)
            # ptr?
            a.cmp_r64_imm("r10", 0)
            a.jcc('e', el_ptr)
            a.jmp(el_uns)

            a.mark(el_int)
            # rcx = rax ; call fn_int_to_dec
            a.mov_r64_r64("rcx", "rax")
            a.call('fn_int_to_dec')
            a.mov_r8d_edx()
            a.mov_rdx_rax()
            self.emit_writefile_ptr_len()
            a.jmp(el_end)

            a.mark(el_bool)
            a.test_rax_imm32(8)
            el_false = f"arr_el_false_{elem_id}"
            a.jcc('z', el_false)
            off, ln = self.rdata.labels['true_nn']
            self.emit_writefile('true_nn', ln)
            a.jmp(el_end)
            a.mark(el_false)
            off, ln = self.rdata.labels['false_nn']
            self.emit_writefile('false_nn', ln)
            a.jmp(el_end)

            a.mark(el_enum)
            # rcx = enum value; call fn_value_to_string -> rax=OBJ_STRING*
            a.mov_r64_r64("rcx", "rax")
            a.call('fn_value_to_string')
            # print as string (no newline)
            a.mov_r32_membase_disp("r8d", "rax", 4)  # r8d=[rax+4]
            a.lea_r64_membase_disp("rdx", "rax", 8)  # rdx=rax+8
            self.emit_writefile_ptr_len()
            a.jmp(el_end)

            a.mark(el_ptr)
            # edx = [rax] type
            a.mov_r32_membase_disp("edx", "rax", 0)
            # string?
            a.cmp_r32_imm("edx", OBJ_STRING)
            l_el_str = f"arr_el_str_{elem_id}"
            a.jcc('e', l_el_str)
            # array?
            a.cmp_r32_imm("edx", OBJ_ARRAY)
            l_el_arr = f"arr_el_arr_{elem_id}"
            a.jcc('e', l_el_arr)

            # bytes?
            a.cmp_r32_imm("edx", OBJ_BYTES)
            l_el_bytes = f"arr_el_bytes_{elem_id}"
            a.jcc('e', l_el_bytes)
            a.jmp(el_uns)

            a.mark(l_el_str)
            a.mov_r32_membase_disp("r8d", "rax", 4)  # r8d=[rax+4]
            a.lea_r64_membase_disp("rdx", "rax", 8)  # rdx=rax+8
            self.emit_writefile_ptr_len()
            a.jmp(el_end)

            a.mark(l_el_arr)
            off, ln = self.rdata.labels['array_nn']
            self.emit_writefile('array_nn', ln)
            a.jmp(el_end)

            a.mark(l_el_bytes)
            a.lea_rax_rip('obj_bytes')
            a.jmp(l_el_str)

            a.mark(el_uns)
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(s)
                except Exception:
                    pass
            self._emit_make_error_const(ERR_PRINT_UNSUPPORTED, "Cannot print unsupported array element")
            self._emit_auto_errprop()
            a.jmp(lbl_end)

            a.mark(el_end)

            # ---- element printed ----

            # i++
            a.inc_r32("r12d")  # inc r12d
            # if i == len: skip comma
            a.cmp_r32_r32("r12d", "r13d")
            a.jcc('e', l_skip_comma)
            self.emit_writefile('comma_sp', 2)
            a.mark(l_skip_comma)
            a.jmp(l_top)

            a.mark(l_done)
            self.emit_writefile('rbrack', 1)
            self.emit_writefile('nl', 1)
            a.jmp(lbl_end)

            # ---- fallback: print "<unsupported>\n" ----
            a.mark(lbl_uns)
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(s)
                except Exception:
                    pass
            self._emit_make_error_const(ERR_PRINT_UNSUPPORTED, "Cannot print unsupported value")
            self._emit_auto_errprop()
            a.jmp(lbl_end)

            # ---- int print ----
            a.mark(lbl_int)
            # call fn_int_to_dec(rcx=value)
            # rcx = rax
            a.mov_r64_r64("rcx", "rax")
            a.call('fn_int_to_dec')
            # returns rax=ptr, edx=len
            a.mov_r8d_edx()
            a.mov_rdx_rax()
            self.emit_writefile_ptr_len()
            # write newline
            self.emit_writefile('nl', 1)
            a.jmp(lbl_end)

            # ---- bool print ----
            a.mark(lbl_bool)
            # test bit3 (0x8): true if set
            a.test_rax_imm32(8)
            lbl_false = f"print_bool_false_{a.pos}"
            a.jcc('z', lbl_false)
            off, ln = self.rdata.labels['true_s']
            self.emit_writefile('true_s', ln)
            a.jmp(lbl_end)
            a.mark(lbl_false)
            off, ln = self.rdata.labels['false_s']
            self.emit_writefile('false_s', ln)

            a.mark(lbl_end)
            return

        if isinstance(s, ml.ExprStmt):
            # evaluate and discard
            self.emit_expr(s.expr)
            return

        if isinstance(s, ml.If):
            # Step 4: simplify constant conditions (safe subset).
            # We also drop leading constant-false branches and stop early on
            # constant-true branches.
            cases: list[tuple[Any, list[Any]]] = [(getattr(s, 'cond', None), getattr(s, 'then_body', []) or [])]
            for (c, b) in (getattr(s, 'elifs', []) or []):
                cases.append((c, b or []))
            else_body = getattr(s, 'else_body', []) or []

            # Scan from the top to remove constant branches.
            start_idx = 0
            while start_idx < len(cases):
                tv = self._opt_try_truthy(cases[start_idx][0])
                if tv is True:
                    self.push_scope()
                    self._emit_stmt_list(cases[start_idx][1])
                    self.pop_scope()
                    return
                if tv is False:
                    start_idx += 1
                    continue
                break

            # All branches were constant-false -> only else remains.
            if start_idx >= len(cases):
                self.push_scope()
                self._emit_stmt_list(else_body)
                self.pop_scope()
                return

            rem_cases = cases[start_idx:]

            lid = self.new_label_id()
            end_label = f"if_end_{lid}"

            for i, (cond, body) in enumerate(rem_cases):
                tv = self._opt_try_truthy(cond)
                if tv is False:
                    continue

                if tv is True:
                    # Unconditional branch (reachable only if earlier unknown branches were false).
                    self.push_scope()
                    self._emit_stmt_list(body)
                    self.pop_scope()
                    a.jmp(end_label)
                    break

                next_lbl = f"if_next_{lid}_{i}"
                self.emit_expr(cond)

                # Strict-void: using `void` as condition must raise an error.
                # (We intentionally keep `emit_jmp_if_false_rax` permissive for other call sites.)
                l_cond_ok = f"if_cond_ok_{lid}_{i}"
                a.mov_r64_r64("r10", "rax")
                a.and_r64_imm("r10", 7)
                a.cmp_r64_imm("r10", TAG_VOID)
                a.jcc('ne', l_cond_ok)
                self._emit_make_error_const(ERR_VOID_OP, "Cannot use void as condition")
                self._emit_auto_errprop()
                # If not propagated (top-level), still treat as false to continue control-flow safely.
                a.jmp(next_lbl)
                a.mark(l_cond_ok)

                self.emit_jmp_if_false_rax(next_lbl)
                self.push_scope()
                self._emit_stmt_list(body)
                self.pop_scope()
                a.jmp(end_label)
                a.mark(next_lbl)

            # else
            self.push_scope()
            self._emit_stmt_list(else_body)
            self.pop_scope()

            a.mark(end_label)
            return

        if isinstance(s, ml.Switch):
            # switch <expr>
            #   case <v1>[, <v2> ...] ... end case
            #   case <a> to <b> ... end case
            #   case default ... end case
            # end switch
            #
            # Semantics match the interpreter:
            # - The switch expression is evaluated once.
            # - The first matching case executes and the switch exits.
            # - break inside a switch exits the switch (break n bubbles outward).
            ml = self.ml
            a = self.asm

            sid = self.new_label_id()
            l_end = f"switch_end_{sid}"
            l_default = f"switch_default_{sid}"

            # Enter a breakable context for 'break' inside switch bodies.
            depth_before = self.scope_depth
            self.break_stack.append(
                BreakableCtx(kind='switch', break_label=l_end, break_depth=depth_before, continue_depth=depth_before))

            # Evaluate switch expression once and keep it in a non-volatile register (r12).
            # This avoids spilling into GC root slots, which would otherwise require extra
            # cleanup when `break n` jumps out past the switch.
            self.emit_expr(s.expr)
            a.mov_r64_r64("r12", "rax")  # r12 = switch value (tagged)

            # Pre-allocate labels for each case body so we can jump forward.
            case_body_labels = [f"switch_case_body_{sid}_{i}" for i in range(len(s.cases))]

            # --- match chain ---
            for i, cs in enumerate(s.cases):
                l_next = f"switch_case_next_{sid}_{i}"

                if cs.kind == 'values':
                    # multi-value case: if any value equals the switch value -> match
                    for j, ve in enumerate(cs.values):
                        l_val_next = f"switch_val_next_{sid}_{i}_{j}"

                        # eval case value -> rax
                        self.emit_expr(ve)
                        a.mov_r11_rax()  # keep case value safe

                        # rcx = switch_val ; rdx = case_val
                        a.mov_r64_r64("rcx", "r12")  # rcx = switch_val (tagged)
                        a.mov_r64_r64("rdx", "r11")  # mov rdx,r11

                        # rax = fn_val_eq(rcx, rdx)  (encoded bool)
                        a.call('fn_val_eq')

                        # if false -> next value
                        self.emit_jmp_if_false_rax(l_val_next)
                        # matched
                        a.jmp(case_body_labels[i])

                        a.mark(l_val_next)

                    # no value matched
                    a.jmp(l_next)

                elif cs.kind == 'range':
                    # range case: only for INT (not bool). inclusive between min/max.
                    # Evaluate bounds
                    rng_off = self.alloc_expr_temps(16)
                    lo_off = rng_off
                    hi_off = rng_off + 8

                    self.emit_expr(cs.range_start)
                    a.mov_rsp_disp32_rax(lo_off)
                    self.emit_expr(cs.range_end)
                    a.mov_rsp_disp32_rax(hi_off)

                    # r10 = lo ; r11 = hi
                    a.mov_r64_membase_disp("r10", "rsp", lo_off)  # mov r10,[rsp+lo_off]
                    a.mov_r64_membase_disp("r11", "rsp", hi_off)  # mov r11,[rsp+hi_off]

                    # Both bounds must be int-tagged, otherwise no-match (interpreter would error)
                    # r8 = r10 & 7
                    a.mov_r64_r64("r8", "r10")  # mov r8,r10
                    a.and_r64_imm("r8", 7)  # and r8,7
                    a.cmp_r64_imm("r8", 1)  # cmp r8,1
                    a.jcc('ne', l_next)

                    # r8 = r11 & 7
                    a.mov_r64_r64("r8", "r11")  # mov r8,r11
                    a.and_r64_imm("r8", 7)  # and r8,7
                    a.cmp_r64_imm("r8", 1)  # cmp r8,1
                    a.jcc('ne', l_next)

                    # Ensure r10 <= r11 (swap if needed)
                    l_noswap = f"switch_rng_noswap_{sid}_{i}"
                    a.cmp_r64_r64("r10", "r11")  # cmp r10,r11
                    a.jcc('le', l_noswap)
                    # swap via r8
                    a.mov_r64_r64("r8", "r10")  # mov r8,r10
                    a.mov_r64_r64("r10", "r11")  # mov r10,r11
                    a.mov_r64_r64("r11", "r8")  # mov r11,r8
                    a.mark(l_noswap)

                    # rax = switch_val (tagged) from r12
                    a.mov_r64_r64("rax", "r12")  # mov rax,r12

                    # switch value must be int-tagged
                    a.mov_r64_r64("r8", "rax")  # mov r8,rax
                    a.and_r64_imm("r8", 7)  # and r8,7
                    a.cmp_r64_imm("r8", 1)  # cmp r8,1
                    a.jcc('ne', l_next)

                    # if rax < r10 -> no match
                    a.cmp_r64_r64("rax", "r10")  # cmp rax,r10
                    a.jcc('l', l_next)

                    # if rax > r11 -> no match
                    a.cmp_r64_r64("rax", "r11")  # cmp rax,r11
                    a.jcc('g', l_next)

                    # matched
                    a.jmp(case_body_labels[i])

                    self.free_expr_temps(16)

                else:
                    # Unknown case kind -> treat as no-match
                    a.jmp(l_next)

                a.mark(l_next)

            # No case matched -> default or end
            if getattr(s, 'default_body', None):
                a.jmp(l_default)
            else:
                a.jmp(l_end)

            # --- case bodies ---
            for i, cs in enumerate(s.cases):
                a.mark(case_body_labels[i])
                self.push_scope()
                for st in cs.body:
                    self.emit_stmt(st)
                self.pop_scope()
                # No fallthrough: exit switch after first matched case.
                a.jmp(l_end)

            # --- default body ---
            a.mark(l_default)
            self.push_scope()
            for st in getattr(s, 'default_body', []) or []:
                self.emit_stmt(st)
            self.pop_scope()

            # --- exit ---
            a.mark(l_end)
            self.break_stack.pop()
            return

        if isinstance(s, ml.While):
            tv = self._opt_try_truthy(getattr(s, 'cond', None))
            # while false -> remove loop entirely
            if tv is False:
                return

            top = f"while_top_{a.pos}"
            end = f"while_end_{a.pos}"

            depth_before = self.scope_depth
            self.break_stack.append(
                BreakableCtx(kind='loop', break_label=end, continue_label=top, break_depth=depth_before,
                             continue_depth=depth_before))

            a.mark(top)

            # while true -> skip condition evaluation
            if tv is not True:
                self.emit_expr(s.cond)

                # Strict-void: using `void` as condition must raise an error.
                l_wcond_ok = f"while_cond_ok_{a.pos}"
                a.mov_r64_r64("r10", "rax")
                a.and_r64_imm("r10", 7)
                a.cmp_r64_imm("r10", TAG_VOID)
                a.jcc('ne', l_wcond_ok)
                self._emit_make_error_const(ERR_VOID_OP, "Cannot use void as condition")
                self._emit_auto_errprop()
                # If not propagated, exit the loop.
                a.jmp(end)
                a.mark(l_wcond_ok)

                self.emit_jmp_if_false_rax(end)

            self.push_scope()
            self._emit_stmt_list(getattr(s, 'body', []) or [])
            self.pop_scope()

            a.jmp(top)
            a.mark(end)

            self.break_stack.pop()
            return

        if isinstance(s, ml.DoWhile):
            tv = self._opt_try_truthy(getattr(s, 'cond', None))

            top = f"dowhile_top_{a.pos}"
            check = f"dowhile_check_{a.pos}"
            end = f"dowhile_end_{a.pos}"

            # In do-while, the body runs at least once, and continue jumps to the condition check.
            depth_before = self.scope_depth
            self.break_stack.append(
                BreakableCtx(kind='loop', break_label=end, continue_label=check, break_depth=depth_before,
                             continue_depth=depth_before))

            a.mark(top)
            self.push_scope()
            self._emit_stmt_list(getattr(s, 'body', []) or [])
            self.pop_scope()

            a.mark(check)
            if tv is True:
                # loop ... while true
                a.jmp(top)
            elif tv is False:
                # loop ... while false
                a.jmp(end)
            else:
                self.emit_expr(s.cond)

                # Strict-void: using `void` as condition must raise an error.
                l_dwcond_ok = f"dowhile_cond_ok_{a.pos}"
                a.mov_r64_r64("r10", "rax")
                a.and_r64_imm("r10", 7)
                a.cmp_r64_imm("r10", TAG_VOID)
                a.jcc('ne', l_dwcond_ok)
                self._emit_make_error_const(ERR_VOID_OP, "Cannot use void as condition")
                self._emit_auto_errprop()
                # If not propagated, exit the loop.
                a.jmp(end)
                a.mark(l_dwcond_ok)

                self.emit_jmp_if_false_rax(end)
                a.jmp(top)

            a.mark(end)
            self.break_stack.pop()
            return

        if isinstance(s, ml.For):
            # inclusive for, supports up/down
            top = f"for_top_{a.pos}"
            cont = f"for_cont_{a.pos}"
            end = f"for_end_{a.pos}"

            # Loop variable is an implicit *fresh* declaration in a dedicated loop scope.
            depth_outer = self.scope_depth
            self.push_scope()
            loop_depth = self.scope_depth
            if hasattr(self, "declare_fresh_binding"):
                self.declare_fresh_binding(s.var, node=s)

            self.break_stack.append(
                BreakableCtx(kind='loop', break_label=end, continue_label=cont, break_depth=depth_outer,
                             continue_depth=loop_depth))

            end_lbl = self.ensure_var(f"__for_end_{a.pos}")
            step_lbl = self.ensure_var(f"__for_step_{a.pos}")

            # init var = start
            self.emit_expr(s.start)
            self.emit_store_var(s.var, s)

            # store end
            self.emit_expr(s.end)
            a.mov_rip_qword_rax(end_lbl)

            # determine step based on start <= end
            # compare tagged var and end (monotonic)
            self.emit_load_var(s.var)
            a.mov_r10_rax()
            a.mov_rax_rip_qword(end_lbl)
            a.cmp_r64_r64("rax", "r10")  # cmp rax, r10  (end ? start)
            # if end >= start => step=+1 else -1
            lbl_step_pos = f"for_step_pos_{a.pos}"
            lbl_step_done = f"for_step_done_{a.pos}"
            a.jcc('ge', lbl_step_pos)
            a.mov_rax_imm64(enc_int(-1))
            a.mov_rip_qword_rax(step_lbl)
            a.jmp(lbl_step_done)
            a.mark(lbl_step_pos)
            a.mov_rax_imm64(enc_int(1))
            a.mov_rip_qword_rax(step_lbl)
            a.mark(lbl_step_done)

            a.mark(top)
            # body
            self.push_scope()
            for st in s.body:
                self.emit_stmt(st)
            self.pop_scope()

            a.mark(cont)
            # if var == end -> end loop
            self.emit_load_var(s.var)
            a.mov_r10_rax()
            a.mov_rax_rip_qword(end_lbl)
            a.cmp_rax_r10()
            a.jcc('e', end)

            # var = var + step (tag-add) => (a+b)-1
            self.emit_load_var(s.var)
            a.mov_r10_rax()
            a.mov_rax_rip_qword(step_lbl)
            a.add_rax_r10()
            a.sub_rax_imm8(1)
            self.emit_store_var(s.var, s)

            a.jmp(top)
            a.mark(end)

            self.break_stack.pop()
            self.pop_scope()
            return

        if hasattr(ml, 'SetMember') and isinstance(s, ml.SetMember):
            # obj.field = expr
            #
            # Step 5: If the left side is a dotted identifier chain whose *root* is NOT a
            # bound variable, treat it as a qualified global variable write (namespace/package).
            # Example: std.fs.tmp = 1  -> store into global 'std.fs.tmp'
            obj_expr = getattr(s, 'obj', getattr(s, 'target', None))
            field = getattr(s, 'field', None)
            if field is None:
                field = getattr(s, 'name', None)
            field = str(field)

            def _dotted_name(e):
                if isinstance(e, ml.Var):
                    return getattr(e, 'name', None)
                if isinstance(e, ml.Member):
                    left = _dotted_name(getattr(e, 'target', None))
                    if not isinstance(left, str) or not left:
                        return None
                    return left + '.' + str(getattr(e, 'name', None))
                return None

            qobj = _dotted_name(obj_expr)
            if isinstance(qobj, str) and qobj:
                root = qobj.split('.', 1)[0]
                bound = False
                try:
                    bound = (self.resolve_binding(root) is not None)
                except Exception:
                    bound = False
                if not bound:
                    full = qobj + '.' + field
                    if hasattr(self, '_apply_import_alias'):
                        full = self._apply_import_alias(full)
                    # Evaluate RHS -> RAX and store directly into existing global.
                    self.emit_expr(getattr(s, 'expr', None))
                    if hasattr(self, 'emit_store_existing_global'):
                        self.emit_store_existing_global(full, s)
                    else:
                        raise self.error('Internal compiler error: missing emit_store_existing_global (Step 5).', s)
                    return

            # Struct field write fallback (runtime checked)
            # Evaluate object expression first (may include calls), keep in non-volatile reg r12
            self.emit_expr(obj_expr)
            a.mov_r64_r64("r12", "rax")

            # Evaluate value, keep in non-volatile reg r13
            self.emit_expr(getattr(s, 'expr', None))
            a.mov_r64_r64("r13", "rax")

            fid = self.new_label_id()
            l_fail = f"setm_fail_{fid}"
            l_ok = f"setm_ok_{fid}"
            l_done = f"setm_done_{fid}"

            # Tag check: only pointers can be structs
            a.mov_r64_r64("r10", "r12")
            a.and_r64_imm("r10", 7)
            a.cmp_r64_imm("r10", TAG_PTR)
            a.jcc("ne", l_fail)

            # type check
            a.mov_r32_membase_disp("edx", "r12", 0)  # mov edx,[r12]
            a.cmp_r32_imm("edx", OBJ_STRUCT)
            a.jcc("ne", l_fail)

            # load struct_id (u32) into edx
            a.mov_r32_membase_disp("edx", "r12", 8)  # mov edx,[r12+8]

            field = getattr(s, 'field', None)
            if field is None:
                field = getattr(s, 'name', None)
            field = str(field)

            # Shared dispatch: sets ECX=index and jumps to l_ok on match
            self.emit_struct_field_index_dispatch(field, 'edx', 'ecx', l_ok, l_fail, tag=f"setm_{fid}")

            a.mark(l_ok)
            # store value: [obj + 16 + rcx*8] = r13
            a.mov_mem_bis_r64('r12', 'rcx', 8, 16, 'r13')
            a.jmp(l_done)

            a.mark(l_fail)
            # no-op on failure
            a.mark(l_done)
            return

        if isinstance(s, ml.SetIndex):
            # target[index] = expr (strict)
            # Runtime errors on invalid target/index/rhs (catchable via try()).

            lid = self.new_label_id()
            l_rhs_void = f"seti_rhs_void_{lid}"
            l_bad_target = f"seti_bad_target_{lid}"
            l_bad_index = f"seti_bad_index_{lid}"
            l_oob = f"seti_oob_{lid}"
            l_bad_byte = f"seti_bad_byte_{lid}"
            l_done = f"seti_done_{lid}"

            # --- eval target (spill so index/expr can't clobber) ---
            self.emit_expr(s.target)
            base_off = self.alloc_expr_temps(8)
            a.mov_rsp_disp32_rax(base_off)

            # --- eval index (keep tagged value) ---
            self.emit_expr(s.index)
            idx_off = self.alloc_expr_temps(8)
            a.mov_rsp_disp32_rax(idx_off)

            # --- eval rhs ---
            self.emit_expr(s.expr)
            a.mov_r64_r64("r10", "rax")  # rhs

            # restore base + tagged index
            a.mov_r64_membase_disp("r11", "rsp", base_off)
            a.mov_rax_rsp_disp32(idx_off)

            # free temps (clears stack roots to void)
            self.free_expr_temps(16)

            # rhs must not be VOID
            a.cmp_r64_imm("r10", enc_void())
            a.jcc('e', l_rhs_void)

            # target must be TAG_PTR and non-null
            a.mov_r64_r64("r8", "r11")
            a.and_r64_imm("r8", 7)
            a.cmp_r64_imm("r8", TAG_PTR)
            a.jcc('ne', l_bad_target)
            a.test_r64_r64("r11", "r11")
            a.jcc('e', l_bad_target)

            # target type must be OBJ_ARRAY or OBJ_BYTES
            a.mov_r32_membase_disp("edx", "r11", 0)
            l_type_ok = f"seti_type_ok_{lid}"
            a.cmp_r32_imm("edx", OBJ_ARRAY)
            a.jcc('e', l_type_ok)
            a.cmp_r32_imm("edx", OBJ_BYTES)
            a.jcc('e', l_type_ok)
            a.jmp(l_bad_target)
            a.mark(l_type_ok)

            # index must be TAG_INT
            a.mov_r64_r64("r8", "rax")
            a.and_r64_imm("r8", 7)
            a.cmp_r64_imm("r8", TAG_INT)
            a.jcc('ne', l_bad_index)

            # rcx = decoded index
            a.mov_r64_r64("rcx", "rax")
            a.sar_r64_imm8("rcx", 3)

            # bounds check (with negative index support):
            #   if idx < 0 => idx += len
            #   then require 0 <= idx < len
            a.mov_r32_membase_disp("edx", "r11", 4)  # len
            l_ok = f"seti_ok_{lid}"
            a.cmp_r32_imm("ecx", 0)
            a.jcc('ge', l_ok)
            a.add_r32_r32("ecx", "edx")
            a.mark(l_ok)
            a.cmp_r32_imm("ecx", 0)
            a.jcc('l', l_oob)
            a.cmp_r32_r32("ecx", "edx")
            a.jcc('ge', l_oob)

            # store:
            # - array:  [r11 + rcx*8 + 8] = r10
            # - bytes:  byte [r11 + rcx + 8] = (rhs int 0..255)
            l_store_bytes = f"seti_store_bytes_{lid}"
            # IMPORTANT: EDX currently holds the *length* (loaded from [r11+4]).
            # Reload the object type before deciding the store mode.
            a.mov_r32_membase_disp("edx", "r11", 0)
            a.cmp_r32_imm("edx", OBJ_BYTES)
            a.jcc('e', l_store_bytes)

            # array store
            a.mov_mem_bis_r64("r11", "rcx", 8, 8, "r10")
            a.jmp(l_done)

            # bytes store
            a.mark(l_store_bytes)

            # rhs must be TAG_INT
            a.mov_r64_r64("r8", "r10")
            a.and_r64_imm("r8", 7)
            a.cmp_r64_imm("r8", TAG_INT)
            a.jcc('ne', l_bad_byte)

            # rax = decoded rhs
            a.mov_r64_r64("rax", "r10")
            a.sar_r64_imm8("rax", 3)
            a.cmp_r64_imm("rax", 0)
            a.jcc('l', l_bad_byte)
            a.cmp_r64_imm("rax", 255)
            a.jcc('g', l_bad_byte)

            # addr = r11 + 8 + idx
            a.mov_r64_r64("r8", "r11")
            a.add_r64_r64("r8", "rcx")
            a.add_r64_imm("r8", 8)

            # store byte
            a.mov_membase_disp_r8("r8", 0, "al")
            a.jmp(l_done)

            # ---- error paths ----
            a.mark(l_rhs_void)
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(s)
                except Exception:
                    pass
            self._emit_make_error_const(ERR_VOID_OP, "Cannot assign void via index")
            self._emit_auto_errprop()
            a.jmp(l_done)

            a.mark(l_bad_target)
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(s)
                except Exception:
                    pass
            self._emit_make_error_const(ERR_INDEX_TARGET_TYPE, "Index assignment requires array or bytes")
            self._emit_auto_errprop()
            a.jmp(l_done)

            a.mark(l_bad_index)
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(s)
                except Exception:
                    pass
            self._emit_make_error_const(ERR_INDEX_TYPE, "Index must be an int")
            self._emit_auto_errprop()
            a.jmp(l_done)

            a.mark(l_oob)
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(s)
                except Exception:
                    pass
            self._emit_make_error_const(ERR_INDEX_OOB, "Array index out of bounds")
            self._emit_auto_errprop()
            a.jmp(l_done)

            a.mark(l_bad_byte)
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(s)
                except Exception:
                    pass
            self._emit_make_error_const(ERR_VOID_OP, "Byte value must be an int in range 0..255")
            self._emit_auto_errprop()

            a.mark(l_done)
            return

        if self._is_foreach_stmt(s):
            # for each <var> in <iterable>  (arrays + strings + bytes)
            fid = self.new_label_id()
            it_lbl = f"__foreach_it_{fid}"
            i_lbl = f"__foreach_i_{fid}"

            self.data.add_u64(it_lbl, 0)
            self.data.add_u32(i_lbl, 0)

            # it = iterable
            self.emit_expr(s.iterable)
            a.mov_rip_qword_rax(it_lbl)

            # i = 0
            a.xor_r32_r32("eax", "eax")  # xor eax,eax
            a.mov_rip_dword_eax(i_lbl)

            top = f"foreach_top_{fid}"
            body = f"foreach_body_{fid}"
            cont = f"foreach_cont_{fid}"
            end = f"foreach_end_{fid}"

            l_arr = f"foreach_is_arr_{fid}"
            l_bytes = f"foreach_is_bytes_{fid}"
            l_str = f"foreach_is_str_{fid}"
            # Loop variable name
            var_name = self._foreach_var_name(s)

            # Loop variable is an implicit *fresh* declaration in a dedicated loop scope.
            depth_outer = self.scope_depth
            self.push_scope()
            loop_depth = self.scope_depth
            if hasattr(self, "declare_fresh_binding"):
                self.declare_fresh_binding(var_name, node=s)
            elif hasattr(self, "ensure_binding_for_write"):
                self.ensure_binding_for_write(var_name, node=s)

            self.break_stack.append(
                BreakableCtx(kind='loop', break_label=end, continue_label=cont, break_depth=depth_outer,
                             continue_depth=loop_depth))

            a.mark(top)
            # ecx = i
            a.mov_eax_rip_dword(i_lbl)
            a.mov_r32_r32("ecx", "eax")  # mov ecx,eax

            # r14 = it
            a.mov_rax_rip_qword(it_lbl)
            a.mov_r64_r64("r14", "rax")  # mov r14,rax

            # edx = [r14] (obj type)
            a.mov_r32_membase_disp("edx", "r14", 0)  # mov edx,[r14]
            # if array
            a.cmp_r32_imm("edx", OBJ_ARRAY)
            a.jcc('e', l_arr)
            # if bytes
            a.cmp_r32_imm("edx", OBJ_BYTES)
            a.jcc('e', l_bytes)
            # if string
            a.cmp_r32_imm("edx", OBJ_STRING)
            a.jcc('e', l_str)
            # unsupported iterable => end
            a.jmp(end)

            # ---- array path ----
            a.mark(l_arr)
            # edx = len(arr)
            a.mov_r32_membase_disp("edx", "r14", 4)  # mov edx,[r14+4]
            # if i >= len => end
            a.cmp_r32_r32("ecx", "edx")  # cmp ecx,edx
            a.jcc('ge', end)
            # load element rax = [r14 + rcx*8 + 8]
            a.mov_r64_mem_bis("rax", "r14", "rcx", 8, 8)
            # assign loop var
            self.emit_store_var(var_name, s)
            a.jmp(body)

            # ---- bytes path ----
            a.mark(l_bytes)
            # edx = len(bytes)
            a.mov_r32_membase_disp("edx", "r14", 4)
            # if i >= len => end
            a.cmp_r32_r32("ecx", "edx")
            a.jcc('ge', end)

            # addr = r14 + 8 + i
            a.mov_r64_r64("rax", "r14")
            a.add_r64_r64("rax", "rcx")
            a.add_rax_imm8(8)
            # eax = byte [rax]
            a.movzx_r32_membase_disp("eax", "rax", 0)
            # tag int
            a.shl_rax_imm8(3)
            a.or_rax_imm8(TAG_INT)

            # assign loop var
            self.emit_store_var(var_name, s)
            a.jmp(body)
            # ---- string path ----
            a.mark(l_str)
            # edx = len(str)
            a.mov_r32_membase_disp("edx", "r14", 4)  # mov edx,[r14+4]
            # if i >= len => end
            a.cmp_r32_r32("ecx", "edx")  # cmp ecx,edx
            a.jcc('ge', end)

            # addr = r14 + 8 + i
            a.mov_r64_r64("rax", "r14")  # mov rax,r14
            a.add_r64_r64("rax", "rcx")  # add rax,rcx
            a.add_rax_imm8(8)
            # dl = byte [rax]
            a.mov_r8_membase_disp("dl", "rax", 0)  # mov dl,[rax]
            # Save the byte across the call (calls clobber RDX/DL). Use the outgoing-args area,
            # which is not part of the GC root slots.
            a.mov_membase_disp_r8("rsp", 0x20, "dl")  # mov byte [rsp+0x20],dl

            # allocate new 1-char string: size = 8 + 1 + 1 = 10
            a.mov_rcx_imm32(10)
            a.call('fn_alloc')

            # r11 = base
            a.mov_r11_rax()
            # header
            a.mov_membase_disp_imm32("r11", 0, OBJ_STRING, qword=False)
            a.mov_membase_disp_imm32("r11", 4, 1, qword=False)
            # [r11+8] = char
            a.mov_r8_membase_disp("dl", "rsp", 0x20)
            a.mov_membase_disp_r8("r11", 8, "dl")
            # [r11+9] = 0
            a.mov_membase_disp_imm8("r11", 9, 0)

            # return tagged ptr (heap is 8-aligned => low bits 000)
            a.mov_rax_r11()
            self.emit_store_var(var_name, s)

            a.mark(body)
            # body
            self.push_scope()
            for st in s.body:
                self.emit_stmt(st)
            self.pop_scope()

            a.mark(cont)
            # i++ (reload i because body may clobber ECX)
            a.mov_eax_rip_dword(i_lbl)
            a.mov_r32_r32("ecx", "eax")  # mov ecx,eax
            a.inc_r32("ecx")  # inc ecx
            a.mov_r32_r32("eax", "ecx")  # mov eax,ecx
            a.mov_rip_dword_eax(i_lbl)
            a.jmp(top)

            a.mark(end)
            self.break_stack.pop()
            self.pop_scope()
            return

        if isinstance(s, ml.Break):
            if not self.break_stack:
                raise self.error('break outside loop/switch', s)
            n = getattr(s, 'count', 1)
            idx = len(self.break_stack) - n
            if idx < 0:
                idx = 0
            ctx = self.break_stack[idx]
            # Lexical-scope cleanup before breaking out (important for GC roots)
            if hasattr(self, "emit_cleanup_to_depth"):
                self.emit_cleanup_to_depth(ctx.break_depth)
            a.jmp(ctx.break_label)
            return

        if isinstance(s, ml.Continue):
            # continue bubbles to the nearest enclosing loop (switch is ignored)
            for ctx in reversed(self.break_stack):
                if ctx.kind == 'loop' and ctx.continue_label is not None:
                    # Lexical-scope cleanup before continuing (important for GC roots)
                    if hasattr(self, "emit_cleanup_to_depth"):
                        self.emit_cleanup_to_depth(ctx.continue_depth)
                    a.jmp(ctx.continue_label)
                    return
            raise self.error('continue outside loop', s)

        if isinstance(s, ml.FunctionDef):
            # Top-level functions are emitted after main as native subroutines.
            # Inside a function, `function foo(...) ... end function` is a *statement* that
            # creates a function value at runtime and assigns it to the local name `foo`.
            if not self.in_function:
                return
            if bool(getattr(s, "is_inline", False)):
                raise self.error(
                    "inline is only supported for top-level functions and struct methods (not nested function statements)",
                    s,
                )
            code_name = getattr(s, '_ml_codegen_name', None)
            if not code_name:
                raise self.error(
                    f"Internal compiler error: nested function '{getattr(s, 'name', '<anonymous>')}' is missing _ml_codegen_name (Step 6.2a)",
                    s, )

            # Allocate function object:
            #   +0  u32 type (=OBJ_FUNCTION)
            #   +4  u32 arity
            #   +8  u64 code_ptr (raw address of fn_user_<code_name>)
            #   +16 u64 env (tagged ptr to current environment frame)
            a.mov_rcx_imm32(24)
            a.call("fn_alloc")
            a.mov_r64_r64("r11", "rax")  # r11 = obj
            a.mov_membase_disp_imm32("r11", 0, OBJ_FUNCTION, qword=False)
            a.mov_membase_disp_imm32("r11", 4, len(getattr(s, 'params', []) or []), qword=False)
            a.lea_rdx_rip(f"fn_user_{code_name}")
            a.mov_membase_disp_r64("r11", 8, "rdx")
            # +16 env: capture current environment pointer ONLY if the nested function
            # actually needs a parent env (it captures or is an env-hop for deeper captures).
            need_parent = bool(getattr(s, "_ml_captures", set()) or set()) or bool(getattr(s, "_ml_env_hop", False))
            if need_parent:
                a.mov_membase_disp_r64("r11", 16, "r15")
            else:
                a.mov_membase_disp_imm32("r11", 16, enc_void(), qword=True)

            # Assign to the local variable name.
            self.emit_store_var_scoped(getattr(s, 'name'), s)
            return

        if isinstance(s, ml.Return):
            if not self.in_function or self.func_ret_label is None:
                raise self.error('return outside function', s)
            if s.expr is None:
                a.mov_rax_imm64(enc_void())
            else:
                self.emit_expr(s.expr)
            a.jmp(self.func_ret_label)
            return

        # extern function ... (top-level only; declaration-only)
        if hasattr(ml, 'ExternFunctionDef') and isinstance(s, ml.ExternFunctionDef):
            if bool(getattr(self, 'in_function', False)):
                raise self.error('extern function declarations are only allowed at top-level', s)
            # Externs are collected by the frontend/compiler into extern_sigs; nothing to emit here.
            return

        # Unsupported statements for now
        raise self.error(f"Unsupported statement in native compiler v0.4: {type(s).__name__}", s)

    # ---------- program ----------

    def emit_program(self, program: List[Any]) -> None:
        a = self.asm
        # Step 10: value-enum storage (EnumName -> {Member -> Expr})
        self.value_enum_values = {}

        # Collect declarations (functions/structs), including inside namespaces.
        #
        # Namespaces are compile-time only. Declarations inside `namespace X ... end namespace`
        # are registered with qualified names like "X.foo".
        #
        # NOTE: imported modules are concatenated by compiler.py; all declarations are in `program`.
        def _is_node(n: object, clsname: str) -> bool:
            cls = getattr(self.ml, clsname, None)
            return (cls is not None and isinstance(n, cls)) or (n.__class__.__name__ == clsname)

        builtin_structs = getattr(self, 'builtin_struct_names', set())
        reserved_idents = getattr(self, 'reserved_identifiers', set())

        def _has_reserved_segment(name: str) -> bool:
            if not (isinstance(reserved_idents, set) and reserved_idents):
                return False
            parts = [p for p in str(name).split('.') if p]
            return any(p in reserved_idents for p in parts)

        next_sid = max([sid for nm, sid in self.struct_id.items() if nm not in builtin_structs], default=0) + 1
        next_eid = max(self.enum_id.values(), default=0) + 1

        def _collect_decls(stmts: List[Any], prefix: str = "", current_file: Optional[str] = None,
                           file_prefix: Optional[Dict[str, str]] = None,
                           file_seen_nonpackage: Optional[Dict[str, bool]] = None, in_ns: bool = False) -> None:
            """Collect declarations, applying per-file `package` prefix and nested namespaces.

            - `package X` is represented as `NamespaceDecl(name=X)` and applies to the rest of that file.
            - `namespace X ... end namespace` is represented as `NamespaceDef` and nests under the current prefix.
            """
            nonlocal next_sid, next_eid
            if file_prefix is None:
                file_prefix = {}
            if file_seen_nonpackage is None:
                file_seen_nonpackage = {}

            def _st_file(node: Any) -> Optional[str]:
                fn = getattr(node, '_filename', None)
                return fn if isinstance(fn, str) else None

            for st in stmts:
                # When traversing the merged program (multiple files), reset prefix at file boundaries.
                st_file = _st_file(st) or current_file
                if current_file is None or (st_file is not None and st_file != current_file):
                    current_file = st_file
                    prefix = file_prefix.get(current_file or '', '')
                    file_seen_nonpackage.setdefault(current_file or '', False)

                # package X  (modeled as NamespaceDecl)
                if _is_node(st, "NamespaceDecl"):
                    ns = getattr(st, "name", None)
                    if not isinstance(ns, str) or not ns:
                        raise self.error("Invalid package name", st)

                    if _has_reserved_segment(ns):
                        raise self.error(f"package name '{ns}' is reserved", st)

                    file_key = current_file or ''

                    # Step 7.0a-2: package must be the first statement in a file, and only once.
                    if file_seen_nonpackage.get(file_key, False):
                        raise self.error("package must be the first statement in the file", st)
                    if file_key in file_prefix:
                        raise self.error("duplicate package directive in file", st)

                    file_prefix[file_key] = ns + "."
                    prefix = file_prefix[file_key]
                    continue

                # namespace X ... end namespace
                if _is_node(st, "NamespaceDef"):
                    ns = getattr(st, "name", None)
                    if not isinstance(ns, str) or not ns:
                        raise self.error("Invalid namespace name", st)

                    if _has_reserved_segment(ns):
                        raise self.error(f"namespace name '{ns}' is reserved", st)
                    body = getattr(st, "body", None) or []
                    if not in_ns:
                        file_seen_nonpackage[current_file or ''] = True
                    _collect_decls(body, prefix + ns + ".", current_file=current_file, file_prefix=file_prefix,
                                   file_seen_nonpackage=file_seen_nonpackage, in_ns=True)
                    continue

                # const / global assignments at top-level or inside namespaces
                if _is_node(st, 'ConstDecl') or _is_node(st, 'Assign'):
                    if not in_ns:
                        file_seen_nonpackage[current_file or ''] = True
                    # qualification and runtime hoisting are handled later by _flatten_runtime()
                    continue

                # function
                # function
                if _is_node(st, "FunctionDef"):
                    base_name = getattr(st, "name")

                    if isinstance(base_name, str) and base_name != 'main' and base_name in reserved_idents:
                        raise self.error(f"function name '{base_name}' is reserved", st)

                    # Special entrypoint: main(args) (top-level only)
                    if base_name == "main":
                        if prefix:
                            raise self.error(
                                "main(args) must be declared at top-level (not inside a namespace or package)", st)
                        params = list(getattr(st, "params", []) or [])
                        if len(params) != 1:
                            raise self.error(f"main(args) expects exactly 1 parameter, got {len(params)}", st)
                        if getattr(self, "main_function", None) is not None:
                            raise self.error("duplicate main(args) function", st)

                    if not in_ns:
                        file_seen_nonpackage[current_file or ''] = True

                    qname = prefix + base_name
                    setattr(st, "name", qname)  # rewrite name in-place (used by codegen/calls)
                    if qname in self.user_functions:
                        raise self.error(f"duplicate function: {qname}", st)
                    self.user_functions[qname] = st

                    # record main for later codegen stages
                    if base_name == "main" and not prefix:
                        self.main_function = qname
                    continue

                # struct
                if _is_node(st, "StructDef"):
                    if not in_ns:
                        file_seen_nonpackage[current_file or ''] = True

                    base_name = getattr(st, "name")
                    if isinstance(base_name, str) and base_name in reserved_idents:
                        raise self.error(f"struct name '{base_name}' is reserved", st)

                    qname = prefix + str(base_name)
                    setattr(st, "name", qname)

                    # Reserve built-in struct names (e.g. global `error`).
                    if qname in builtin_structs:
                        raise self.error(f"struct name '{qname}' is reserved", st)

                    if qname in self.struct_fields:
                        raise self.error(f"duplicate struct: {qname}", st)
                    fields = list(getattr(st, "fields", []) or [])
                    seen = set()
                    for f in fields:
                        if f in seen:
                            raise self.error(f"duplicate field {f} in struct {qname}", st)
                        seen.add(f)
                    self.struct_fields[qname] = fields
                    if qname not in self.struct_id:
                        self.struct_id[qname] = next_sid
                        next_sid += 1

                    # methods inside struct (OOP sugar): hoist as top-level functions.
                    # - instance methods: StructName.method(this, ...)   (implicit `this`)
                    # - static methods:   StructName.__static__.method(...)
                    methods = list(getattr(st, "methods", []) or [])
                    if methods:
                        mdict: Dict[str, str] = {}  # instance
                        sdict: Dict[str, str] = {}  # static
                        seen_names: set[str] = set()

                        for mfn in methods:
                            mbase = getattr(mfn, "name", None)
                            if not isinstance(mbase, str) or not mbase:
                                raise self.error(f"invalid method name in struct {qname}", mfn)
                            if mbase in reserved_idents:
                                raise self.error(f"method name '{mbase}' is reserved", mfn)
                            if mbase in seen_names:
                                raise self.error(f"duplicate method {mbase} in struct {qname}", mfn)
                            if mbase in fields:
                                raise self.error(f"method name '{mbase}' conflicts with field in struct {qname}", mfn)

                            seen_names.add(mbase)

                            is_static = bool(getattr(mfn, "is_static", False))
                            if is_static:
                                qfn = f"{qname}.__static__.{mbase}"
                                params = list(getattr(mfn, "params", []) or [])
                                sdict[mbase] = qfn
                            else:
                                qfn = f"{qname}.{mbase}"
                                params = ['this'] + list(getattr(mfn, "params", []) or [])
                                mdict[mbase] = qfn

                            body = list(getattr(mfn, "body", []) or [])

                            fn_node = self.ml.FunctionDef(
                                qfn,
                                params,
                                body,
                                is_static=is_static,
                                is_inline=bool(getattr(mfn, "is_inline", False)),
                            )
                            # preserve source position/filename if present
                            for attr in ("_pos", "_filename"):
                                if hasattr(mfn, attr):
                                    setattr(fn_node, attr, getattr(mfn, attr))

                            if qfn in self.user_functions:
                                raise self.error(f"method name conflicts with function: {qfn}", fn_node)
                            self.user_functions[qfn] = fn_node

                        if mdict:
                            self.struct_methods[qname] = mdict
                        if sdict:
                            self.struct_static_methods[qname] = sdict
                # enum
                if _is_node(st, "EnumDef"):
                    if not in_ns:
                        file_seen_nonpackage[current_file or ''] = True

                    base_name = getattr(st, "name")
                    if isinstance(base_name, str) and base_name in reserved_idents:
                        raise self.error(f"enum name '{base_name}' is reserved", st)

                    qname = prefix + str(base_name)
                    setattr(st, "name", qname)

                    # Name conflicts across kinds
                    if qname in self.enum_variants or qname in (getattr(self, "value_enum_values", {}) or {}):
                        raise self.error(f"duplicate enum: {qname}", st)
                    if qname in self.user_functions:
                        raise self.error(f"enum name conflicts with function: {qname}", st)
                    if qname in self.struct_fields:
                        raise self.error(f"enum name conflicts with struct: {qname}", st)

                    variants = list(getattr(st, "variants", []) or [])
                    if len(variants) > 65536:
                        raise self.error(f"enum {qname} has too many variants (max 65536)", st)

                    seen = set()
                    for v in variants:
                        if not isinstance(v, str) or not v:
                            raise self.error(f"invalid enum variant in {qname}", st)
                        if v in seen:
                            raise self.error(f"duplicate variant {v} in enum {qname}", st)
                        seen.add(v)

                    # Step 4: value-enums (explicit or auto-filled member values)
                    # We do NOT evaluate values here anymore; instead we keep constexpr expressions
                    # and let the global const-eval pass resolve them in source order.
                    values = list(getattr(st, 'values', []) or [])
                    if any(vv is not None for vv in values):
                        if len(values) != len(variants):
                            raise self.error(f"enum {qname} value list length mismatch", st)

                        member_map: Dict[str, Any] = {}
                        # Track last member that participates in numeric auto-increment.
                        # Explicit string values are ignored for the numeric sequence.
                        prev_int_member: Optional[str] = None

                        for vn, vx in zip(variants, values):
                            vname = str(vn)

                            if vx is not None:
                                if not _is_constexpr_expr(self.ml, vx):
                                    raise self.error(f"enum {qname} value for {vname} must be constexpr", st)
                                expr_node = vx
                            else:
                                # Auto-fill: first missing -> 0; subsequent missing -> prev_int+1
                                if prev_int_member is None:
                                    expr_node = self.ml.Num(0)
                                else:
                                    vref = self.ml.Var(f"{qname}.{prev_int_member}")
                                    expr_node = self.ml.Bin(vref, '+', self.ml.Num(1))
                                    # marker for stricter auto-increment rules (must follow an int)
                                    try:
                                        setattr(expr_node, '_ml_enum_autoinc_prev', f"{qname}.{prev_int_member}")
                                    except Exception:
                                        pass

                                # Propagate source location for diagnostics.
                                for attr in ('_pos', '_filename'):
                                    if hasattr(st, attr):
                                        try:
                                            setattr(expr_node, attr, getattr(st, attr))
                                        except Exception:
                                            pass

                            member_map[vname] = expr_node

                            # Update numeric auto-increment anchor:
                            # - Auto-filled members are numeric by construction.
                            # - Explicit string literals are ignored.
                            # - Other constexpr expressions remain anchors (old behavior).
                            if vx is None:
                                prev_int_member = vname
                            else:
                                str_cls = getattr(self.ml, 'Str', None)
                                if str_cls is None or not isinstance(vx, str_cls):
                                    prev_int_member = vname

                        self.value_enum_values[qname] = member_map
                        continue

                    self.enum_variants[qname] = variants
                    if qname not in self.enum_id:
                        if next_eid > 65535:
                            raise self.error("too many enums (max 65535)", st)
                        self.enum_id[qname] = next_eid
                        next_eid += 1
                    continue

                    continue

                # imports are stripped by compiler.py but tolerate nodes anyway
                if _is_node(st, "Import") or _is_node(st, "ImportStmt"):
                    if not in_ns:
                        file_seen_nonpackage[current_file or ''] = True
                    continue

        # Persist a filename -> package-prefix mapping so expression codegen can
        # resolve unqualified references inside `package ...` files.
        file_prefix_map: Dict[str, str] = {}
        file_seen_nonpackage: Dict[str, bool] = {}
        _collect_decls(program, file_prefix=file_prefix_map, file_seen_nonpackage=file_seen_nonpackage)
        self.file_prefix_map = file_prefix_map
        # Keep CodegenCore package-resolution helpers in sync.
        self._file_prefix_map = file_prefix_map
        self.current_file_prefix = ''

        # Step 10.0: materialize boxed string constants for typeName(x).
        # typeName() is like typeof(), but returns concrete struct/enum names.
        # We create one boxed string in .rdata per known struct/enum ID.
        self.typename_struct_by_id = {}
        self.typename_struct_by_qname = {}
        try:
            for qn, sid in getattr(self, 'struct_id', {}).items():
                try:
                    sid_i = int(sid)
                except Exception:
                    continue
                lbl = f"obj_typename_struct_{sid_i}"
                self.rdata.add_obj_string(lbl, str(qn))
                self.typename_struct_by_id[sid_i] = lbl
                self.typename_struct_by_qname[str(qn)] = lbl
        except Exception:
            pass

        self.typename_enum_by_id = {}
        self.typename_enum_by_qname = {}
        try:
            for qn, eid in getattr(self, 'enum_id', {}).items():
                try:
                    eid_i = int(eid)
                except Exception:
                    continue
                lbl = f"obj_typename_enum_{eid_i}"
                self.rdata.add_obj_string(lbl, str(qn))
                self.typename_enum_by_id[eid_i] = lbl
                self.typename_enum_by_qname[str(qn)] = lbl
        except Exception:
            pass
        # Current emission context for CodegenCore._qualify_identifier
        # (set while emitting top-level statements and function bodies).
        self._current_fn_file = None
        self._current_fn_qname = None

        # Step 10: Materialize namespace-level globals/consts and value-enum members as
        # runtime top-level statements in source order (namespaces are compile-time only).
        def _flatten_runtime(stmts: List[Any], *, prefix: str = '', current_file: Optional[str] = None) -> List[Any]:
            out: List[Any] = []

            def _tag_ns(node: Any) -> None:
                # Attach the active package/namespace prefix to statements so unqualified
                # name resolution works inside namespaces (Step 4).
                try:
                    setattr(node, '_ml_ns_prefix', prefix if isinstance(prefix, str) else '')
                except Exception:
                    pass

            def _st_file(node: Any) -> Optional[str]:
                fn = getattr(node, '_filename', None)
                return fn if isinstance(fn, str) else None

            for st in stmts:
                st_file = _st_file(st) or current_file
                if current_file is None or (st_file is not None and st_file != current_file):
                    current_file = st_file
                    prefix = file_prefix_map.get(current_file or '', '') or ''

                # Keep package/namespace decl nodes for other passes (they emit no runtime code).
                if _is_node(st, 'NamespaceDecl'):
                    _tag_ns(st)
                    out.append(st)
                    continue

                # namespace ... end namespace: splice any initializers inside the namespace body here.
                if _is_node(st, 'NamespaceDef'):
                    _tag_ns(st)
                    out.append(st)
                    ns = getattr(st, 'name', None)
                    body = getattr(st, 'body', None) or []
                    if isinstance(ns, str) and ns and isinstance(body, list):
                        out.extend(_flatten_runtime(body, prefix=prefix + ns + '.', current_file=current_file))
                    continue

                # enum ... end enum: if it is a value-enum, emit const member bindings right after it.
                if _is_node(st, 'EnumDef'):
                    _tag_ns(st)
                    out.append(st)
                    qn = getattr(st, 'name', None)
                    if isinstance(qn, str):
                        members = (getattr(self, 'value_enum_values', {}) or {}).get(qn)
                        if isinstance(members, dict) and members:
                            if not hasattr(self.ml, 'ConstDecl'):
                                raise self.error('Internal error: ConstDecl AST node missing (Step 10).', st)
                            for vn, vx in members.items():
                                cd = self.ml.ConstDecl(f"{qn}.{vn}", vx)
                                for attr in ('_pos', '_filename'):
                                    if hasattr(st, attr):
                                        setattr(cd, attr, getattr(st, attr))
                                _tag_ns(cd)
                                out.append(cd)
                    continue

                # Top-level const/assign in package files: qualify unqualified names by prefix.
                if hasattr(self.ml, 'ConstDecl') and isinstance(st, self.ml.ConstDecl):
                    nm = getattr(st, 'name', None)
                    if isinstance(nm, str) and prefix and '.' not in nm:
                        setattr(st, 'name', prefix + nm)
                    _tag_ns(st)
                    out.append(st)
                    continue

                if isinstance(st, self.ml.Assign):
                    nm = getattr(st, 'name', None)
                    if isinstance(nm, str) and prefix and '.' not in nm:
                        setattr(st, 'name', prefix + nm)
                    _tag_ns(st)
                    out.append(st)
                    continue

                _tag_ns(st)
                out.append(st)
            return out

        program = _flatten_runtime(program)

        # Track which module/file owns each top-level global/const runtime binding.
        # Used for module-init dependency diagnostics on cross-module global reads.
        self._global_owner_file = {}
        self._module_init_status_labels = {}
        self._module_init_active = False
        self._module_init_active_file = None
        try:
            _assign_cls = getattr(self.ml, 'Assign', None)
            _const_cls = getattr(self.ml, 'ConstDecl', None)
            for _st in program:
                _st_file = getattr(_st, '_filename', None)
                if not (isinstance(_st_file, str) and _st_file):
                    continue
                _is_bind = False
                if _assign_cls is not None and isinstance(_st, _assign_cls):
                    _is_bind = True
                if _const_cls is not None and isinstance(_st, _const_cls):
                    _is_bind = True
                if not _is_bind:
                    continue
                _nm = getattr(_st, 'name', None)
                if isinstance(_nm, str) and _nm:
                    self._global_owner_file[_nm] = _st_file
        except Exception:
            pass

        # Step 6.1: analyze nested functions + captures (closures preparation)
        nested_fns = self._closure_analyze_program()

        # Step 6.2a/6.2b: register nested functions and assign stable codegen names.
        # Nested function defs are emitted as runtime statements; their bodies are emitted as
        # separate native subroutines (fn_user_<code_name>).
        self.nested_user_functions: Dict[str, Any] = {}

        if nested_fns:
            nested_counter = 1
            for nf in nested_fns:
                parent = getattr(nf, '_ml_parent_fn', None)
                parent_code = getattr(parent, '_ml_codegen_name',
                                      getattr(parent, 'name', 'toplevel')) if parent is not None else 'toplevel'
                parent_disp = getattr(parent, '_ml_display_name',
                                      getattr(parent, 'name', 'toplevel')) if parent is not None else 'toplevel'
                base = str(getattr(nf, 'name', 'fn'))
                code_name = f"{parent_code}__{base}__n{nested_counter}"
                nested_counter += 1
                display_name = f"{parent_disp}.{base}" if parent is not None else base

                setattr(nf, '_ml_codegen_name', code_name)
                setattr(nf, '_ml_display_name', display_name)
                self.nested_user_functions[code_name] = nf

                # ------------------------------------------------------------
        # Call profiling (--profile-calls)
        # ------------------------------------------------------------
        self._callprof_enabled = bool(getattr(self, 'call_profile', False))
        self._callprof_entries = []
        self._callprof_index = {}
        self._callprof_name_labels = []
        self._callprof_n = 0
        if self._callprof_enabled:
            entries = []
            for nm in sorted(self.user_functions.keys()):
                fn = self.user_functions[nm]
                code_name = getattr(fn, '_ml_codegen_name', nm)
                disp = getattr(fn, '_ml_display_name', nm)
                entries.append((str(code_name), str(disp)))
            for nm in sorted(getattr(self, 'nested_user_functions', {}).keys()):
                fn = (getattr(self, 'nested_user_functions', {}) or {}).get(nm)
                disp = getattr(fn, '_ml_display_name', None) if fn is not None else None
                if not (isinstance(disp, str) and disp):
                    disp = str(nm)
                entries.append((str(nm), str(disp)))
            self._callprof_entries = entries
            self._callprof_index = {code: i for i, (code, _disp) in enumerate(entries)}
            self._callprof_n = len(entries)
            if self._callprof_n > 0:
                # Writable qword counters (NOT GC roots)
                if 'callprof_counts' not in getattr(self.data, 'labels', {}):
                    self.data.add_bytes('callprof_counts', b'\x00' * (8 * self._callprof_n))
                # Boxed name objects in .rdata (pooled)
                for i, (_code, disp) in enumerate(entries):
                    lbl = f'callprof_name_{i}'
                    self.rdata.add_obj_string(lbl, disp)
                    self._callprof_name_labels.append(lbl)

# Hoist top-level function identifiers as global bindings (first-class functions).
        # This makes `f = add` legal even if `add` is never written as a variable.
        self.function_global_labels: Dict[str, str] = {}
        for nm, fn in self.user_functions.items():
            b = None
            try:
                b = self.resolve_binding(nm)
            except Exception:
                b = None
            if b is None:
                try:
                    b = self.declare_global_binding(nm, node=fn)
                except Exception:
                    b = None
            if b is not None and getattr(b, "kind", None) == "global" and getattr(b, "label", None):
                self.function_global_labels[nm] = b.label

        # Hoist struct identifiers as global bindings (first-class struct constructors/types).
        # This makes `ctor = Point` / `ctor = geom.Point` legal.
        self.struct_global_labels: Dict[str, str] = {}
        for nm in self.struct_fields.keys():
            b = None
            try:
                b = self.resolve_binding(nm)
            except Exception:
                b = None
            if b is None:
                try:
                    b = self.declare_global_binding(nm, node=None)
                except Exception:
                    b = None
            if b is not None and getattr(b, "kind", None) == "global" and getattr(b, "label", None):
                self.struct_global_labels[nm] = b.label

        # Hoist selected builtin identifiers as global bindings (first-class builtins).
        # This makes `f = len; f([1,2,3])` work.
        #
        # NOTE: We only declare a builtin binding if the name is otherwise unused at the
        # top level (i.e., we never override user globals / functions / structs).
        self.builtin_specs: Dict[str, Tuple[int, int, str]] = {# name: (min_arity, max_arity, code_label)
            'len': (1, 1, 'fn_builtin_len'), 'toNumber': (1, 1, 'fn_toNumber'), 'typeof': (1, 1, 'fn_typeof'),
            'typeName': (1, 1, 'fn_typeName'),
            'input': (0, 1, 'fn_builtin_input'),

            # bytes/string helpers (native)
            # NOTE: bytes()/byteBuffer() are implemented as special forms in CodegenExpr
            # (argument validation + allocation) and are therefore not first-class here.
            'decode': (1, 2, 'fn_decode'), 'decodeZ': (1, 1, 'fn_decodeZ'), 'decode16Z': (1, 1, 'fn_decode16Z'),
            'hex': (1, 1, 'fn_hex'), 'fromHex': (1, 1, 'fn_fromHex'), 'slice': (3, 3, 'fn_slice'),

            'gc_collect': (0, 0, 'fn_builtin_gc_collect'),

            'gc_set_limit': (1, 1, 'fn_builtin_gc_set_limit'),

            # heap / debug builtins
            'heap_count': (0, 0, 'fn_heap_count'), 'heap_bytes_used': (0, 0, 'fn_heap_bytes_used'),
            'heap_bytes_committed': (0, 0, 'fn_heap_bytes_committed'),
            'heap_bytes_reserved': (0, 0, 'fn_heap_bytes_reserved'), 'heap_free_bytes': (0, 0, 'fn_heap_free_bytes'),
            'heap_free_blocks': (0, 0, 'fn_heap_free_blocks'), }

        self.builtin_global_labels: Dict[str, str] = {}
        for nm in self.builtin_specs.keys():
            b = None
            try:
                b = self.resolve_binding(nm)
            except Exception:
                b = None
            if b is not None:
                continue  # user-defined global already exists
            try:
                b = self.declare_global_binding(nm, node=None)
            except Exception:
                b = None
            if b is not None and getattr(b, 'kind', None) == 'global' and getattr(b, 'label', None):
                self.builtin_global_labels[nm] = b.label

        # Hoist extern function identifiers as global bindings (stub-only externs).
        # Externs are declared in source via `extern function ...` and collected by compiler.py
        # into `self.extern_sigs` (qname -> signature). Here we create a global binding so
        # externs become first-class values (OBJ_BUILTIN) and can be called uniformly.
        self.extern_global_labels: Dict[str, str] = {}
        self.extern_stub_labels: Dict[str, str] = {}
        for qn, sig in (getattr(self, 'extern_sigs', {}) or {}).items():
            b = None
            try:
                b = self.resolve_binding(qn)
            except Exception:
                b = None
            if b is not None:
                continue  # user/global already exists; do not override
            try:
                b = self.declare_global_binding(qn, node=None)
            except Exception:
                b = None
            if b is not None and getattr(b, 'kind', None) == 'global' and getattr(b, 'label', None):
                self.extern_global_labels[qn] = b.label
                # Use the unique global label in the stub name to avoid collisions.
                self.extern_stub_labels[qn] = f"fn_extern_{b.label}"

        # Reset internal-helper usage tracking for this compilation unit
        if hasattr(self, 'reset_helper_tracking'):
            self.reset_helper_tracking()

        # Prologue: create stack frame.
        # We size the main stack frame dynamically based on maximum call arity.

        def max_calls_expr(e: Any) -> int:
            m = 0
            if isinstance(e, self.ml.Call):
                call_arity = len(e.args)
                try:
                    cal = e.callee
                    if isinstance(cal, self.ml.Member):
                        mname = getattr(cal, 'name', None)
                        if isinstance(mname, str):
                            for _s, _md in (getattr(self, 'struct_methods', {}) or {}).items():
                                if mname in (_md or {}):
                                    call_arity += 1
                                    break
                except Exception:
                    pass
                m = max(m, call_arity)
                m = max(m, max_calls_expr(e.callee))
                for aa in e.args:
                    m = max(m, max_calls_expr(aa))
                return m
            if isinstance(e, self.ml.Unary):
                return max_calls_expr(e.right)
            if isinstance(e, self.ml.Bin):
                return max(max_calls_expr(e.left), max_calls_expr(e.right))
            if isinstance(e, self.ml.Index):
                return max(max_calls_expr(e.target), max_calls_expr(e.index))
            if isinstance(e, self.ml.ArrayLit):
                for it in e.items:
                    m = max(m, max_calls_expr(it))
                return m
            if isinstance(e, self.ml.Member):

                t = getattr(e, 'target', None)

                if t is None:
                    t = getattr(e, 'obj', None)

                return max_calls_expr(t)
            return 0

        def max_calls_stmts(stmts: List[Any]) -> int:
            m = 0
            for ss in stmts:
                if isinstance(ss, self.ml.Assign):
                    m = max(m, max_calls_expr(ss.expr))
                elif hasattr(self.ml, 'ConstDecl') and isinstance(ss, self.ml.ConstDecl):
                    m = max(m, max_calls_expr(getattr(ss, 'expr', None)))
                elif isinstance(ss, self.ml.Print):
                    m = max(m, max_calls_expr(ss.expr))
                elif isinstance(ss, self.ml.ExprStmt):
                    m = max(m, max_calls_expr(ss.expr))
                elif hasattr(self.ml, 'SetMember') and isinstance(ss, self.ml.SetMember):
                    m = max(m, max_calls_expr(getattr(ss, 'obj', getattr(ss, 'target', None))))
                    m = max(m, max_calls_expr(getattr(ss, 'expr', None)))
                elif isinstance(ss, self.ml.SetIndex):
                    m = max(m, max_calls_expr(ss.target))
                    m = max(m, max_calls_expr(ss.index))
                    m = max(m, max_calls_expr(ss.expr))
                elif isinstance(ss, self.ml.If):
                    m = max(m, max_calls_expr(ss.cond))
                    m = max(m, max_calls_stmts(ss.then_body))
                    for (c, b) in ss.elifs:
                        m = max(m, max_calls_expr(c))
                        m = max(m, max_calls_stmts(b))
                    if ss.else_body is not None:
                        m = max(m, max_calls_stmts(ss.else_body))
                elif isinstance(ss, self.ml.While):
                    m = max(m, max_calls_expr(ss.cond))
                    m = max(m, max_calls_stmts(ss.body))
                elif isinstance(ss, self.ml.DoWhile):
                    m = max(m, max_calls_stmts(ss.body))
                    m = max(m, max_calls_expr(ss.cond))
                elif isinstance(ss, self.ml.For):
                    m = max(m, max_calls_expr(ss.start))
                    m = max(m, max_calls_expr(ss.end))
                    m = max(m, max_calls_stmts(ss.body))
                elif isinstance(ss, self.ml.ForEach):
                    m = max(m, max_calls_expr(ss.iterable))
                    m = max(m, max_calls_stmts(ss.body))
                elif isinstance(ss, self.ml.Switch):
                    m = max(m, max_calls_expr(ss.expr))
                    for case in ss.cases:
                        for vv in case.values:
                            if isinstance(vv, tuple):
                                m = max(m, max_calls_expr(vv[0]))
                                m = max(m, max_calls_expr(vv[1]))
                            else:
                                m = max(m, max_calls_expr(vv))
                        m = max(m, max_calls_stmts(case.body))
                    if ss.default_body is not None:
                        m = max(m, max_calls_stmts(ss.default_body))
                elif isinstance(ss, self.ml.Return):
                    if ss.expr is not None:
                        m = max(m, max_calls_expr(ss.expr))
                elif isinstance(ss, (self.ml.Break, self.ml.Continue, self.ml.FunctionDef)):
                    pass
            return m

        # ------------------------------------------------------------
        # Inline functions (function inline ...)
        # ------------------------------------------------------------
        # Inline functions are expanded directly in CodegenExpr (no call overhead).
        # Direct calls like `f(x,y)` are expanded; indirect calls still work via the
        # out-of-line function body.
        #
        # NOTE: Multi-statement bodies are supported; CodegenExpr implements the
        #       full statement/block expansion with an isolated inline scope.
        self.inline_functions = {}
        for qn, fn in (getattr(self, "user_functions", {}) or {}).items():
            if not bool(getattr(fn, "is_inline", False)):
                continue
            self.inline_functions[qn] = fn

        # ------------------------------------------------------------
        # Stack layout sizing (global maximum call arity)
        # ------------------------------------------------------------
        # When inlining, calls inside the inlined expression appear in the *caller*
        # without being visible in the caller's own AST. To avoid under-sizing the
        # outgoing-args scratch area, we conservatively size it to the maximum call
        # arity seen anywhere in the program.
        max_call_args_main = max_calls_stmts(program)
        max_call_args_global = max_call_args_main
        for _fn in (getattr(self, "user_functions", {}) or {}).values():
            try:
                max_call_args_global = max(max_call_args_global, max_calls_stmts(list(getattr(_fn, "body", []) or [])))
            except Exception:
                pass
        for _fn in (getattr(self, "nested_user_functions", {}) or {}).values():
            try:
                max_call_args_global = max(max_call_args_global, max_calls_stmts(list(getattr(_fn, "body", []) or [])))
            except Exception:
                pass

        self._max_call_args_global = int(max_call_args_global)

        # Use global max for main frame too.
        max_call_args_main = self._max_call_args_global

        # Layout:
        # [rsp+0x00..0x1F] shadow space for calls
        # [rsp+0x20..] outgoing stack args for our calls (arg5+) + scratch
        out_stack_args = max(0, max_call_args_main - 4)
        out_reserve = max(8, out_stack_args * 8)
        self.call_temp_base = align_up(0x20 + out_reserve, 16)
        call_temp_bytes = align_up(max(0x40, max_call_args_main * 8), 16)
        self.expr_temp_base = self.call_temp_base + call_temp_bytes
        self.expr_temp_top = 0

        frame_end = self.expr_temp_base + self.expr_temp_max
        # Reserve space for GC shadow-stack root-frame record (32 bytes).
        main_frame = align_to_mod(frame_end + 0x20, 16, 8)  # entry RSP is 8 mod 16
        root_rec_off = main_frame - 0x20

        a.sub_rsp_imm32(main_frame)

        # For GUI / windows-subsystem builds, detach from any inherited console.
        # This preserves normal Win32 window behavior (e.g. fullscreen) while
        # preventing a console window/scrollbar from sticking around when started
        # from PowerShell/cmd.
        if getattr(self, 'is_windows_subsystem', False):
            a.mov_rax_rip_qword('iat_FreeConsole')
            a.call_rax()

        # GetStdHandle(STD_OUTPUT_HANDLE=-11)
        a.mov_rcx_imm32(0xFFFFFFF5)
        a.mov_rax_rip_qword('iat_GetStdHandle')
        a.call_rax()
        a.mov_rbx_rax()

        # SetConsoleOutputCP(CP_UTF8=65001) so UTF-8 bytes are displayed correctly if we fall back to WriteFile
        if not getattr(self, 'is_windows_subsystem', False):
            a.mov_rcx_imm32(65001)
            a.mov_rax_rip_qword('iat_SetConsoleOutputCP')
            a.call_rax()

        # Initialize heap + GC globals (implemented in CodegenMemory).
        # Heap init (bump allocator): one fixed 32 MiB heap reserved+committed at startup.
        self.emit_heap_init()

        # Initialize function values for all top-level (and namespaced) user functions.
        # Layout (24 bytes):
        #   +0  u32 type    = OBJ_FUNCTION
        #   +4  u32 arity
        #   +8  u64 code_ptr (raw address of fn_user_<name>)
        #  +16  u64 env      (reserved for closures; currently VOID)
        voidv = enc_void()
        for nm, fn in self.user_functions.items():
            lbl = getattr(self, "function_global_labels", {}).get(nm)
            if not lbl:
                continue
            arity = len(getattr(fn, "params", []) or [])
            a.mov_rcx_imm32(24)
            a.call("fn_alloc")
            a.mov_r64_r64("r11", "rax")  # r11 = obj
            a.mov_membase_disp_imm32("r11", 0, OBJ_FUNCTION, qword=False)
            a.mov_membase_disp_imm32("r11", 4, arity, qword=False)
            a.lea_rax_rip(f"fn_user_{nm}")
            a.mov_membase_disp_r64("r11", 8, "rax")
            a.mov_membase_disp_imm32("r11", 16, voidv, qword=True)
            a.mov_rip_qword_r11(lbl)
        # Step 6.2b-2b-1: compute env slot layout metadata (boxed vars + indices)
        # Must happen AFTER nested_user_functions is populated so nested functions also get layout.
        self._closure_assign_env_layout(nested_fns)

        # Initialize struct type values for all structs.
        # Layout (16 bytes):
        #   +0  u32 type     = OBJ_STRUCTTYPE
        #   +4  u32 nfields
        #   +8  u32 struct_id
        #   +12 u32 pad
        for nm, fields in self.struct_fields.items():
            lbl = getattr(self, "struct_global_labels", {}).get(nm)
            if not lbl:
                continue
            nfields = len(fields)
            sid = self.struct_id.get(nm, 0)
            a.mov_rcx_imm32(16)
            a.call("fn_alloc")
            a.mov_r64_r64("r11", "rax")  # r11 = obj
            a.mov_membase_disp_imm32("r11", 0, OBJ_STRUCTTYPE, qword=False)
            a.mov_membase_disp_imm32("r11", 4, nfields, qword=False)
            a.mov_membase_disp_imm32("r11", 8, sid, qword=False)
            a.mov_membase_disp_imm32("r11", 12, 0, qword=False)
            a.mov_rip_qword_r11(lbl)

        # Initialize first-class builtin function values (OBJ_BUILTIN) for selected builtins.
        # Layout (24 bytes):
        #   +0  u32 type    = OBJ_BUILTIN
        #   +4  u32 min_arity
        #   +8  u32 max_arity
        #   +12 u32 pad
        #   +16 u64 code_ptr (raw address of fn_*)
        for nm, spec in getattr(self, 'builtin_specs', {}).items():
            lbl = getattr(self, 'builtin_global_labels', {}).get(nm)
            if not lbl:
                continue
            try:
                min_a, max_a, code_lbl = spec
            except Exception:
                continue
            # We take the address of `code_lbl` (lea rip), so ensure the helper is emitted.
            if hasattr(self, 'used_helpers'):
                try:
                    self.used_helpers.add(str(code_lbl))  # type: ignore[attr-defined]
                except Exception:
                    pass
            a.mov_rcx_imm32(24)
            a.call('fn_alloc')
            a.mov_r64_r64('r11', 'rax')
            a.mov_membase_disp_imm32('r11', 0, OBJ_BUILTIN, qword=False)
            a.mov_membase_disp_imm32('r11', 4, int(min_a), qword=False)
            a.mov_membase_disp_imm32('r11', 8, int(max_a), qword=False)
            a.mov_membase_disp_imm32('r11', 12, 0, qword=False)
            a.lea_rax_rip(str(code_lbl))
            a.mov_membase_disp_r64('r11', 16, 'rax')
            a.mov_rip_qword_r11(lbl)

        # Initialize extern function values (OBJ_BUILTIN stubs).
        for qn, sig in (getattr(self, 'extern_sigs', {}) or {}).items():
            lbl = getattr(self, 'extern_global_labels', {}).get(qn)
            stub_lbl = getattr(self, 'extern_stub_labels', {}).get(qn)
            if not lbl or not stub_lbl:
                continue
            params = list((sig or {}).get('params', []) or [])
            # Extern out-params are implicit at the call site: arity counts only non-out params.
            arity = 0
            for pp in params:
                if isinstance(pp, dict) and bool(pp.get('out', False)):
                    continue
                arity += 1
            a.mov_rcx_imm32(24)
            a.call('fn_alloc')
            a.mov_r64_r64('r11', 'rax')
            a.mov_membase_disp_imm32('r11', 0, OBJ_BUILTIN, qword=False)
            a.mov_membase_disp_imm32('r11', 4, arity, qword=False)
            a.mov_membase_disp_imm32('r11', 8, arity, qword=False)
            a.mov_membase_disp_imm32('r11', 12, 0, qword=False)
            a.lea_rax_rip(stub_lbl)
            a.mov_membase_disp_r64('r11', 16, 'rax')
            a.mov_rip_qword_r11(lbl)

        # ------------------------------------------------------------
        # Step 7.1b: predeclare globals referenced via `global ...` inside functions.
        #
        # Rationale:
        # - User functions are emitted in sorted order, not source order.
        # - A `global x` statement should be able to introduce a new global slot even
        #   if there was no top-level initializer.
        # - Other functions (or top-level code) may reference that global before the
        #   defining function is emitted; predeclaring makes this robust.
        # ------------------------------------------------------------
        def _is_stmt(obj: Any) -> bool:
            try:
                st_cls = getattr(self.ml, 'Stmt', None)
                return st_cls is not None and isinstance(obj, st_cls)
            except Exception:
                return False

        def _walk_stmt(node: Any) -> List[Any]:
            """Return child statements for a statement-like node."""
            out: List[Any] = []
            if node is None:
                return out

            # Switch cases carry nested bodies.
            if type(node).__name__ == 'SwitchCase':
                body = getattr(node, 'body', None)
                if isinstance(body, list):
                    out.extend(body)
                return out

            # Generic walk: collect any list-valued fields that contain Stmt/SwitchCase.
            d = getattr(node, '__dict__', None)
            if isinstance(d, dict):
                for v in d.values():
                    if isinstance(v, list):
                        for it in v:
                            if _is_stmt(it) or type(it).__name__ == 'SwitchCase':
                                out.append(it)
                    else:
                        if _is_stmt(v) or type(v).__name__ == 'SwitchCase':
                            out.append(v)
            return out

        def _pref_is_method_prefix(qpref: str) -> bool:
            try:
                qn0 = qpref[:-1] if qpref.endswith('.') else qpref
                if not qn0:
                    return False
                if '.__static__' in qn0:
                    return True
                sf = getattr(self, 'struct_fields', {}) or {}
                if isinstance(sf, dict) and qn0 in sf:
                    return True
            except Exception:
                return False
            return False

        def _resolve_global_target(raw: str, *, qpref: str, fpref: str) -> str:
            raw = str(raw)
            if '.' in raw:
                return raw

            cands: List[str] = []
            if qpref:
                cands.append((qpref if qpref.endswith('.') else (qpref + '.')) + raw)
            if fpref:
                cands.append((fpref if fpref.endswith('.') else (fpref + '.')) + raw)
            cands.append(raw)

            # If any candidate already exists as a root global, prefer it.
            for cand in cands:
                try:
                    b = self._scope_stack[0].get(cand)
                except Exception:
                    b = None
                if b is not None and getattr(b, 'kind', None) == 'global' and getattr(b, 'depth', 0) == 0:
                    return cand

            # Otherwise, choose a creation target.
            if qpref and not _pref_is_method_prefix(qpref):
                return (qpref if qpref.endswith('.') else (qpref + '.')) + raw
            if fpref:
                return (fpref if fpref.endswith('.') else (fpref + '.')) + raw
            return raw

        def _scan_function_for_global_decls(fn: Any) -> None:
            if fn is None:
                return
            if not hasattr(self.ml, 'FunctionDef') or not isinstance(fn, self.ml.FunctionDef):
                return

            fn_qn = getattr(fn, 'name', '')
            qpref = ''
            if isinstance(fn_qn, str) and '.' in fn_qn:
                qpref = fn_qn.rsplit('.', 1)[0] + '.'

            fn_file = getattr(fn, '_filename', None)
            if not (isinstance(fn_file, str) and fn_file):
                # nested functions may inherit file from parent
                p = getattr(fn, '_ml_parent_fn', None)
                fn_file = getattr(p, '_filename', None) if p is not None else None
            fpref = ''
            try:
                mp = getattr(self, 'file_prefix_map', None) or {}
                if isinstance(mp, dict) and isinstance(fn_file, str):
                    fpref = mp.get(fn_file, '') or ''
            except Exception:
                fpref = ''

            stack: List[Any] = list(getattr(fn, 'body', []) or [])
            seen: set[int] = set()

            while stack:
                st = stack.pop()
                if st is None:
                    continue
                sid = id(st)
                if sid in seen:
                    continue
                seen.add(sid)

                if hasattr(self.ml, 'GlobalDecl') and isinstance(st, self.ml.GlobalDecl):
                    for nm in getattr(st, 'names', []) or []:
                        tgt = _resolve_global_target(str(nm), qpref=qpref, fpref=fpref)
                        try:
                            self.declare_global_binding_root(tgt, node=st)
                        except Exception:
                            # If the slot already exists or cannot be declared here,
                            # let normal compilation surface the real diagnostic.
                            pass
                    continue

                # Recurse
                for ch in _walk_stmt(st):
                    stack.append(ch)

        # Scan all user functions (and nested functions, if any).
        for _fn in (getattr(self, 'user_functions', {}) or {}).values():
            _scan_function_for_global_decls(_fn)
        for _fn in (getattr(self, 'nested_user_functions', {}) or {}).values():
            _scan_function_for_global_decls(_fn)

        # Group merged top-level statements into internal per-file module-init blocks.
        # These init blocks are auto-called before main(args), are not user-visible,
        # and are guarded so each module runs at most once.
        def _group_program_by_file(stmts: List[Any]) -> List[Tuple[str, List[Any]]]:
            groups: List[Tuple[str, List[Any]]] = []
            cur_file: Optional[str] = None
            cur_items: List[Any] = []
            synthetic_idx = 0

            for st in stmts:
                st_file = getattr(st, '_filename', None)
                if not (isinstance(st_file, str) and st_file):
                    if cur_file is None:
                        st_file = f"<module:{synthetic_idx}>"
                        synthetic_idx += 1
                    else:
                        st_file = cur_file
                if cur_file is None:
                    cur_file = st_file
                if st_file != cur_file:
                    groups.append((cur_file, cur_items))
                    cur_file = st_file
                    cur_items = []
                cur_items.append(st)

            if cur_items:
                groups.append((cur_file or '<module:entry>', cur_items))
            return groups

        module_init_recs: List[Tuple[str, List[Any], str, str, str]] = []
        for _mid, (_mfile, _mstmts) in enumerate(_group_program_by_file(program), start=1):
            fn_lbl = f"modinit_{_mid}"
            flag_lbl = f"modinit_done_{_mid}"
            status_lbl = f"modinit_status_{_mid}"
            self.data.add_u64(flag_lbl, 0)
            self.data.add_u64(status_lbl, 0)  # 0=uninitialized, 1=initializing, 2=initialized
            self._module_init_status_labels[_mfile] = status_lbl
            module_init_recs.append((_mfile, _mstmts, fn_lbl, flag_lbl, status_lbl))

        # Auto-run internal module init blocks before main(args).
        # IMPORTANT: run them inline inside the entry frame.
        # Top-level stmt emission uses the entry scratch/expr-temp frame layout and
        # assumes the current RSP-based offsets are valid. Emitting them as separate
        # subroutines without a matching frame/prologue corrupts the stack/ABI.
        # We still keep internal per-module guard labels/flags so each block executes
        # at most once, but the execution itself stays inside the entry stub.
        for _mfile, _mstmts, _fn_lbl, _flag_lbl, _status_lbl in module_init_recs:
            _done_lbl = f"{_fn_lbl}_done"
            a.mov_rax_rip_qword(_flag_lbl)
            a.test_r64_r64('rax', 'rax')
            a.jcc('ne', _done_lbl)
            a.mov_r64_imm64('rax', 1)
            a.mov_rip_qword_rax(_flag_lbl)
            a.mov_r64_imm64('rax', 1)
            a.mov_rip_qword_rax(_status_lbl)
            _prev_active = getattr(self, '_module_init_active', False)
            _prev_file = getattr(self, '_module_init_active_file', None)
            self._module_init_active = True
            self._module_init_active_file = _mfile
            try:
                for _st in _mstmts:
                    self.emit_stmt(_st)
            finally:
                self._module_init_active = _prev_active
                self._module_init_active_file = _prev_file
            a.mov_r64_imm64('rax', 2)
            a.mov_rip_qword_rax(_status_lbl)
            a.mark(_done_lbl)

        # If main(args) exists (top-level), call it after executing top-level code.
        main_name = getattr(self, "main_function", None)
        if main_name:
            # args := build_args()  (argv[1..] as array<string>)
            a.call("fn_build_args")
            a.mov_r64_r64("rcx", "rax")  # RCX = args

            # call main(args)
            # r10 carries the incoming closure environment pointer (void for entry/main).
            a.mov_r64_imm64("r10", voidv)

            a.call(f"fn_user_{main_name}")

            # unhandled error from main: print + exit
            err_id = self.new_label_id()
            l_main_noerr = f"lbl_main_noerr_{err_id}"
            # if not ptr -> noerr
            a.mov_r64_r64("r11", "rax")
            a.and_r64_imm("r11", 7)
            a.cmp_r64_imm("r11", TAG_PTR)
            a.jcc("ne", l_main_noerr)
            # if not struct -> noerr
            a.mov_r32_membase_disp("edx", "rax", 0)
            a.cmp_r32_imm("edx", OBJ_STRUCT)
            a.jcc("ne", l_main_noerr)
            # if struct_id != ERROR_STRUCT_ID -> noerr
            a.mov_r32_membase_disp("edx", "rax", 8)
            a.cmp_r32_imm("edx", ERROR_STRUCT_ID)
            a.jcc("ne", l_main_noerr)
            # handle
            a.mov_r64_r64("rcx", "rax")
            a.call("fn_unhandled_error_exit")
            a.mark(l_main_noerr)

            # main return handling:
            # - int  -> ExitProcess(int)
            # - void -> ExitProcess(0)
            # - other -> ExitProcess(1)
            lbl_int = f"lbl_main_ret_int_{self.new_label_id()}"
            lbl_void = f"lbl_main_ret_void_{self.new_label_id()}"
            lbl_other = f"lbl_main_ret_other_{self.new_label_id()}"

            a.mov_r64_r64("r10", "rax")
            a.and_r64_imm("r10", 7)

            a.cmp_r64_imm("r10", TAG_INT)
            a.jcc("e", lbl_int)

            a.cmp_r64_imm("r10", TAG_VOID)
            a.jcc("e", lbl_void)

            # other: ExitProcess(1)
            a.mark(lbl_other)
            a.mov_rcx_imm32(1)
            a.mov_rax_rip_qword("iat_ExitProcess")
            a.call_rax()

            # void: ExitProcess(0)
            a.mark(lbl_void)
            a.xor_ecx_ecx()
            a.mov_rax_rip_qword("iat_ExitProcess")
            a.call_rax()

            # int: decode and ExitProcess
            a.mark(lbl_int)
            a.sar_r64_imm8("rax", 3)  # decode tagged int
            a.mov_r64_r64("rcx", "rax")  # RCX = exit code
            a.mov_rax_rip_qword("iat_ExitProcess")
            a.call_rax()

        # No main(): default ExitProcess(0)
        a.xor_ecx_ecx()
        a.mov_rax_rip_qword('iat_ExitProcess')
        a.call_rax()

        # Internal per-file module init blocks currently execute inline in the
        # entry stub (see above) so they share the entry frame/scratch area.
        # We intentionally do not emit standalone call/ret bodies here yet.

        # User function bodies appended.
        #
        # With first-class functions / indirect calls, we can no longer soundly prune
        # user functions based on static reachability. We therefore emit *all* user
        # functions so taking their address and calling via values always works.
        for nm in sorted(self.user_functions.keys()):
            self.emit_user_function(self.user_functions[nm])

        for nm in sorted(getattr(self, 'nested_user_functions', {}).keys()):
            self.emit_user_function(self.nested_user_functions[nm])

        # Extern stubs appended (stub-only externs as OBJ_BUILTIN values).
        if hasattr(self, 'emit_extern_stubs'):
            self.emit_extern_stubs()  # type: ignore[attr-defined]

        # Refresh global slots now that all top-level/global bindings have been discovered.
        # NOTE: CodegenCore snapshots scope_global_slots at init time; we need the up-to-date list
        # for GC root scanning (gc_collect) to keep globals alive.
        try:
            self.global_slots = self.scope_global_slots  # type: ignore[attr-defined]
        except Exception:
            pass

        # Internal helpers: only emit what was actually referenced

        self.emit_used_helpers()

    # ---------- user functions ----------

    def emit_user_function(self, fn: Any) -> None:
        """Emit a top-level MiniLang function as a native subroutine.

        Step 10: function codegen is now compatible with lexical block scopes and true shadowing.

        Key properties:
        - Parameters are bound in the function root scope (depth 0).
        - First write introduces a new binding in the current lexical scope (unless an outer binding exists).
        - Reads of an undefined name raise a CompileError (read-before-write / out-of-scope).
        - Shadowing inside nested blocks creates a *new* binding (new stack slot), not slot-reuse by name.

        Implementation strategy:
        - Run a lightweight lexical analysis pass over the function body to pre-allocate
          VarBindings for first-writes (decl sites), so stack slots can be laid out
          before emitting the prologue.
        - During real emission, stores pass the AST node so the decl-site binding can be
          looked up and installed into the current scope.
        """
        ml = self.ml
        a = self.asm

        if not isinstance(fn, ml.FunctionDef):
            return

        # ---- maximum call arity inside this function ----
        def max_calls_expr(e):
            m = 0
            if e is None:
                return 0
                # Struct member read: obj.field
                if hasattr(ml, 'Member') and isinstance(e, ml.Member):
                    t = getattr(e, 'target', None)
                    if t is None:
                        t = getattr(e, 'obj', None)
                    analyze_expr(t)
                    return

            if isinstance(e, ml.Call):
                call_arity = len(e.args)
                try:
                    cal = e.callee
                    if hasattr(ml, 'Member') and isinstance(cal, ml.Member):
                        mname = getattr(cal, 'name', None)
                        if isinstance(mname, str):
                            for _s, _md in (getattr(self, 'struct_methods', {}) or {}).items():
                                if mname in (_md or {}):
                                    call_arity += 1
                                    break
                except Exception:
                    pass
                m = max(m, call_arity)
                m = max(m, max_calls_expr(e.callee))
                for aa in e.args:
                    m = max(m, max_calls_expr(aa))
                return m
            if isinstance(e, ml.Unary):
                return max_calls_expr(e.right)
            if isinstance(e, ml.Bin):
                return max(max_calls_expr(e.left), max_calls_expr(e.right))
            if isinstance(e, ml.ArrayLit):
                for it in e.items:
                    m = max(m, max_calls_expr(it))
                return m
            if isinstance(e, ml.Index):
                return max(max_calls_expr(e.target), max_calls_expr(e.index))
            if isinstance(e, getattr(ml, 'StructInit', ())):
                for v in e.values:
                    m = max(m, max_calls_expr(v))
                return m
            # literals / vars
            return 0

        def max_calls_stmts(stmts):
            m = 0
            for st in stmts:
                if isinstance(st, ml.Assign):
                    m = max(m, max_calls_expr(st.expr))
                elif isinstance(st, ml.Print):
                    m = max(m, max_calls_expr(st.expr))
                elif isinstance(st, ml.ExprStmt):
                    m = max(m, max_calls_expr(st.expr))
                elif isinstance(st, ml.If):
                    m = max(m, max_calls_expr(st.cond))
                    m = max(m, max_calls_stmts(st.then_body))
                    for ec, eb in st.elifs:
                        m = max(m, max_calls_expr(ec))
                        m = max(m, max_calls_stmts(eb))
                    m = max(m, max_calls_stmts(st.else_body))
                elif isinstance(st, ml.While):
                    m = max(m, max_calls_expr(st.cond))
                    m = max(m, max_calls_stmts(st.body))
                elif isinstance(st, ml.DoWhile):
                    m = max(m, max_calls_stmts(st.body))
                    m = max(m, max_calls_expr(st.cond))
                elif isinstance(st, ml.For):
                    m = max(m, max_calls_expr(st.start))
                    m = max(m, max_calls_expr(st.end))
                    m = max(m, max_calls_stmts(st.body))
                elif self._is_foreach_stmt(st):
                    m = max(m, max_calls_expr(st.iterable))
                    m = max(m, max_calls_stmts(st.body))
                elif isinstance(st, ml.Switch):
                    m = max(m, max_calls_expr(st.expr))
                    for cs in st.cases:
                        if cs.kind == 'values':
                            for v in cs.values:
                                m = max(m, max_calls_expr(v))
                        else:
                            m = max(m, max_calls_expr(cs.range_start))
                            m = max(m, max_calls_expr(cs.range_end))
                        m = max(m, max_calls_stmts(cs.body))
                    m = max(m, max_calls_stmts(st.default_body))
                elif isinstance(st, ml.Return):
                    m = max(m, max_calls_expr(st.expr))
                elif isinstance(st, ml.FunctionDef):
                    # ignore nested defs (unsupported in native)
                    pass
            return m

        # See emit_program(): stack call-arg scratch is sized to the global maximum
        # to stay safe under inlining.
        max_call_args = int(getattr(self, "_max_call_args_global", 0) or 0)
        if max_call_args <= 0:
            max_call_args = max_calls_stmts(fn.body)

        # ---- lexical analysis: pre-allocate local bindings + decl-site map ----
        # We keep global bindings visible via resolve_binding() fallback, but start with an empty
        # function scope stack so locals/params live only inside the function.
        if not hasattr(self, "analysis_reset_function") or not hasattr(self, "register_decl_site_binding"):
            raise self.error(
                "Internal compiler error: scope analysis helpers missing (update mlc/codegen/codegen_scope.py).", fn)

        # Save & clear function-specific analysis state.
        # (decl-site bindings are only needed while emitting this function)
        saved_decl_site = dict(getattr(self, "_decl_site_bindings", {}))
        saved_fn_locals = list(getattr(self, "_function_locals", []))

        self.analysis_reset_function()

        saved_stack = getattr(self, "_scope_stack", None)
        saved_declared = getattr(self, "_scope_declared", None)
        saved_in_fn = getattr(self, "in_function", False)
        _saved_ctx_file = getattr(self, "_current_fn_file", None)
        _saved_ctx_qname = getattr(self, "_current_fn_qname", None)
        # Builtin call identifiers are not variables; they may be used as callees without prior assignment.
        builtin_callees = {'try', "input", "len", "toNumber", "typeof", "bytes", "byteBuffer", "decode", "decodeZ",
            "decode16Z", "hex", "fromHex", "slice", "typeName", "heap_count", "heap_bytes_used", "heap_bytes_committed",
            "heap_bytes_reserved", "heap_free_bytes", "heap_free_blocks", "gc_collect", "gc_set_limit", "callStats" }
        # Function identifiers (top-level defs) are also not variables, but may appear in call/typeof contexts.
        allowed_function_names = set(getattr(self, "user_functions", {}).keys())
        # Struct type identifiers are not variables; they may be used as callees (Point(...))
        # and as typeof() arguments without requiring 'global'.
        allowed_struct_names = set(getattr(self, 'struct_fields', {}).keys())
        allowed_extern_names = set(getattr(self, 'extern_sigs', {}).keys())
        if getattr(fn, "name", None):
            allowed_function_names.add(fn.name)

        boxed_names = set(getattr(fn, "_ml_boxed", set()) or set())

        def analyze_read_var(node, name: str) -> None:
            b = self.resolve_binding(name)
            if b is None:
                raise self.error(f"Undefined variable '{name}'", node)
            if getattr(self, 'in_function', False) and getattr(b, 'kind', None) == 'global':
                caps = getattr(self, '_func_captures', None)
                if isinstance(caps, set):
                    caps.add(name)

        def analyze_write_var(node, name: str) -> None:
            # Writes update nearest existing binding; otherwise introduce in current scope.
            if self.resolve_binding_for_write(name) is not None:
                return
            b = self.declare_local_binding(name, node=node, offset=None)
            if name in boxed_names:
                b.boxed = True
            self.register_decl_site_binding(node, name, b)

        def analyze_expr(e, *, allow_func_ident: bool = False):

            if e is None:
                return

            if isinstance(e, ml.Var):

                # Apply compile-time import aliases for qualified names.
                nm0 = self._apply_import_alias(str(e.name))

                # Apply package/namespace qualification so unqualified references inside
                # `package`/`namespace` files resolve to their qualified declarations.
                nm = nm0
                try:
                    if hasattr(self, '_qualify_identifier'):
                        nm = self._qualify_identifier(nm0, e)
                except Exception:
                    nm = nm0

                # Allow certain identifiers in special contexts (callee / typeof arg).
                if allow_func_ident:
                    if (nm0 in builtin_callees) or (nm in builtin_callees):
                        return
                    if nm in allowed_function_names:
                        return
                    if nm in allowed_struct_names:
                        return
                    if nm in allowed_extern_names:
                        return

                analyze_read_var(e, nm)
                return

            if isinstance(e, ml.Call):

                # Builtin direct calls: don't treat the callee identifier as a variable read.

                if isinstance(e.callee, ml.Var) and self._apply_import_alias(str(e.callee.name)) in builtin_callees:

                    cal = self._apply_import_alias(str(e.callee.name))

                    if cal in ("typeof", "typeName"):

                        for aa in e.args:
                            analyze_expr(aa, allow_func_ident=True)


                    else:

                        for aa in e.args:
                            analyze_expr(aa)

                    return

                # Direct call to known user function: also not a variable read of the callee.

                if isinstance(e.callee, ml.Var) and self._apply_import_alias(
                        str(e.callee.name)) in allowed_function_names:

                    for aa in e.args:
                        analyze_expr(aa)

                    return

                # Direct call to a known struct type (constructor): callee is not a variable read.
                if isinstance(e.callee, ml.Var) and self._apply_import_alias(
                        str(e.callee.name)) in allowed_struct_names:

                    for aa in e.args:
                        analyze_expr(aa)

                    return

                # Direct call to known extern function: callee is not a variable read.
                if isinstance(e.callee, ml.Var) and self._apply_import_alias(
                        str(e.callee.name)) in allowed_extern_names:

                    for aa in e.args:
                        analyze_expr(aa)

                    return

                # Qualified member-call (package/namespace via import alias):
                # If the callee is `alias.foo(...)` where `alias` is an import alias (or a fully-qualified
                # function name like `std.fs.delete(...)`), we must NOT treat the left-most identifier
                # as a runtime variable read.
                if isinstance(e.callee, ml.Member):

                    def _flatten_member_chain(node):
                        parts = []
                        cur = node
                        while isinstance(cur, ml.Member):
                            parts.append(str(cur.name))
                            cur = cur.target
                        if isinstance(cur, ml.Var):
                            parts.append(str(cur.name))
                            parts.reverse()
                            return ".".join(parts)
                        return None

                    qn0 = _flatten_member_chain(e.callee)
                    if isinstance(qn0, str) and qn0:
                        parts0 = qn0.split(".")
                        aliases0 = getattr(self, "import_aliases", None) or {}
                        qn = qn0
                        if parts0 and parts0[0] in aliases0:
                            ali = str(aliases0[parts0[0]])
                            if ali:
                                qn = ".".join(ali.split(".") + parts0[1:])
                            # base is an import alias, never a runtime variable
                            for aa in e.args:
                                analyze_expr(aa)
                            return

                        # Not an alias: if this resolves to a known function/extern/struct constructor,
                        # treat it as a compile-time qualified name.
                        if qn in allowed_function_names or qn in allowed_extern_names or qn in allowed_struct_names:
                            for aa in e.args:
                                analyze_expr(aa)
                            return

                analyze_expr(e.callee)

                for aa in e.args:
                    analyze_expr(aa)

                return

            if isinstance(e, ml.Unary):
                analyze_expr(e.right)
                return

            if isinstance(e, ml.Bin):
                analyze_expr(e.left)
                analyze_expr(e.right)
                return

            if isinstance(e, ml.ArrayLit):
                for it in e.items:
                    analyze_expr(it)
                return

            if isinstance(e, ml.Index):
                analyze_expr(e.target)
                analyze_expr(e.index)
                return

            if isinstance(e, getattr(ml, 'StructInit', ())):
                for v in e.values:
                    analyze_expr(v)
                return

            # literals (Num/Bool/Str/EnumLit/...) have no reads
            return

        def analyze_block(stmts):
            for st in stmts:
                # global x, y (function scope declaration)
                if hasattr(ml, 'GlobalDecl') and isinstance(st, ml.GlobalDecl):
                    for nm in getattr(st, 'names', []) or []:
                        # Option B: requires existing global
                        if hasattr(self, 'declare_function_global'):
                            self.declare_function_global(nm, node=st)
                        else:
                            raise self.error("Internal: global not supported (missing declare_function_global)", st)
                    continue
                if isinstance(st, ml.Assign):
                    analyze_expr(st.expr)
                    analyze_write_var(st, st.name)
                    continue
                # struct member write: obj.field = expr
                if hasattr(ml, 'SetMember') and isinstance(st, ml.SetMember):
                    analyze_expr(getattr(st, 'obj', getattr(st, 'target', None)))
                    analyze_expr(getattr(st, 'expr', None))
                    continue
                if isinstance(st, ml.SetIndex):
                    analyze_expr(st.target)
                    analyze_expr(st.index)
                    analyze_expr(st.expr)
                    continue
                if isinstance(st, ml.Print):
                    analyze_expr(st.expr)
                    continue
                if isinstance(st, ml.ExprStmt):
                    analyze_expr(st.expr)
                    continue
                if isinstance(st, ml.Return):
                    analyze_expr(st.expr)
                    continue
                if isinstance(st, ml.If):
                    analyze_expr(st.cond)
                    # then
                    self.push_scope()
                    analyze_block(st.then_body)
                    self.pop_scope(emit_cleanup=False)
                    # elifs
                    for ec, eb in st.elifs:
                        analyze_expr(ec)
                        self.push_scope()
                        analyze_block(eb)
                        self.pop_scope(emit_cleanup=False)
                    # else
                    if st.else_body:
                        self.push_scope()
                        analyze_block(st.else_body)
                        self.pop_scope(emit_cleanup=False)
                    continue
                if isinstance(st, ml.While):
                    analyze_expr(st.cond)
                    self.push_scope()
                    analyze_block(st.body)
                    self.pop_scope(emit_cleanup=False)
                    continue
                if isinstance(st, ml.DoWhile):
                    self.push_scope()
                    analyze_block(st.body)
                    self.pop_scope(emit_cleanup=False)
                    analyze_expr(st.cond)
                    continue
                if isinstance(st, ml.For):
                    analyze_expr(st.start)
                    analyze_expr(st.end)
                    self.push_scope()
                    # loop var is an implicit *fresh* declaration (must not clobber outer vars)
                    b = self.declare_local_binding(st.var, node=st, offset=None)
                    if isinstance(st.var, str) and st.var in boxed_names:
                        b.boxed = True
                    self.register_decl_site_binding(st, st.var, b)
                    analyze_block(st.body)
                    self.pop_scope(emit_cleanup=False)
                    continue
                if isinstance(st, ml.ForEach):
                    analyze_expr(st.iterable)
                    self.push_scope()
                    # loop var is an implicit *fresh* declaration (must not clobber outer vars)
                    b = self.declare_local_binding(st.var, node=st, offset=None)
                    if isinstance(st.var, str) and st.var in boxed_names:
                        b.boxed = True
                    self.register_decl_site_binding(st, st.var, b)
                    analyze_block(st.body)
                    self.pop_scope(emit_cleanup=False)
                    continue
                if isinstance(st, ml.Switch):
                    analyze_expr(st.expr)
                    for cs in st.cases:
                        self.push_scope()
                        if cs.kind == 'values':
                            for v in cs.values:
                                analyze_expr(v)
                        else:
                            analyze_expr(cs.range_start)
                            analyze_expr(cs.range_end)
                        analyze_block(cs.body)
                        self.pop_scope(emit_cleanup=False)
                    if st.default_body:
                        self.push_scope()
                        analyze_block(st.default_body)
                        self.pop_scope(emit_cleanup=False)
                    continue
                if hasattr(ml, 'StructDef') and isinstance(st, ml.StructDef):
                    raise self.error('struct definitions are only allowed at top-level', st)
                if isinstance(st, ml.FunctionDef):
                    # Nested function defs introduce a local binding at the decl site.
                    analyze_write_var(st, st.name)
                    continue
                # break/continue/enum/etc.: no reads
                continue

        try:
            # isolated function scope stack for analysis
            if saved_stack is not None:
                base_globals = {}
                try:
                    if saved_stack and len(saved_stack) > 0:
                        base_globals = dict(saved_stack[0])
                except Exception:
                    base_globals = {}
                # Scope[0] = globals (readable), Scope[1] = function locals/params
                self._scope_stack = [base_globals, {}]
            if saved_declared is not None:
                self._scope_declared = [[], []]
            self.in_function = True
            # Set package/namespace resolution context for the analysis pass.
            try:
                fn_file = getattr(fn, '_filename', None)
                if isinstance(fn_file, str) and fn_file:
                    self._current_fn_file = fn_file
                fn_qn = getattr(fn, 'name', None)
                if isinstance(fn_qn, str) and fn_qn:
                    self._current_fn_qname = fn_qn
            except Exception:
                pass

            # Step 6.2b-2b-1: declare capture bindings (metadata-only)
            self._closure_declare_capture_bindings(fn)

            # Mark parameters as defined (no read-before-write error).
            # Offsets are laid out later; bind with placeholder 0.
            for p in fn.params:
                b = self.bind_param(p, 0, node=fn)
                pname = p if isinstance(p, str) else None
                if pname is None:
                    try:
                        pname = self._coerce_name(p)
                    except Exception:
                        pname = None
                if pname is not None and pname in boxed_names:
                    b.boxed = True

            analyze_block(fn.body)

        finally:
            # restore compiler state (analysis shouldn't change codegen scopes)
            if saved_stack is not None:
                self._scope_stack = saved_stack
            if saved_declared is not None:
                self._scope_declared = saved_declared
            self._current_fn_file = _saved_ctx_file
            self._current_fn_qname = _saved_ctx_qname
            self.in_function = saved_in_fn
        # Now `_function_locals` contains *bindings*, not names.
        n_locals = len(getattr(self, "_function_locals", []))

        # ---- stack layout ----
        # [rsp+0x00..0x1F] shadow space for calls (Windows x64)
        # [rsp+0x20..] outgoing stack args for calls (arg5+) + scratch (WriteFile overlapped)
        out_stack_args = max(0, max_call_args - 4)
        out_scratch = 8  # at least 8 bytes at [rsp+0x20] for misc scratch

        # Save/restore debug-loc globals across calls (script/func/line).
        # This must NOT overlap with outgoing stack args or scratch (it must survive the whole function).
        dbg_save_size = 24
        dbg_save_base = 0x20 + max(out_scratch, out_stack_args * 8)

        # outgoing stack args for calls (arg5+) + scratch + debug-loc save area
        out_reserve = max(out_scratch, out_stack_args * 8) + dbg_save_size

        # locals start after outgoing-args area, aligned to 16 bytes
        local_base = align_up(0x20 + out_reserve, 16)

        # Reserve one hidden root slot for the current closure environment pointer.
        # This slot is part of the GC root range so env frames stay alive across allocations.
        env_root_off = local_base
        locals_base = local_base + 8

        local_bytes = n_locals * 8
        params_base = locals_base + local_bytes

        # call-temp slots: spill evaluated call arguments
        call_temp_base = params_base + len(fn.params) * 8
        call_temp_bytes = align_up(max(0x40, max_call_args * 8), 16)

        # expression temp arena starts after call-temp area
        expr_temp_base = call_temp_base + call_temp_bytes

        frame_end = expr_temp_base + self.expr_temp_max

        # Reserve space for GC shadow-stack root-frame record (32 bytes).
        frame_size = align_up(frame_end + 0x20, 16)
        root_rec_off = frame_size - 0x20
        root_base = local_base
        root_top = expr_temp_base + self.expr_temp_max
        # Assign offsets for the preallocated local bindings.
        self.analysis_layout_function_locals(locals_base)

        code_name = getattr(fn, '_ml_codegen_name', fn.name)

        fn_label = f"fn_user_{code_name}"
        ret_label = f"fn_ret_{code_name}"

        a.mark(fn_label)

        # Preserve nonvolatile registers we use elsewhere (RBX holds stdout handle)
        a.push_rbx()
        a.push_r12()
        a.push_r13()
        a.push_r14()
        a.push_r15()

        # Reserve stack space (shadow + locals + temps). Must stay 16-byte aligned here.
        a.sub_rsp_imm32(frame_size)

        # Runtime trace: print function name on entry (enabled with --trace-calls).
        # NOTE: emit_writefile performs Win64 calls and clobbers volatile regs.
        if bool(getattr(self, 'trace_calls', False)):
            a.push_reg("rcx")
            a.push_reg("rdx")
            a.push_reg("r8")
            a.push_reg("r9")

            # Prefer qualified function name if available.
            try:
                trace_name = str(getattr(fn, '_ml_display_name', None) or getattr(fn, 'name', None) or code_name)
            except Exception:
                trace_name = str(code_name)

            lbl_tr = f"trace_call_{len(self.rdata.labels)}"
            self.rdata.add_str(lbl_tr, trace_name, add_newline=True)
            try:
                tr_len = int(self.rdata.labels[lbl_tr][1])
            except Exception:
                tr_len = len((trace_name + "\n").encode("utf-8"))
            self.emit_writefile_stderr(lbl_tr, tr_len)

            a.pop_reg("r9")
            a.pop_reg("r8")
            a.pop_reg("rdx")
            a.pop_reg("rcx")

        # Call profiling counter increment (enabled only with --profile-calls)
        if bool(getattr(self, 'call_profile', False)):
            try:
                idx_cp = (getattr(self, '_callprof_index', {}) or {}).get(str(code_name))
            except Exception:
                idx_cp = None
            if idx_cp is not None:
                a.lea_r11_rip('callprof_counts')
                a.inc_membase_disp_qword('r11', int(idx_cp) * 8)

        # ---- debug script/function context ----

        # Save previous debug-loc globals so the caller context is restored on return.
        # (Prevents errors after a nested call from reporting the wrong function.)
        a.mov_rax_rip_qword('dbg_loc_script')
        a.mov_membase_disp_r64('rsp', dbg_save_base + 0, 'rax')
        a.mov_rax_rip_qword('dbg_loc_func')
        a.mov_membase_disp_r64('rsp', dbg_save_base + 8, 'rax')
        a.mov_rax_rip_qword('dbg_loc_line')
        a.mov_membase_disp_r64('rsp', dbg_save_base + 16, 'rax')
        # Store current script + function name into global debug-loc slots.
        # This lets builtins attach callsite information when they construct an `error`.
        try:
            fn_file0 = getattr(fn, '_filename', None)
        except Exception:
            fn_file0 = None
        try:
            fn_name0 = getattr(fn, 'name', None)
        except Exception:
            fn_name0 = None

        script_s = None
        if isinstance(fn_file0, str) and fn_file0:
            try:
                script_s = (getattr(self, '_pretty_script', None) or (lambda x: x))(fn_file0)
            except Exception:
                script_s = fn_file0
        if not isinstance(script_s, str) or not script_s:
            script_s = str(getattr(self, 'filename', '') or '')

        func_s = str(fn_name0) if isinstance(fn_name0, str) and fn_name0 else str(code_name)

        lbl_sc = f"dbg_sc_{len(self.rdata.labels)}"
        self.rdata.add_obj_string(lbl_sc, script_s)
        a.lea_rax_rip(lbl_sc)
        a.mov_rip_qword_rax('dbg_loc_script')

        lbl_fn = f"dbg_fn_{len(self.rdata.labels)}"
        self.rdata.add_obj_string(lbl_fn, func_s)
        a.lea_rax_rip(lbl_fn)
        a.mov_rip_qword_rax('dbg_loc_func')

        # ---- GC shadow stack roots (Part A) ----

        # Clear all root slots (locals + params + temps) to VOID so GC doesn't keep stale values alive.
        self.emit_gc_clear_root_slots(root_base, root_top)

        # Push function root-frame record at [rsp+root_rec_off] and link it into gc_roots_head.
        self.emit_gc_push_root_frame(root_rec_off, root_base, root_top)

        # Save incoming closure environment (passed in r10) in a nonvolatile register.
        a.mov_r64_r64("r14", "r10")

        # ---- set function context ----
        old_in = self.in_function
        old_params = self.func_param_offsets
        old_locals = self.func_local_offsets
        old_ret = self.func_ret_label
        old_ctb = self.call_temp_base
        old_etb = self.expr_temp_base
        old_ett = self.expr_temp_top

        # Save/override scope stack for real emission (function-local only)
        saved_emit_stack = getattr(self, "_scope_stack", None)
        saved_emit_declared = getattr(self, "_scope_declared", None)

        self.in_function = True
        self.func_param_offsets = {}
        self.func_local_offsets = {}
        self.func_ret_label = ret_label
        self.call_temp_base = call_temp_base
        self.expr_temp_base = expr_temp_base
        self.expr_temp_top = 0

        if saved_emit_stack is not None:
            base_globals = {}
            try:
                if saved_emit_stack and len(saved_emit_stack) > 0:
                    base_globals = dict(saved_emit_stack[0])
            except Exception:
                base_globals = {}
            self._scope_stack = [base_globals, {}]
        if saved_emit_declared is not None:
            self._scope_declared = [[], []]

        # Step 6.2b-2b-1: declare capture bindings (metadata-only)
        self._closure_declare_capture_bindings(fn)

        # Spill incoming parameters into stack slots and bind them in scope.
        for i, p in enumerate(fn.params):
            off = params_base + i * 8
            self.func_param_offsets[p] = off

            if i == 0:
                a.mov_r64_r64("rax", "rcx")  # mov rax,rcx
            elif i == 1:
                a.mov_r64_r64("rax", "rdx")  # mov rax,rdx
            elif i == 2:
                a.mov_r64_r64("rax", "r8")  # mov rax,r8
            elif i == 3:
                a.mov_r64_r64("rax", "r9")  # mov rax,r9
            else:
                # stack args start at [entry_rsp + 0x28]
                # after pushes+sub in our prologue, that becomes:
                #   [rsp + frame_size + 0x50 + 8*(i-4)]
                a.mov_rax_rsp_disp32(frame_size + 0x50 + (i - 4) * 8)

            a.mov_rsp_disp32_rax(off)
            # bind param in root scope so reads work
            b = self.bind_param(p, off, node=fn)
            try:
                pn = self._coerce_name(p)
            except Exception:
                pn = p if isinstance(p, str) else str(p)
            if pn in boxed_names:
                b.boxed = True

        # ---- closure environment (Step 6.2d-1: env elision) ----
        #
        # Captured variable access assumes r15 points to a *current* env object whose
        # [env+8] links to the parent env. Therefore we only elide env allocation for
        # functions that do not participate in closures at all.
        #
        # We still materialize empty env frames for:
        #   - functions that have captures themselves (_ml_captures)
        #   - intermediate "env hop" functions for grandparent+ captures (_ml_env_hop)
        #   - functions that own boxed vars (_ml_env_slots)
        env_slots = list(getattr(fn, "_ml_env_slots", []) or [])
        has_caps = bool(getattr(fn, "_ml_captures", set()) or set())
        env_hop = bool(getattr(fn, "_ml_env_hop", False))
        need_env = has_caps or env_hop or (len(env_slots) > 0)

        # Build a mapping from env slot name -> stack slot offset.
        param_off: dict[str, int] = {}
        for i, p in enumerate(fn.params):
            try:
                nm = self._coerce_name(p)
            except Exception:
                nm = p if isinstance(p, str) else str(p)
            param_off[nm] = params_base + i * 8

        local_off: dict[str, int] = {}
        local_count: dict[str, int] = {}
        for bnd in (getattr(self, "_function_locals", []) or []):
            nm = getattr(bnd, "name", None)
            if not isinstance(nm, str) or not nm:
                continue
            off = getattr(bnd, "offset", None)
            if off is None:
                continue
            local_count[nm] = local_count.get(nm, 0) + 1
            if nm not in local_off:
                local_off[nm] = int(off)

        slot_off: dict[str, int] = {}
        for nm in env_slots:
            has_param = nm in param_off
            lcnt = local_count.get(nm, 0)
            # Reject any shadowing/duplication for captured names for now.
            if (has_param and lcnt > 0) or lcnt > 1:
                raise self.error(f"Shadowing of captured variable '{nm}' is not supported yet (Step 6.2c)", fn, )
            if has_param:
                slot_off[nm] = int(param_off[nm])
            elif lcnt == 1:
                slot_off[nm] = int(local_off[nm])
            else:
                raise self.error(f"Internal compiler error: captured name '{nm}' has no slot", fn, )

        if need_env:
            # Box captured locals/params and write the cell pointer back into the variable slot.
            for nm in env_slots:
                off = slot_off[nm]
                # r12 = initial value (from slot)
                a.mov_r64_membase_disp("r12", "rsp", off)
                # alloc box (16 bytes)
                a.mov_rcx_imm32(16)
                a.call("fn_alloc")
                a.mov_r64_r64("r11", "rax")
                a.mov_membase_disp_imm32("r11", 0, OBJ_BOX, qword=False)
                a.mov_membase_disp_imm32("r11", 4, 0, qword=False)
                a.mov_membase_disp_r64("r11", 8, "r12")
                # overwrite variable slot with box pointer
                a.mov_rsp_disp32_rax(off)

            # Allocate env frame: 16-byte header + N slots.
            env_n = len(env_slots)
            a.mov_rcx_imm32(16 + env_n * 8)
            a.call("fn_alloc")
            a.mov_r64_r64("r11", "rax")
            a.mov_membase_disp_imm32("r11", 0, OBJ_ENV, qword=False)
            a.mov_membase_disp_imm32("r11", 4, env_n, qword=False)
            # parent = incoming env (VOID if not needed / not provided)
            a.mov_membase_disp_r64("r11", 8, "r14")
            # slots = pointers to boxes
            for i, nm in enumerate(env_slots):
                off = slot_off[nm]
                a.mov_r64_membase_disp("r10", "rsp", off)
                a.mov_membase_disp_r64("r11", 16 + i * 8, "r10")

            # Current env pointer lives in r15 (and in the hidden root slot for GC).
            a.mov_r64_r64("r15", "r11")
            a.mov_rsp_disp32_rax(env_root_off)
        else:
            # No env needed at all.
            a.mov_r64_imm64("r15", enc_void())
            a.mov_r64_imm64("rax", enc_void())
            a.mov_rsp_disp32_rax(env_root_off)

        # ---- body ----
        old_qpref = getattr(self, 'current_qname_prefix', '')
        _old_fn_qn = getattr(self, '_current_fn_qname', None)
        _old_fn_file = getattr(self, '_current_fn_file', None)
        try:
            qpref = ''
            fn_qn = getattr(fn, 'name', '')
            if isinstance(fn_qn, str) and '.' in fn_qn:
                qpref = fn_qn.rsplit('.', 1)[0] + '.'
            self.current_qname_prefix = qpref

            # Keep CodegenCore package/namespace resolution context in sync.
            if isinstance(fn_qn, str) and fn_qn:
                self._current_fn_qname = fn_qn
            fn_file = getattr(fn, '_filename', None)
            if isinstance(fn_file, str) and fn_file:
                self._current_fn_file = fn_file
        except Exception:
            self.current_qname_prefix = old_qpref
            self._current_fn_qname = _old_fn_qn
            self._current_fn_file = _old_fn_file

        try:
            for st in fn.body:
                self.emit_stmt(st)
        finally:
            self.current_qname_prefix = old_qpref
            self._current_fn_qname = _old_fn_qn
            self._current_fn_file = _old_fn_file

        # Default return void
        a.mov_rax_imm64(enc_void())
        a.jmp(ret_label)

        # ---- epilogue ----
        a.mark(ret_label)
        # Pop GC root-frame record (must not clobber RAX return value)
        self.emit_gc_pop_root_frame(root_rec_off)

        # Restore previous debug-loc globals (do not clobber RAX return value).
        a.mov_r64_membase_disp("r11", "rsp", dbg_save_base + 0)
        a.mov_rip_qword_r11('dbg_loc_script')
        a.mov_r64_membase_disp("r11", "rsp", dbg_save_base + 8)
        a.mov_rip_qword_r11('dbg_loc_func')
        a.mov_r64_membase_disp("r11", "rsp", dbg_save_base + 16)
        a.mov_rip_qword_r11('dbg_loc_line')

        # restore scope stack
        if saved_emit_stack is not None:
            self._scope_stack = saved_emit_stack
        if saved_emit_declared is not None:
            self._scope_declared = saved_emit_declared

        # restore context
        self.in_function = old_in
        self.func_param_offsets = old_params
        self.func_local_offsets = old_locals
        self.func_ret_label = old_ret
        self.call_temp_base = old_ctb
        self.expr_temp_base = old_etb
        self.expr_temp_top = old_ett

        a.add_rsp_imm32(frame_size)
        a.pop_r15()
        a.pop_r14()
        a.pop_r13()
        a.pop_r12()
        a.pop_rbx()
        a.ret()

        # restore analysis state for outer compilation (other functions)
        self._decl_site_bindings = saved_decl_site
        self._function_locals = saved_fn_locals
