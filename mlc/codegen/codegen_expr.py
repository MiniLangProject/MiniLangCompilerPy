"""
MiniLang -> x86-64 machine code generation for Windows (PE32+).
"""

from __future__ import annotations

import os
import re
from typing import Any, List, Optional

from ..constants import (TAG_PTR, TAG_INT, TAG_BOOL, TAG_VOID, TAG_ENUM, OBJ_STRING, OBJ_ARRAY, OBJ_BYTES, OBJ_FUNCTION,
                         OBJ_FLOAT, OBJ_STRUCT, ERROR_STRUCT_ID, ERR_EXTERN_CONVERSION, ERR_EXTERN_RET_WSTR_CONVERSION,
                         ERR_CALL_NOT_CALLABLE, ERR_METHOD_NOT_FOUND, ERR_VOID_OP, OBJ_STRUCTTYPE, OBJ_BUILTIN, WIDEBUF_SIZE, )
from ..errors import CompileError
from ..tools import align_up, enc_int, enc_bool, enc_void, enc_enum, align_to_mod


class CodegenExpr:

    # ------------------------------------------------------------
    # Optimizer Step 4: constant folding (safe subset)
    # ------------------------------------------------------------
    # We fold *pure* expressions to reduce runtime work and enable
    # statement-level simplifications (if/while with constant conditions).
    #
    # Conservative rules:
    # - Only literals, const bindings with known compile-time values,
    #   and unary/binops are considered.
    # - No calls, indexing, member loads on runtime values, allocations, etc.
    # - We match runtime "truthiness" used by emit_jmp_if_false_rax.

    _OPT_NO = object()

    @staticmethod
    def _opt_truthy(v: Any) -> bool:
        if v is None:
            return False
        if isinstance(v, bool):
            return bool(v)
        if isinstance(v, (int, float)):
            return v != 0
        if isinstance(v, str):
            return v != ""
        return bool(v)

    def _opt_try_const_value(self, e: Any) -> Any:
        """Try to evaluate `e` to a Python value (safe subset).

        Returns:
            A Python value (int/float/bool/str) if `e` is foldable, else _OPT_NO.
        """
        ml = self.ml

        if e is None:
            return self._OPT_NO

        # literals
        if isinstance(e, ml.Num):
            return e.value
        if hasattr(ml, 'Bool') and isinstance(e, ml.Bool):
            return bool(getattr(e, 'value', False))
        if hasattr(ml, 'Str') and isinstance(e, ml.Str):
            return str(getattr(e, 'value', ''))

        # const binding reads (incl. package/namespace resolution)
        if hasattr(ml, 'Var') and isinstance(e, ml.Var):
            nm = self._qualify_identifier(str(getattr(e, 'name', '')), e)
            b = None
            try:
                b = self.resolve_binding(nm) if hasattr(self, 'resolve_binding') else None
            except Exception:
                b = None
            if b is None:
                return self._OPT_NO
            if not getattr(b, 'is_const', False):
                return self._OPT_NO
            pyv = getattr(b, 'const_value_py', None)
            if pyv is None:
                return self._OPT_NO
            if isinstance(pyv, (bool, int, float, str)):
                return pyv
            return self._OPT_NO

        # Member chains used as qualified names (best-effort const lookup)
        if hasattr(ml, 'Member') and isinstance(e, ml.Member):
            def _qname_parts(expr: Any) -> Optional[List[str]]:
                if hasattr(ml, 'Var') and isinstance(expr, ml.Var):
                    nm0 = str(getattr(expr, 'name', ''))
                    return nm0.split('.') if '.' in nm0 else [nm0]
                if hasattr(ml, 'Member') and isinstance(expr, ml.Member):
                    tgt = getattr(expr, 'target', None)
                    if tgt is None:
                        tgt = getattr(expr, 'obj', None)
                    base = _qname_parts(tgt)
                    if base is None:
                        return None
                    nm1 = getattr(expr, 'name', None)
                    if nm1 is None:
                        nm1 = getattr(expr, 'field', None)
                    if nm1 is None:
                        return None
                    return base + [str(nm1)]
                return None

            parts = _qname_parts(e)
            if parts is None:
                return self._OPT_NO
            full = self._apply_import_alias('.'.join(parts))

            cands: list[str] = [full]
            qpref = getattr(self, 'current_qname_prefix', '') or ''
            fpref = getattr(self, 'current_file_prefix', '') or ''
            if isinstance(qpref, str) and qpref and not qpref.endswith('.'):
                qpref += '.'
            if isinstance(fpref, str) and fpref and not fpref.endswith('.'):
                fpref += '.'
            if qpref and not full.startswith(qpref):
                cands.append(qpref + full)
            if fpref and not full.startswith(fpref):
                cands.append(fpref + full)

            for cand in cands:
                try:
                    b = self.resolve_binding(cand) if hasattr(self, 'resolve_binding') else None
                except Exception:
                    b = None
                if b is None:
                    continue
                if not getattr(b, 'is_const', False):
                    continue
                pyv = getattr(b, 'const_value_py', None)
                if pyv is None:
                    continue
                if isinstance(pyv, (bool, int, float, str)):
                    return pyv

            return self._OPT_NO

        # unary
        if hasattr(ml, 'Unary') and isinstance(e, ml.Unary):
            op = getattr(e, 'op', None)
            rv = self._opt_try_const_value(getattr(e, 'right', None))
            if rv is self._OPT_NO:
                return self._OPT_NO
            if op == 'not':
                return (not self._opt_truthy(rv))
            if op == '-':
                if isinstance(rv, bool):
                    return self._OPT_NO
                if isinstance(rv, (int, float)):
                    r = -rv
                    if isinstance(r, float) and r.is_integer():
                        return int(r)
                    return r
                return self._OPT_NO
            if op == '~':
                if isinstance(rv, int) and not isinstance(rv, bool):
                    return ~rv
                return self._OPT_NO
            return self._OPT_NO

        # binary
        if hasattr(ml, 'Bin') and isinstance(e, ml.Bin):
            op = getattr(e, 'op', None)
            lv = self._opt_try_const_value(getattr(e, 'left', None))

            # short-circuit opportunities without evaluating RHS
            if op == 'and' and lv is not self._OPT_NO and not self._opt_truthy(lv):
                return False
            if op == 'or' and lv is not self._OPT_NO and self._opt_truthy(lv):
                return True

            rv = self._opt_try_const_value(getattr(e, 'right', None))
            if lv is self._OPT_NO or rv is self._OPT_NO:
                return self._OPT_NO

            # boolean ops
            if op == 'and':
                return self._opt_truthy(lv) and self._opt_truthy(rv)
            if op == 'or':
                return self._opt_truthy(lv) or self._opt_truthy(rv)

            # equality
            if op == '==':
                return lv == rv
            if op == '!=':
                return lv != rv

            # comparisons (numeric only)
            if op in ('<', '>', '<=', '>='):
                if isinstance(lv, bool) or isinstance(rv, bool):
                    return self._OPT_NO
                if isinstance(lv, (int, float)) and isinstance(rv, (int, float)):
                    if op == '<':
                        return lv < rv
                    if op == '>':
                        return lv > rv
                    if op == '<=':
                        return lv <= rv
                    return lv >= rv
                return self._OPT_NO

            # arithmetic / concat
            if op == '+':
                if isinstance(lv, (int, float)) and isinstance(rv, (int, float)) and not isinstance(lv, bool) and not isinstance(rv, bool):
                    r = lv + rv
                    if isinstance(r, float) and r.is_integer():
                        return int(r)
                    return r
                if isinstance(lv, str) and isinstance(rv, str):
                    return lv + rv
                return self._OPT_NO
            if op == '-':
                if isinstance(lv, (int, float)) and isinstance(rv, (int, float)) and not isinstance(lv, bool) and not isinstance(rv, bool):
                    r = lv - rv
                    if isinstance(r, float) and r.is_integer():
                        return int(r)
                    return r
                return self._OPT_NO
            if op == '*':
                if isinstance(lv, (int, float)) and isinstance(rv, (int, float)) and not isinstance(lv, bool) and not isinstance(rv, bool):
                    r = lv * rv
                    if isinstance(r, float) and r.is_integer():
                        return int(r)
                    return r
                return self._OPT_NO
            if op == '/':
                # Runtime division normalizes exact ints; but also returns void on div-by-0.
                # We keep folding conservative: only fold when divisor is non-zero.
                if isinstance(lv, (int, float)) and isinstance(rv, (int, float)) and not isinstance(lv, bool) and not isinstance(rv, bool):
                    if float(rv) == 0.0:
                        return self._OPT_NO
                    r = float(lv) / float(rv)
                    if r.is_integer():
                        return int(r)
                    return float(r)
                return self._OPT_NO
            if op == '%':
                if isinstance(lv, int) and isinstance(rv, int) and not isinstance(lv, bool) and not isinstance(rv, bool):
                    if rv == 0:
                        return self._OPT_NO
                    return lv % rv
                return self._OPT_NO

            # bitwise (ints)
            if op in ('&', '|', '^'):
                if isinstance(lv, int) and isinstance(rv, int) and not isinstance(lv, bool) and not isinstance(rv, bool):
                    if op == '&':
                        return lv & rv
                    if op == '|':
                        return lv | rv
                    return lv ^ rv
                return self._OPT_NO
            if op in ('<<', '>>'):
                if isinstance(lv, int) and isinstance(rv, int) and not isinstance(lv, bool) and not isinstance(rv, bool):
                    if rv < 0:
                        return self._OPT_NO
                    if op == '<<':
                        return lv << rv
                    return lv >> rv
                return self._OPT_NO

            return self._OPT_NO

        return self._OPT_NO

    def _opt_emit_const_value(self, v: Any) -> None:
        """Emit a folded constant into RAX."""
        a = self.asm
        if isinstance(v, bool):
            a.mov_rax_imm64(enc_bool(bool(v)))
            return
        if isinstance(v, int) and not isinstance(v, bool):
            a.mov_rax_imm64(enc_int(int(v)))
            return
        if isinstance(v, float):
            lbl = f"cflt_{len(self.rdata.labels)}"
            self.rdata.add_obj_float(lbl, float(v))
            a.lea_rax_rip(lbl)
            return
        if isinstance(v, str):
            lbl = f"cstr_{len(self.rdata.labels)}"
            self.rdata.add_obj_string(lbl, str(v))
            a.lea_rax_rip(lbl)
            return

        # Not supported -> don't fold
        raise CompileError(f"Internal error: cannot emit const value type {type(v).__name__}")

    def _emit_make_error_const(self, code: int, message: str) -> None:
        """Allocate and return an `error(code, message)` value in RAX.

        The built-in `error` struct carries additional optional fields (script,
        func, line). We auto-fill these from the current debug-loc globals so
        runtime-generated errors still point at the correct callsite.
        """
        a = self.asm

        # Message as a boxed string constant in .rdata.
        lbl = f"objstr_{len(self.rdata.labels)}"
        self.rdata.add_obj_string(lbl, str(message))

        # Allocate a 5-field struct: 16 header + 5*8 fields = 56 bytes.
        a.mov_rcx_imm32(56)
        a.call('fn_alloc')

        a.mov_r11_rax()
        # header: type / nfields / struct_id / pad
        a.mov_membase_disp_imm32('r11', 0, OBJ_STRUCT, qword=False)
        a.mov_membase_disp_imm32('r11', 4, 5, qword=False)
        a.mov_membase_disp_imm32('r11', 8, ERROR_STRUCT_ID, qword=False)
        a.mov_membase_disp_imm32('r11', 12, 0, qword=False)

        # field0 = code (TAG_INT)
        a.mov_rax_imm64(enc_int(int(code)))
        a.mov_membase_disp_r64('r11', 16, 'rax')

        # field1 = message (TAG_PTR to OBJ_STRING)
        a.lea_rax_rip(lbl)
        a.mov_membase_disp_r64('r11', 24, 'rax')

        # field2 = script (string|void)
        a.mov_rax_rip_qword('dbg_loc_script')
        a.mov_membase_disp_r64('r11', 32, 'rax')

        # field3 = func (string|void)
        a.mov_rax_rip_qword('dbg_loc_func')
        a.mov_membase_disp_r64('r11', 40, 'rax')

        # field4 = line (int|void)
        a.mov_rax_rip_qword('dbg_loc_line')
        a.mov_membase_disp_r64('r11', 48, 'rax')

        a.mov_rax_r11()


    def _emit_auto_errprop(self) -> None:
        """If RAX is an `error(...)` and we're not inside try(), propagate it."""
        a = self.asm
        if int(getattr(self, '_errprop_suppression', 0) or 0) != 0:
            return
    
        lidp = self.new_label_id()
        l_noerr = f"errprop_noerr_{lidp}"
    
        # Check: TAG_PTR + OBJ_STRUCT + struct_id == ERROR_STRUCT_ID
        a.mov_r64_r64("r10", "rax")
        a.and_r64_imm("r10", 7)
        a.cmp_r64_imm("r10", TAG_PTR)
        a.jcc("ne", l_noerr)
        a.mov_r32_membase_disp("r10d", "rax", 0)
        a.cmp_r32_imm("r10d", OBJ_STRUCT)
        a.jcc("ne", l_noerr)
        a.mov_r32_membase_disp("r10d", "rax", 8)
        a.cmp_r32_imm("r10d", ERROR_STRUCT_ID)
        a.jcc("ne", l_noerr)
    
        if bool(getattr(self, 'in_function', False)) and getattr(self, 'func_ret_label', None):
            a.jmp(self.func_ret_label)
        else:
            a.mov_r64_r64("rcx", "rax")
            a.call('fn_unhandled_error_exit')
    
        a.mark(l_noerr)
    
    
    def _extern_dll_base(self, dll: str) -> str:
        # Must match compiler._dll_base() used for IAT label generation.
        base = os.path.basename(dll).lower()
        if base.endswith(".dll"):
            base = base[:-4]
        base = re.sub(r"[^a-z0-9_]+", "_", base)
        base = re.sub(r"_+", "_", base).strip("_")
        return base or "dll"

    def _extern_iat_label(self, dll: str, symbol: str) -> str:
        # Disambiguated label, e.g. iat_kernel32_ExitProcess
        return f"iat_{self._extern_dll_base(dll)}_{symbol}"

    def _abi_ty_to_str(self, abi_ty: Any) -> str:
        """Best-effort normalize extern ABI type declarations to a string.

        Frontend versions may store ABI types either as strings ("u32", "wstr", ...)
        or as small dicts (e.g. {"name": "path", "ty": "wstr"}). This helper
        extracts the actual type token so codegen can stay compatible.
        """
        if abi_ty is None:
            return ""

        if isinstance(abi_ty, str):
            return abi_ty

        # Common frontend shape: dict with one of these keys pointing to the type token.
        if isinstance(abi_ty, dict):
            # direct keys
            for k in ("abi_ty", "abi", "ty", "type", "ret", "name"):
                v = abi_ty.get(k)
                if isinstance(v, str) and v.strip():
                    # Heuristic: if key is "name" but looks like a type token, accept it.
                    return v
            # nested: walk values
            seen = set()
            stack = list(abi_ty.values())
            while stack:
                v = stack.pop()
                if id(v) in seen:
                    continue
                seen.add(id(v))
                if isinstance(v, str) and v.strip():
                    return v
                if isinstance(v, dict):
                    stack.extend(v.values())
                if isinstance(v, (list, tuple)):
                    stack.extend(list(v))
            return ""

        return str(abi_ty)

    def _emit_extern_arg_to_native(self, abi_ty: Any, fail_label: str, pos: Any, *,
                                   wbuf_label: Optional[str] = None) -> None:
        """Convert MiniLang value in RAX to native Win64-ABI representation in RAX.

        On type mismatch, jumps to `fail_label`.
        """
        a = self.asm
        t = self._abi_ty_to_str(abi_ty).strip().lower()

        # r10 = tag (low 3 bits)
        a.mov_r64_r64("r10", "rax")
        a.and_r64_imm8("r10", 7)

        # --- integers ---
        if t in ("int", "i64", "u64", "i32", "u32"):
            a.cmp_r64_imm8("r10", TAG_INT)
            a.jne(fail_label)
            a.sar_r64_imm8("rax", 3)
            if t == "u32":
                a.and_r64_imm("rax", 0xFFFFFFFF)
            return

        # --- bool ---
        if t == "bool":
            lid = self.new_label_id()
            lbl_bool = f"L_extarg_bool_bool_{lid}"
            lbl_done = f"L_extarg_bool_done_{lid}"
            a.cmp_r64_imm8("r10", TAG_BOOL)
            a.je(lbl_bool)
            a.cmp_r64_imm8("r10", TAG_INT)
            a.jne(fail_label)
            a.sar_r64_imm8("rax", 3)
            a.jmp(lbl_done)
            a.mark(lbl_bool)
            a.shr_r64_imm8("rax", 3)
            a.mark(lbl_done)
            return

        # --- ptr/pointer (accept int, ptr-obj, void->NULL) ---
        if t in ("ptr", "pointer"):
            lid = self.new_label_id()
            lbl_int = f"L_extarg_ptr_int_{lid}"
            lbl_ptr = f"L_extarg_ptr_ptr_{lid}"
            lbl_void = f"L_extarg_ptr_void_{lid}"
            lbl_ok = f"L_extarg_ptr_ok_{lid}"

            a.cmp_r64_imm8("r10", TAG_INT)
            a.je(lbl_int)
            a.cmp_r64_imm8("r10", TAG_PTR)
            a.je(lbl_ptr)
            a.cmp_r64_imm8("r10", TAG_VOID)
            a.je(lbl_void)
            a.jmp(fail_label)

            a.mark(lbl_int)
            a.sar_r64_imm8("rax", 3)
            a.jmp(lbl_ok)

            a.mark(lbl_ptr)
            # already a raw pointer to heap object
            a.jmp(lbl_ok)

            a.mark(lbl_void)
            a.xor_eax_eax()
            a.jmp(lbl_ok)

            a.mark(lbl_ok)
            return

        # --- bytes/buffer: TAG_PTR OBJ_BYTES -> native u8* (payload); void->NULL ---
        if t in ("bytes", "buffer", "bytebuffer"):
            lid = self.new_label_id()
            lbl_ptr = f"L_extarg_bytes_ptr_{lid}"
            lbl_void = f"L_extarg_bytes_void_{lid}"
            lbl_ok = f"L_extarg_bytes_ok_{lid}"

            a.cmp_r64_imm8("r10", TAG_PTR)
            a.je(lbl_ptr)
            a.cmp_r64_imm8("r10", TAG_VOID)
            a.je(lbl_void)
            a.jmp(fail_label)

            a.mark(lbl_void)
            a.xor_eax_eax()
            a.jmp(lbl_ok)

            a.mark(lbl_ptr)
            a.mov_r32_membase_disp("edx", "rax", 0)
            a.cmp_r32_imm("edx", OBJ_BYTES)
            a.jne(fail_label)
            a.lea_r64_membase_disp("rax", "rax", 8)
            a.jmp(lbl_ok)

            a.mark(lbl_ok)
            return

        # --- cstr: TAG_PTR OBJ_STRING -> native char* (payload); void->NULL ---
        if t in ("cstr", "cstring"):
            lid = self.new_label_id()
            lbl_ptr = f"L_extarg_cstr_ptr_{lid}"
            lbl_void = f"L_extarg_cstr_void_{lid}"
            lbl_ok = f"L_extarg_cstr_ok_{lid}"

            a.cmp_r64_imm8("r10", TAG_PTR)
            a.je(lbl_ptr)
            a.cmp_r64_imm8("r10", TAG_VOID)
            a.je(lbl_void)
            a.jmp(fail_label)

            a.mark(lbl_void)
            a.xor_eax_eax()
            a.jmp(lbl_ok)

            a.mark(lbl_ptr)
            a.mov_r32_membase_disp("edx", "rax", 0)
            a.cmp_r32_imm("edx", OBJ_STRING)
            a.jne(fail_label)
            a.lea_r64_membase_disp("rax", "rax", 8)  # payload (UTF-8, NUL-terminated)
            a.jmp(lbl_ok)

            a.mark(lbl_ok)
            return

        # --- wstr: TAG_PTR OBJ_STRING -> native wchar_t* (UTF-16 in temp buffer); void->NULL ---
        if t in ("wstr", "wstring"):
            lid = self.new_label_id()
            lbl_ptr = f"L_extarg_wstr_ptr_{lid}"
            lbl_void = f"L_extarg_wstr_void_{lid}"
            lbl_ok = f"L_extarg_wstr_ok_{lid}"

            a.cmp_r64_imm8("r10", TAG_PTR)
            a.je(lbl_ptr)
            a.cmp_r64_imm8("r10", TAG_VOID)
            a.je(lbl_void)
            a.jmp(fail_label)

            a.mark(lbl_void)
            a.xor_eax_eax()
            a.jmp(lbl_ok)

            a.mark(lbl_ptr)
            a.mov_r32_membase_disp("edx", "rax", 0)
            a.cmp_r32_imm("edx", OBJ_STRING)
            a.jne(fail_label)

            # MultiByteToWideChar(CP_UTF8,0, src,-1, wbuf, WIDEBUF_SIZE/2)
            a.mov_rcx_imm32(65001)
            a.xor_r32_r32("edx", "edx")
            a.lea_r64_membase_disp("r8", "rax", 8)  # src bytes
            a.mov_r32_imm32("r9d", 0xFFFFFFFF)  # -1 (NUL-terminated)
            a.lea_r11_rip(wbuf_label or "widebuf")  # dst buffer
            a.mov_membase_disp_r64("rsp", 0x20, "r11")  # arg5: dst
            a.mov_membase_disp_imm32("rsp", 0x28, (WIDEBUF_SIZE // 2), qword=True)  # arg6: cchWideChar
            a.mov_rax_rip_qword("iat_MultiByteToWideChar")
            a.call_rax()

            # return wchar_t* = wbuf
            a.lea_rax_rip(wbuf_label or "widebuf")
            a.jmp(lbl_ok)

            a.mark(lbl_ok)
            return

        raise CompileError(f"Unsupported extern ABI type '{self._abi_ty_to_str(abi_ty) or str(abi_ty)}'", pos)

    def _emit_extern_ret_from_native(self, ret_ty: Any, pos: Any) -> None:
        """Convert native Win64-ABI return value in RAX into a MiniLang tagged value in RAX."""
        a = self.asm
        t = self._abi_ty_to_str(ret_ty).strip().lower()

        if t in ("void", "none", ""):
            a.mov_rax_imm64(enc_void())
            return

        if t == "bool":
            # rax = 0/!=0  => TAG_BOOL
            a.test_r64_r64("rax", "rax")
            a.setcc_al("ne")
            a.movzx_r32_r8("eax", "al")
            a.shl_rax_imm8(3)
            a.or_rax_imm8(TAG_BOOL)
            return

        if t == "u32":
            a.and_r64_imm("rax", 0xFFFFFFFF)
            a.shl_rax_imm8(3)
            a.or_rax_imm8(TAG_INT)
            return

        if t == "i32":
            # sign-extend eax -> rax (no dedicated movsxd helper, so do it manually)
            a.shl_rax_imm8(32)
            a.sar_r64_imm8("rax", 32)
            a.shl_rax_imm8(3)
            a.or_rax_imm8(TAG_INT)
            return

        if t in ("int", "i64", "u64", "ptr", "pointer"):
            a.shl_rax_imm8(3)
            a.or_rax_imm8(TAG_INT)
            return

        if t in ("cstr", "cstring"):
            # native char* (UTF-8, NUL-terminated) -> OBJ_STRING*
            self.ensure_gc_data()

            lid = self.new_label_id()
            l_null = f"L_extret_cstr_null_{lid}"
            l_scan = f"L_extret_cstr_scan_{lid}"
            l_done = f"L_extret_cstr_done_{lid}"
            l_after = f"L_extret_cstr_after_{lid}"

            # gc_tmp0 = src (TAG_INT encoded pointer)
            # gc_tmp1 = len (TAG_INT)
            # gc_tmp2 = result (TAG_PTR)
            a.mov_r64_r64("r10", "rax")
            a.shl_r64_imm8("r10", 3)
            a.or_r64_imm8("r10", TAG_INT)
            a.mov_r64_r64("r11", "r10")
            a.mov_rip_qword_r11("gc_tmp0")

            a.test_r64_r64("rax", "rax")
            a.je(l_null)

            # r10 = src (native)
            a.mov_rax_rip_qword("gc_tmp0")
            a.mov_r64_r64("r10", "rax")
            a.sar_r64_imm8("r10", 3)

            # r9d = len (scan for NUL)
            a.xor_r32_r32("r9d", "r9d")
            a.mark(l_scan)
            a.mov_r64_r64("r11", "r10")
            a.add_r64_r64("r11", "r9")
            a.movzx_r32_membase_disp("eax", "r11", 0)
            a.cmp_r8_imm8("al", 0)
            a.je(l_done)
            a.inc_r32("r9d")
            a.jmp(l_scan)

            a.mark(l_done)
            a.mov_r64_r64("r11", "r9")
            a.shl_r64_imm8("r11", 3)
            a.or_r64_imm8("r11", TAG_INT)
            a.mov_rip_qword_r11("gc_tmp1")

            # alloc size = 9 + len
            a.mov_r32_r32("ecx", "r9d")
            a.add_r32_imm("ecx", 9)
            a.call("fn_alloc")

            a.mov_r11_rax()
            a.mov_rip_qword_r11("gc_tmp2")

            # header: type + len
            a.mov_membase_disp_imm32("r11", 0, OBJ_STRING, qword=False)
            a.mov_rax_rip_qword("gc_tmp1")
            a.mov_r64_r64("r9", "rax")
            a.sar_r64_imm8("r9", 3)
            a.mov_r32_r32("r9d", "r9d")
            a.mov_membase_disp_r32("r11", 4, "r9d")

            # reload src -> r10
            a.mov_rax_rip_qword("gc_tmp0")
            a.mov_r64_r64("r10", "rax")
            a.sar_r64_imm8("r10", 3)

            # copy bytes
            a.push_reg("rsi")
            a.push_reg("rdi")
            a.mov_r64_r64("rsi", "r10")
            a.lea_r64_membase_disp("rdi", "r11", 8)
            a.mov_r32_r32("ecx", "r9d")
            a.rep_movsb()
            a.pop_reg("rdi")
            a.pop_reg("rsi")

            # ensure NUL at [base+8+len]
            a.mov_r64_r64("rax", "r11")
            a.add_r64_r64("rax", "r9")
            a.add_rax_imm8(8)
            a.mov_membase_disp_imm8("rax", 0, 0)

            a.mov_rax_r11()
            a.jmp(l_after)

            a.mark(l_null)
            a.mov_rax_imm64(enc_void())

            a.mark(l_after)
            # clear temp roots
            a.mov_r64_r64("r10", "rax")
            a.mov_rax_imm64(enc_void())
            a.mov_rip_qword_rax("gc_tmp0")
            a.mov_rip_qword_rax("gc_tmp1")
            a.mov_rip_qword_rax("gc_tmp2")
            a.mov_r64_r64("rax", "r10")
            return

        if t in ("wstr", "wstring"):
            # native wchar_t* (UTF-16, NUL-terminated) -> OBJ_STRING* (UTF-8)
            self.ensure_gc_data()

            lid = self.new_label_id()
            l_null = f"L_extret_wstr_null_{lid}"
            l_fail = f"L_extret_wstr_fail_{lid}"
            l_after = f"L_extret_wstr_after_{lid}"

            # gc_tmp0 = src (TAG_INT pointer)
            # gc_tmp1 = out_len (TAG_INT)
            # gc_tmp2 = result (TAG_PTR)
            a.mov_r64_r64("r10", "rax")
            a.shl_r64_imm8("r10", 3)
            a.or_r64_imm8("r10", TAG_INT)
            a.mov_r64_r64("r11", "r10")
            a.mov_rip_qword_r11("gc_tmp0")

            a.test_r64_r64("rax", "rax")
            a.je(l_null)

            # WideCharToMultiByte(CP_UTF8,0,src,-1,NULL,0,NULL,NULL)
            a.mov_rcx_imm32(65001)
            a.xor_r32_r32("edx", "edx")
            a.mov_rax_rip_qword("gc_tmp0")
            a.mov_r64_r64("r8", "rax")
            a.sar_r64_imm8("r8", 3)
            a.mov_r32_imm32("r9d", 0xFFFFFFFF)
            a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)
            a.mov_membase_disp_imm32("rsp", 0x28, 0, qword=True)
            a.mov_membase_disp_imm32("rsp", 0x30, 0, qword=True)
            a.mov_membase_disp_imm32("rsp", 0x38, 0, qword=True)
            a.mov_rax_rip_qword("iat_WideCharToMultiByte")
            a.call_rax()

            a.cmp_rax_imm8(0)
            a.je(l_fail)

            # out_len(bytes) = bytes_with_nul - 1
            a.dec_r32("eax")
            a.mov_r64_r64("r11", "rax")
            a.shl_r64_imm8("r11", 3)
            a.or_r64_imm8("r11", TAG_INT)
            a.mov_rip_qword_r11("gc_tmp1")

            # alloc size = 9 + out_len
            a.mov_r32_r32("ecx", "eax")
            a.add_r32_imm("ecx", 9)
            a.call("fn_alloc")

            a.mov_r11_rax()
            a.mov_rip_qword_r11("gc_tmp2")

            a.mov_membase_disp_imm32("r11", 0, OBJ_STRING, qword=False)
            a.mov_rax_rip_qword("gc_tmp1")
            a.mov_r64_r64("r10", "rax")
            a.sar_r64_imm8("r10", 3)
            a.mov_r32_r32("r10d", "r10d")
            a.mov_membase_disp_r32("r11", 4, "r10d")

            # WideCharToMultiByte(CP_UTF8,0,src,-1,dst,out_len+1,NULL,NULL)
            a.mov_rcx_imm32(65001)
            a.xor_r32_r32("edx", "edx")
            a.mov_rax_rip_qword("gc_tmp0")
            a.mov_r64_r64("r8", "rax")
            a.sar_r64_imm8("r8", 3)
            a.mov_r32_imm32("r9d", 0xFFFFFFFF)

            # dst = base+8
            a.mov_rax_rip_qword("gc_tmp2")
            a.mov_r64_r64("r11", "rax")
            a.lea_r64_membase_disp("rax", "r11", 8)
            a.mov_membase_disp_r64("rsp", 0x20, "rax")

            # cbMultiByte = out_len + 1
            a.mov_rax_rip_qword("gc_tmp1")
            a.sar_r64_imm8("rax", 3)
            a.inc_r32("eax")
            a.mov_membase_disp_r64("rsp", 0x28, "rax")

            a.mov_membase_disp_imm32("rsp", 0x30, 0, qword=True)
            a.mov_membase_disp_imm32("rsp", 0x38, 0, qword=True)
            a.mov_rax_rip_qword("iat_WideCharToMultiByte")
            a.call_rax()

            a.cmp_rax_imm8(0)
            a.je(l_fail)

            # ensure NUL at [base+8+out_len]
            a.mov_rax_rip_qword("gc_tmp2")
            a.mov_r64_r64("r11", "rax")
            a.mov_rax_rip_qword("gc_tmp1")
            a.mov_r64_r64("r10", "rax")
            a.sar_r64_imm8("r10", 3)
            a.mov_r64_r64("rax", "r11")
            a.add_r64_r64("rax", "r10")
            a.add_rax_imm8(8)
            a.mov_membase_disp_imm8("rax", 0, 0)

            a.mov_rax_r11()
            a.jmp(l_after)

            a.mark(l_fail)
            self._emit_make_error_const(ERR_EXTERN_RET_WSTR_CONVERSION,
                                        "Extern return conversion failed: wstr (WideCharToMultiByte returned 0)", )
            a.jmp(l_after)

            a.mark(l_null)
            a.mov_rax_imm64(enc_void())

            a.mark(l_after)
            # clear temp roots
            a.mov_r64_r64("r10", "rax")
            a.mov_rax_imm64(enc_void())
            a.mov_rip_qword_rax("gc_tmp0")
            a.mov_rip_qword_rax("gc_tmp1")
            a.mov_rip_qword_rax("gc_tmp2")
            a.mov_r64_r64("rax", "r10")
            return

        raise CompileError(f"Unsupported extern return type '{self._abi_ty_to_str(ret_ty) or str(ret_ty)}'", pos)

    def _emit_extern_call(self, e: Any, callee_name: str) -> None:
        """Emit a direct call to an `extern function` via the PE import table (IAT)."""
        sig = self.extern_sigs.get(callee_name)
        if not sig:
            raise CompileError(f"Unknown extern function '{callee_name}'", getattr(e, "pos", None))

        params = list(sig.get("params", []))
        ret_ty = sig.get("ret_ty", "void")
        dll = sig.get("dll", "")
        symbol = sig.get("symbol", callee_name)

        if len(e.args) != len(params):
            raise CompileError(
                f"Extern call arity mismatch: {callee_name} expects {len(params)} args, got {len(e.args)}", e.pos, )

        a = self.asm
        fail_label = f"L_extern_fail_{self.new_label_id()}"
        cleanup_label = f"L_extern_cleanup_{self.new_label_id()}"
        done_label = f"L_extern_done_{self.new_label_id()}"

        # Root-stash original MiniLang arg values so later arg evaluation can't GC-free them.
        roots_size = max(0, len(params) * 8)
        roots_off = self.alloc_expr_temps(roots_size) if roots_size else 0

        # Pick stable temp wide buffers for wstr args.
        wpool = getattr(self, "ext_widebuf_labels", None) or ["widebuf"]

        for i, (arg_expr, abi_ty) in enumerate(zip(e.args, params)):
            self.emit_expr(arg_expr)  # -> RAX tagged
            if roots_size:
                a.mov_membase_disp_r64("rsp", roots_off + i * 8, "rax")

            wbuf = None
            if self._abi_ty_to_str(abi_ty).strip().lower() in ("wstr", "wstring"):
                wbuf = wpool[i % len(wpool)]

            self._emit_extern_arg_to_native(abi_ty, fail_label, e.pos, wbuf_label=wbuf)  # RAX = native

            # Store native args GC-safe as TAG_INT on stack.
            a.shl_rax_imm8(3)
            a.or_rax_imm8(TAG_INT)
            a.mov_membase_disp_r64("rsp", self.call_temp_base + i * 8, "rax")

        # Move first 4 args into registers (Windows x64 ABI), rest into outgoing stack args.
        regs = ["rcx", "rdx", "r8", "r9"]
        for i in range(min(4, len(params))):
            a.mov_r64_membase_disp(regs[i], "rsp", self.call_temp_base + i * 8)
            a.sar_r64_imm8(regs[i], 3)

        for i in range(4, len(params)):
            a.mov_r64_membase_disp("rax", "rsp", self.call_temp_base + i * 8)
            a.sar_r64_imm8("rax", 3)
            a.mov_membase_disp_r64("rsp", 0x20 + (i - 4) * 8, "rax")

        # Call through the imported function pointer.
        a.mov_rax_rip_qword(self._extern_iat_label(dll, symbol))
        a.call_rax()

        # Marshal return value back into MiniLang representation.
        self._emit_extern_ret_from_native(ret_ty, e.pos)
        a.jmp(cleanup_label)

        a.mark(fail_label)
        self._emit_make_error_const(ERR_EXTERN_CONVERSION,
                                    f"Extern call failed: {callee_name} (argument type mismatch or conversion failure)", )

        a.mark(cleanup_label)
        if roots_size:
            self.free_expr_temps(roots_size)

        a.mark(done_label)

    # ---------- extern stub-only mode ----------

    def emit_extern_stubs(self) -> None:
        """Emit per-extern OBJ_BUILTIN stub functions.

        In stub-only mode, extern identifiers are globals that evaluate to an
        OBJ_BUILTIN object whose code_ptr points at one of these stubs.

        Calling convention (internal): arguments arrive as *tagged* MiniLang
        Values in RCX/RDX/R8/R9 and on the stack (Win64 ABI). The stub converts
        to native ABI values, calls the imported symbol via IAT, and converts
        the return value back to a tagged Value in RAX.
        """
        a = self.asm
        externs = getattr(self, 'extern_sigs', {}) or {}
        if not externs:
            return

        wpool = getattr(self, 'ext_widebuf_labels', None) or ['widebuf']
        stub_labels = getattr(self, 'extern_stub_labels', {}) or {}

        for qn, sig in externs.items():
            if not isinstance(sig, dict):
                continue

            dll = sig.get('dll', '')
            sym = sig.get('symbol', None) or qn.split('.')[-1]
            params = list(sig.get('params', []) or [])
            ret_ty = sig.get('ret_ty', 'void')
            pos = sig.get('pos', None)

            nargs = len(params)
            out_args = max(0, nargs - 4)

            stub_lbl = stub_labels.get(qn)
            if not stub_lbl:
                # Fallback: sanitize qname (should not normally happen)
                safe = re.sub(r'[^A-Za-z0-9_]+', '_', str(qn)).strip('_')
                stub_lbl = f"fn_extern_{safe or 'anon'}"

            l_fail = f"lbl_extern_stub_fail_{self.new_label_id()}"
            l_done = f"lbl_extern_stub_done_{self.new_label_id()}"

            # Local layout:
            # - [rsp+0x20..] is reserved for outgoing stack args (and WinAPI helper arg slots)
            # - We store tagged args and converted native args above that.
            tag_off = align_up(0x40 + out_args * 8, 16)
            native_off = tag_off + nargs * 8
            required = native_off + nargs * 8
            # Ensure we have room for WinAPI helper arg slots up to [rsp+0x38].
            required = max(required, 0x40)
            # Ensure we have room for outgoing args (if many args).
            required = max(required, 0x20 + out_args * 8 + 0x20)
            frame = align_to_mod(required, 16, 8)  # keep 16B alignment for nested calls

            a.mark(stub_lbl)
            if frame <= 0x7F:
                a.sub_rsp_imm8(frame)
            else:
                a.sub_rsp_imm32(frame)

            # Save incoming tagged args into locals (so conversions can freely clobber registers).
            if nargs >= 1:
                a.mov_membase_disp_r64('rsp', tag_off + 0 * 8, 'rcx')
            if nargs >= 2:
                a.mov_membase_disp_r64('rsp', tag_off + 1 * 8, 'rdx')
            if nargs >= 3:
                a.mov_membase_disp_r64('rsp', tag_off + 2 * 8, 'r8')
            if nargs >= 4:
                a.mov_membase_disp_r64('rsp', tag_off + 3 * 8, 'r9')

            # Stack args from caller are located at:
            #   [rsp + 0x28] = 5th arg
            #   [rsp + 0x30] = 6th arg
            #   [rsp + 0x38] = 7th arg
            # ...
            # because Windows x64 has a return address at [rsp] and 32 bytes of shadow space.
            for i in range(4, nargs):
                src_disp = frame + 0x28 + (i - 4) * 8
                a.mov_r64_membase_disp('rax', 'rsp', src_disp)
                a.mov_membase_disp_r64('rsp', tag_off + i * 8, 'rax')

            # Convert tagged args -> native (stored untagged in locals).
            for i, abi_ty in enumerate(params):
                a.mov_r64_membase_disp('rax', 'rsp', tag_off + i * 8)
                wbuf = None
                if self._abi_ty_to_str(abi_ty).strip().lower() in ('wstr', 'wstring'):
                    wbuf = wpool[i % len(wpool)]
                self._emit_extern_arg_to_native(abi_ty, l_fail, pos, wbuf_label=wbuf)
                a.mov_membase_disp_r64('rsp', native_off + i * 8, 'rax')

            # Marshal args to Win64 ABI: RCX/RDX/R8/R9 + outgoing stack slots.
            regs = ['rcx', 'rdx', 'r8', 'r9']
            for i in range(min(4, nargs)):
                a.mov_r64_membase_disp(regs[i], 'rsp', native_off + i * 8)

            for i in range(4, nargs):
                a.mov_r64_membase_disp('rax', 'rsp', native_off + i * 8)
                a.mov_membase_disp_r64('rsp', 0x20 + (i - 4) * 8, 'rax')

            # Call through IAT.
            # Sanity-check that the import was registered (otherwise the PE patch stage would fail
            # with an obscure missing-label error).
            dll_n = str(dll or '').strip().lower()
            sym_s = str(sym or '').strip()
            imports = getattr(self, 'imports', {}) or {}
            if dll_n and sym_s:
                if dll_n not in imports or sym_s not in (imports.get(dll_n) or []):
                    raise CompileError(
                        f"Extern '{qn}' uses {dll_n}!{sym_s} but the symbol was not added to the PE import table (internal error)",
                        pos, )
            a.mov_rax_rip_qword(self._extern_iat_label(str(dll), str(sym)))
            a.call_rax()

            # Convert return value back to a tagged MiniLang Value.
            self._emit_extern_ret_from_native(ret_ty, pos)
            a.jmp(l_done)

            # Type mismatch / conversion failure
            a.mark(l_fail)
            self._emit_make_error_const(ERR_EXTERN_CONVERSION,
                                        f"Extern call failed: {qn} (argument type mismatch or conversion failure)", )

            a.mark(l_done)
            if frame <= 0x7F:
                a.add_rsp_imm8(frame)
            else:
                a.add_rsp_imm32(frame)
            a.ret()

    # ------------------------------------------------------------
    # Inline functions (function inline ...)
    # ------------------------------------------------------------

    def _emit_inline_call(self, e: Any, callee_name: str) -> None:
        """Emit a direct expansion of an inline function call (full body inlining).

        Direct calls like `f(x,y)` are expanded in-place (no call overhead).
        The callee body is emitted as statements, with `return` translated into a
        jump to a local end label that yields the call result in RAX.

        Implementation notes:
        - Arguments are evaluated left-to-right and stored in persistent stack slots.
        - The inline body is emitted inside an *isolated* scope stack so it cannot
          access or overwrite caller locals.
        - New local bindings inside the inline body allocate stack slots lazily
          in the expression-temp arena (see CodegenScope.emit_store_var_scoped).
        """

        ml = self.ml
        a = self.asm

        fn = (getattr(self, 'inline_functions', {}) or {}).get(callee_name)
        if fn is None:
            raise self.error(f"Unknown inline function '{callee_name}'", e)

        # Reject closure/capture machinery for now: those rely on a real function prologue.
        if bool(getattr(fn, "_ml_env_hop", False)):
            raise self.error(f"inline function '{callee_name}' cannot use closures/env hops", fn)
        if (getattr(fn, "_ml_env_slots", None) or []) or (getattr(fn, "_ml_captures", None) or set()):
            raise self.error(f"inline function '{callee_name}' cannot capture variables (closures not supported for inlining)",
                             fn)
        if (getattr(fn, "_ml_boxed", None) or set()):
            # Boxing is used for closures; keep this explicit until we inline env/box setup.
            raise self.error(f"inline function '{callee_name}' uses boxed variables (not supported for inlining)", fn)

        # Disallow nested function defs inside inline bodies for now.
        def _contains_nested_fn(stmts) -> bool:
            for st in stmts or []:
                if isinstance(st, ml.FunctionDef):
                    return True
                if isinstance(st, ml.If):
                    if _contains_nested_fn(getattr(st, 'then_body', None)):
                        return True
                    for _c, _b in getattr(st, 'elifs', []) or []:
                        if _contains_nested_fn(_b):
                            return True
                    if _contains_nested_fn(getattr(st, 'else_body', None)):
                        return True
                if isinstance(st, ml.While) or isinstance(st, getattr(ml, 'DoWhile', ())):
                    if _contains_nested_fn(getattr(st, 'body', None)):
                        return True
                if isinstance(st, ml.For) or isinstance(st, getattr(ml, 'ForEach', ())):
                    if _contains_nested_fn(getattr(st, 'body', None)):
                        return True
                if isinstance(st, ml.Switch):
                    for cs in getattr(st, 'cases', []) or []:
                        if _contains_nested_fn(getattr(cs, 'body', None)):
                            return True
                    if _contains_nested_fn(getattr(st, 'default_body', None)):
                        return True
            return False

        body = list(getattr(fn, 'body', []) or [])
        if _contains_nested_fn(body):
            raise self.error(f"inline function '{callee_name}' cannot contain nested function definitions", fn)

        # Recursion / mutual recursion guard.
        stk = getattr(self, '_inline_call_stack', None)
        if stk is None:
            self._inline_call_stack = []
            stk = self._inline_call_stack
        if callee_name in stk:
            chain = " -> ".join(list(stk) + [callee_name])
            raise self.error(f"inline recursion is not supported ({chain})", e)

        params = list(getattr(fn, 'params', []) or [])
        args = list(getattr(e, 'args', []) or [])
        if len(args) != len(params):
            raise self.error(f"Function {callee_name} expects {len(params)} args, got {len(args)}", e)

        # Allocate persistent param slots in the expression-temp arena.
        # We free the entire inline allocation delta at the end label.
        base_top = int(getattr(self, 'expr_temp_top', 0) or 0)
        nargs = len(params)
        param_bytes = nargs * 8
        param_base = self.alloc_expr_temps(param_bytes) if nargs else 0

        for i, arg in enumerate(args):
            self.emit_expr(arg)
            a.mov_rsp_disp32_rax(param_base + i * 8)

        lid = self.new_label_id()
        l_end = f"inline_end_{lid}"

        # Save compiler/codegen state we temporarily override.
        saved_in_fn = bool(getattr(self, 'in_function', False))
        saved_ret = getattr(self, 'func_ret_label', None)
        saved_param_off = dict(getattr(self, 'func_param_offsets', {}) or {})
        saved_func_params = dict(getattr(self, 'func_param_offsets', {}) or {})
        saved_scope_stack = getattr(self, '_scope_stack', None)
        saved_scope_declared = getattr(self, '_scope_declared', None)

        saved_decl_site = dict(getattr(self, '_decl_site_bindings', {}) or {})
        saved_fn_locals = list(getattr(self, '_function_locals', []) or [])
        saved_fn_local_ids = set(getattr(self, '_function_local_ids', set()) or set())
        saved_func_globals = set(getattr(self, '_func_globals', set()) or set())
        saved_func_global_map = dict(getattr(self, '_func_global_map', {}) or {})

        saved_qpref = getattr(self, 'current_qname_prefix', '')
        saved_filepref = getattr(self, 'current_file_prefix', '')
        saved_ctx_file = getattr(self, '_current_fn_file', None)
        saved_ctx_qn = getattr(self, '_current_fn_qname', None)
        saved_inline_alloc = bool(getattr(self, '_inline_alloc_enabled', False))

        try:
            # Isolate scope stack: globals + fresh inline root scope.
            base_globals = {}
            try:
                if saved_scope_stack and len(saved_scope_stack) > 0:
                    base_globals = dict(saved_scope_stack[0])
            except Exception:
                base_globals = {}

            if saved_scope_stack is not None:
                self._scope_stack = [base_globals, {}]
            if saved_scope_declared is not None:
                self._scope_declared = [[], []]

            # Reset per-function scope metadata so inline locals don't pollute the caller.
            self._decl_site_bindings = {}
            self._function_locals = []
            self._function_local_ids = set()
            self._func_globals = set()
            self._func_global_map = {}

            # Inline emission behaves like a function for returns + error propagation.
            self.in_function = True
            self.func_ret_label = l_end
            self._inline_alloc_enabled = True

            # Use the callee's qualification context for unqualified name resolution.
            try:
                if isinstance(callee_name, str) and '.' in callee_name:
                    self.current_qname_prefix = callee_name.rsplit('.', 1)[0] + '.'
                else:
                    self.current_qname_prefix = ''
                self._current_fn_qname = callee_name
                fn_file = getattr(fn, '_filename', None)
                if isinstance(fn_file, str) and fn_file:
                    self._current_fn_file = fn_file
            except Exception:
                pass

            # Bind params in the inline root scope and install fast param offsets.
            self.func_param_offsets = {}
            for i, p in enumerate(params):
                off = param_base + i * 8
                self.func_param_offsets[p] = off
                try:
                    self.bind_param(p, off, node=fn)
                except Exception:
                    # If scope stacks are not available for some reason, param offsets still work.
                    pass

            stk.append(callee_name)
            try:
                for st in body:
                    self.emit_stmt(st)
            finally:
                stk.pop()

            # Default fallthrough return value: void.
            a.mov_rax_imm64(enc_void())
            a.mark(l_end)

        finally:
            # Restore compiler state.
            self._inline_alloc_enabled = saved_inline_alloc
            self.in_function = saved_in_fn
            self.func_ret_label = saved_ret
            self.func_param_offsets = saved_param_off
            self.current_qname_prefix = saved_qpref
            self.current_file_prefix = saved_filepref
            self._current_fn_file = saved_ctx_file
            self._current_fn_qname = saved_ctx_qn

            self._decl_site_bindings = saved_decl_site
            self._function_locals = saved_fn_locals
            self._function_local_ids = saved_fn_local_ids
            self._func_globals = saved_func_globals
            self._func_global_map = saved_func_global_map

            if saved_scope_stack is not None:
                self._scope_stack = saved_scope_stack
            if saved_scope_declared is not None:
                self._scope_declared = saved_scope_declared

            # Clear and release all expression-temp bytes allocated by this inline expansion.
            try:
                delta = int(getattr(self, 'expr_temp_top', 0) or 0) - base_top
                if delta > 0:
                    self.free_expr_temps(delta)
            except Exception:
                pass

    def emit_expr(self, e: Any) -> None:
        """Emit code so that RAX contains the Value."""
        ml = self.ml
        a = self.asm

        # Step 4: constant folding (safe subset).
        try:
            cv = self._opt_try_const_value(e)
        except Exception:
            cv = self._OPT_NO
        if cv is not self._OPT_NO:
            try:
                self._opt_emit_const_value(cv)
                return
            except Exception:
                # Fall back to normal emission if something about this constant is unsupported.
                pass

        if isinstance(e, ml.Num):
            if isinstance(e.value, int):
                a.mov_rax_imm64(enc_int(e.value))
            else:
                # boxed float literal in .rdata
                lbl = f"flt_{len(self.rdata.labels)}"
                self.rdata.add_obj_float(lbl, float(e.value))
                a.lea_rax_rip(lbl)
            return

        if isinstance(e, ml.Bool):
            a.mov_rax_imm64(enc_bool(e.value))
            return

        if hasattr(ml, 'VoidLit') and isinstance(e, ml.VoidLit):
            a.mov_rax_imm64(enc_void())
            return

        # `is` named type checks (struct/enum)
        if hasattr(ml, 'IsType') and isinstance(e, ml.IsType):
            ty_raw = str(getattr(e, 'type_name', '') or '')
            neg = bool(getattr(e, 'negated', False))

            # Resolve qualified name similar to identifiers (package/namespace + import aliases)
            ty_q = ty_raw
            try:
                if '.' in ty_q:
                    ty_q = self._apply_import_alias(ty_q)
                else:
                    # Prefer struct resolution, then enum resolution
                    cand_s = self._qualify_identifier(ty_q, e, kind='struct')
                    if cand_s in getattr(self, 'struct_id', {}):
                        ty_q = cand_s
                    else:
                        cand_e = self._qualify_identifier(ty_q, e, kind='enum')
                        if cand_e in getattr(self, 'enum_id', {}):
                            ty_q = cand_e
                        else:
                            ty_q = self._apply_import_alias(ty_q)
            except Exception:
                pass

            # If user wrote Enum.Variant, treat as Enum.
            try:
                if '.' in ty_q and hasattr(self, 'enum_variants'):
                    base, var = ty_q.rsplit('.', 1)
                    base = self._apply_import_alias(base)
                    if base in getattr(self, 'enum_id', {}) and var in getattr(self, 'enum_variants', {}).get(base, []):
                        ty_q = base
            except Exception:
                pass

            # Struct check
            if ty_q in getattr(self, 'struct_id', {}):
                sid = int(getattr(self, 'struct_id', {}).get(ty_q, 0) or 0)
                self.emit_expr(getattr(e, 'expr'))

                fid = self.new_label_id()
                l_false = f"is_s_false_{fid}"
                l_true = f"is_s_true_{fid}"
                l_done = f"is_s_done_{fid}"
                l_type_ok = f"is_s_typeok_{fid}"

                # Must be pointer
                a.mov_r10_rax()
                a.and_r64_imm('r10', 7)
                a.cmp_r64_imm('r10', TAG_PTR)
                a.jcc('ne', l_false)

                # r11 = obj
                a.mov_r11_rax()
                a.mov_r32_membase_disp('edx', 'r11', 0)
                a.cmp_r32_imm('edx', OBJ_STRUCT)
                a.jcc('e', l_type_ok)
                a.cmp_r32_imm('edx', OBJ_STRUCTTYPE)
                a.jcc('ne', l_false)

                a.mark(l_type_ok)
                a.mov_r32_membase_disp('edx', 'r11', 8)  # struct_id
                a.cmp_r32_imm('edx', sid)
                a.jcc('e', l_true)
                a.jmp(l_false)

                a.mark(l_true)
                a.mov_rax_imm64(enc_bool(True))
                a.jmp(l_done)

                a.mark(l_false)
                a.mov_rax_imm64(enc_bool(False))

                a.mark(l_done)
                if neg:
                    a.xor_r64_imm8('rax', 8)
                return

            # Enum check
            if hasattr(self, 'enum_id') and ty_q in getattr(self, 'enum_id', {}):
                eid = int(getattr(self, 'enum_id', {}).get(ty_q, 0) or 0)
                self.emit_expr(getattr(e, 'expr'))

                fid = self.new_label_id()
                l_false = f"is_e_false_{fid}"
                l_true = f"is_e_true_{fid}"
                l_done = f"is_e_done_{fid}"

                a.mov_r10_rax()
                a.and_r64_imm('r10', 7)
                a.cmp_r64_imm('r10', TAG_ENUM)
                a.jcc('ne', l_false)

                # payload: (variant<<8)|enum_id at bits [3..]
                a.mov_r64_r64('r10', 'rax')
                a.shr_r64_imm8('r10', 3)
                a.and_r64_imm('r10', 0xFF)
                a.cmp_r64_imm('r10', eid)
                a.jcc('e', l_true)
                a.jmp(l_false)

                a.mark(l_true)
                a.mov_rax_imm64(enc_bool(True))
                a.jmp(l_done)

                a.mark(l_false)
                a.mov_rax_imm64(enc_bool(False))

                a.mark(l_done)
                if neg:
                    a.xor_r64_imm8('rax', 8)
                return

            # Value-enum check (enums materialized as constexpr const members)
            # For these enums, member values are plain int/string values, not TAG_ENUM.
            # `x is Color` is treated as: x equals one of Color.<variant> values.
            if hasattr(self, 'value_enum_values') and ty_q in (getattr(self, 'value_enum_values', {}) or {}):
                members = (getattr(self, 'value_enum_values', {}) or {}).get(ty_q) or {}
                if not isinstance(members, dict) or not members:
                    raise CompileError(f"Unknown type '{ty_raw}' in 'is' expression", getattr(e, 'pos', None))

                # Evaluate expr once and spill to temp.
                self.emit_expr(getattr(e, 'expr'))
                off = self.alloc_expr_temps(8)
                a.mov_rsp_disp32_rax(off)

                fid = self.new_label_id()
                l_true = f"is_ve_true_{fid}"
                l_false = f"is_ve_false_{fid}"
                l_done = f"is_ve_done_{fid}"

                # Iterate members: if any equals(expr) => true
                for vn in list(members.keys()):
                    qmem = f"{ty_q}.{vn}"
                    pyv = None
                    try:
                        b = self.resolve_binding(qmem) if hasattr(self, 'resolve_binding') else None
                    except Exception:
                        b = None
                    if b is not None and getattr(b, 'is_const', False):
                        pyv = getattr(b, 'const_value_py', None)

                    # Load rhs
                    if isinstance(pyv, bool):
                        a.mov_r64_imm64('rdx', enc_bool(bool(pyv)))
                    elif isinstance(pyv, int) and not isinstance(pyv, bool):
                        a.mov_r64_imm64('rdx', enc_int(int(pyv)))
                    elif isinstance(pyv, str):
                        lbl = f"cstr_ve_{len(self.rdata.labels)}"
                        self.rdata.add_obj_string(lbl, str(pyv))
                        a.lea_rdx_rip(lbl)
                    else:
                        # Fallback: load the const member value (should fold to an immediate or rdata)
                        try:
                            self.emit_load_var(qmem, e)
                            a.mov_rdx_rax()
                        except Exception:
                            a.mov_r64_imm64('rdx', enc_void())

                    # Load lhs (after rhs load; emit_load_var may clobber rcx)
                    a.mov_r64_membase_disp('rcx', 'rsp', off)

                    a.call('fn_val_eq')
                    a.cmp_r64_imm('rax', enc_bool(True))
                    a.jcc('e', l_true)

                a.jmp(l_false)

                a.mark(l_true)
                a.mov_rax_imm64(enc_bool(True))
                a.jmp(l_done)

                a.mark(l_false)
                a.mov_rax_imm64(enc_bool(False))

                a.mark(l_done)
                self.free_expr_temps(8)
                if neg:
                    a.xor_r64_imm8('rax', 8)
                return

            raise CompileError(f"Unknown type '{ty_raw}' in 'is' expression", getattr(e, 'pos', None))


        if isinstance(e, ml.Var):
            # Inline-param override (used by `function inline ...` expansion).
            nm0 = str(getattr(e, 'name', ''))
            for mp in reversed(getattr(self, '_inline_param_stack', []) or []):
                if nm0 in mp:
                    a.mov_rax_rsp_disp32(int(mp[nm0]))
                    return

            nm = self._qualify_identifier(nm0, e)
            try:
                e.name = nm
            except Exception:
                pass
            self.emit_load_var(nm, e)
            return

        # Struct member read: obj.field
        if hasattr(ml, 'Member') and isinstance(e, ml.Member):
            # Step 4: resolve dotted names inside package/namespace context
            # e.g. inside `package std.time`, `win32.Sleep` should resolve to `std.time.win32.Sleep`
            def _qualify_dotted(qn: str, *, kind: str | None = None) -> str:
                qn0 = self._apply_import_alias(str(qn))
                # Simple name: reuse existing qualifier (package + function prefix)
                if '.' not in qn0:
                    return self._qualify_identifier(qn0, e, kind=kind)

                # If already a known decl/binding, keep it
                pools: list[object] = []
                try:
                    if kind in (None, 'func'):
                        pools.append(getattr(self, 'user_functions', {}) or {})
                    if kind in (None, 'extern'):
                        pools.append(getattr(self, 'extern_sigs', {}) or {})
                    if kind in (None, 'struct'):
                        pools.append(getattr(self, 'struct_fields', {}) or {})
                    if kind in (None, 'enum'):
                        pools.append(getattr(self, 'enum_id', {}) or {})  # value-enums are handled via bindings
                except Exception:
                    pools = []

                for pool in pools:
                    try:
                        if qn0 in pool:
                            return qn0
                    except Exception:
                        pass
                try:
                    if hasattr(self, 'resolve_binding') and self.resolve_binding(qn0) is not None:
                        return qn0
                except Exception:
                    pass

                # Try package prefix + dotted name
                pkg = ''
                try:
                    pkg = self._current_file_package_prefix() or ''
                except Exception:
                    pkg = ''
                if isinstance(pkg, str) and pkg and not qn0.startswith(pkg):
                    cand = pkg + qn0
                    for pool in pools:
                        try:
                            if cand in pool:
                                return cand
                        except Exception:
                            pass
                    try:
                        if hasattr(self, 'resolve_binding') and self.resolve_binding(cand) is not None:
                            return cand
                    except Exception:
                        pass

                return qn0

            # Enum variant literal: Color.Red (or qualified: geom.Color.Red).
            # If this member-chain refers to a known enum type, compile it as an enum immediate.
            def _qname_parts(expr: Any) -> Optional[List[str]]:
                if isinstance(expr, ml.Var):
                    # The frontend may encode qualified names as Var("a.b.c").
                    nm = str(expr.name)
                    return nm.split('.') if '.' in nm else [nm]
                if hasattr(ml, 'Member') and isinstance(expr, ml.Member):
                    tgt = getattr(expr, 'target', None)
                    if tgt is None:
                        tgt = getattr(expr, 'obj', None)
                    base = _qname_parts(tgt)
                    if base is None:
                        return None
                    nm = getattr(expr, 'name', None)
                    if nm is None:
                        nm = getattr(expr, 'field', None)
                    if nm is None:
                        return None
                    return base + [str(nm)]
                return None

            parts = _qname_parts(e)
            if parts is not None and len(parts) >= 2:
                enum_qname = ".".join(parts[:-1])
                variant = parts[-1]
                enum_qname = _qualify_dotted(enum_qname, kind='enum')
                # Value-enum members (Step 10): treat EnumName.Member as a qualified const binding.
                val_enums = getattr(self, 'value_enum_values', {}) or {}
                if enum_qname in val_enums:
                    members = val_enums.get(enum_qname) or {}
                    if variant not in members:
                        raise self.error(f"Enum {enum_qname} has no variant {variant}", e)
                    # Load as qualified global (EnumName.Member).
                    self.emit_load_var(f"{enum_qname}.{variant}", e)
                    return

                if enum_qname in self.enum_id:
                    variants = self.enum_variants.get(enum_qname, [])
                    if variant not in variants:
                        raise self.error(f"Enum {enum_qname} has no variant {variant}", e)
                    enum_id = self.enum_id[enum_qname]
                    variant_id = variants.index(variant)
                    a.mov_rax_imm64(enc_enum(enum_id, variant_id))
                    return

                    a.mov_rax_imm64(enc_enum(enum_id, variant_id))
                    return

            # Struct static method reference: StructName.method  -> StructName.__static__.method
            if parts is not None and len(parts) >= 2:
                struct_qn = ".".join(parts[:-1])
                meth = parts[-1]
                struct_qn_m = _qualify_dotted(struct_qn, kind='struct')
                smap = getattr(self, 'struct_static_methods', {}) or {}
                if struct_qn_m in smap and meth in (smap.get(struct_qn_m) or {}):
                    fn_qn = (smap.get(struct_qn_m) or {}).get(meth)
                    if fn_qn:
                        self.emit_load_var(str(fn_qn), e)
                        return

            # Namespace-qualified user function / extern reference: geom.add (compile-time only)

            # Only treat it as a qualified name if the base identifier is NOT a visible
            # runtime binding (so `geom.add` can still mean struct member access when
            # `geom` is a variable).
            if parts is not None:
                full_qname = ".".join(parts)
                full_qname_m = self._apply_import_alias(full_qname)
                full_qname_q = _qualify_dotted(full_qname_m)

                externs = getattr(self, 'extern_sigs', {}) or {}
                externs_q = externs

                has_direct = (
                        full_qname_m in self.user_functions or full_qname_m in self.struct_fields or full_qname_m in externs)
                has_q = (
                        full_qname_q in self.user_functions or full_qname_q in self.struct_fields or full_qname_q in externs_q)
                try:
                    has_direct = has_direct or (
                            hasattr(self, 'resolve_binding') and self.resolve_binding(full_qname_m) is not None)
                except Exception:
                    pass
                try:
                    has_q = has_q or (
                            hasattr(self, 'resolve_binding') and self.resolve_binding(full_qname_q) is not None)
                except Exception:
                    pass

                if has_direct or has_q:
                    # Prefer qualified candidate if it exists
                    if has_q:
                        full_qname_m = full_qname_q
                    base0 = parts[0]
                    b0 = None
                    base_bound = False
                    if hasattr(self, "resolve_binding") and callable(getattr(self, "resolve_binding")):
                        try:
                            b0 = self.resolve_binding(base0)
                        except Exception:
                            b0 = None
                    base_bound = b0 is not None
                    aliases0 = getattr(self, "import_aliases", None) or {}
                    if base0 in aliases0:
                        # Import-alias bases behave like compile-time namespaces unless shadowed.
                        if b0 is None:
                            base_bound = False
                        else:
                            k0 = getattr(b0, "kind", None)
                            if k0 is None or k0 == "global":
                                base_bound = False
                    if (not base_bound) or (base0 in self.struct_fields and (
                            full_qname_m in self.user_functions or full_qname_m in externs)):
                        self.emit_load_var(full_qname_m, e)
                        return

            # Evaluate target into RAX
            tgt = getattr(e, 'target', None)
            if tgt is None:
                tgt = getattr(e, 'obj', None)
            if tgt is None:
                raise self.error("Invalid member access node", e)
            self.emit_expr(tgt)

            fid = self.new_label_id()
            l_ok = f"memb_ok_{fid}"
            l_fail = f"memb_fail_{fid}"
            l_done = f"memb_done_{fid}"

            # Tag check: only pointers can be structs
            a.mov_r10_rax()
            a.and_r64_imm("r10", 7)
            a.cmp_r64_imm("r10", TAG_PTR)
            a.jcc("ne", l_fail)

            # r11 = object ptr
            a.mov_r11_rax()

            # type check
            a.mov_r32_membase_disp("edx", "r11", 0)  # [r11] => type
            a.cmp_r32_imm("edx", OBJ_STRUCT)
            a.jcc("ne", l_fail)

            # load struct_id (u32) into EDX
            a.mov_r32_membase_disp("edx", "r11", 8)  # [r11+8] => struct_id

            field = getattr(e, 'name', None)
            if field is None:
                field = getattr(e, 'field', None)
            field = str(field)

            # Dispatch struct_id -> field index (ECX). Jumps to ok/fail.
            self.emit_struct_field_index_dispatch(field, 'edx', 'ecx', l_ok, l_fail, tag=f"memb_{fid}")

            a.mark(l_ok)
            # value at [r11 + rcx*8 + 16]
            a.mov_r64_mem_bis("rax", "r11", "rcx", 8, 16)
            a.jmp(l_done)

            a.mark(l_fail)
            # Strict void: member access on void is a runtime error.
            vid = self.new_label_id()
            l_nvoid = f"memb_nvoid_{vid}"
            a.mov_r64_r64("r10", "rax")
            a.and_r64_imm("r10", 7)
            a.cmp_r64_imm("r10", TAG_VOID)
            a.jcc("ne", l_nvoid)
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(e)
                except Exception:
                    pass
            mname = getattr(e, 'name', None)
            if mname is None:
                mname = getattr(e, 'field', None)
            self._emit_make_error_const(ERR_VOID_OP, f"Cannot access member '{mname}' on void")
            self._emit_auto_errprop()
            a.jmp(l_done)
            a.mark(l_nvoid)
            a.mov_rax_imm64(enc_void())

            a.mark(l_done)
            return

        if isinstance(e, ml.Unary):
            self.emit_expr(e.right)
            if e.op == '-':
                # unary minus: int or boxed float
                lid = self.new_label_id()
                l_int = f"uminus_int_{lid}"
                l_ptr = f"uminus_ptr_{lid}"
                l_fail = f"uminus_fail_{lid}"
                l_end = f"uminus_end_{lid}"

                # rdx = tag
                a.mov_r64_r64("rdx", "rax")  # mov rdx,rax
                a.and_r64_imm("rdx", 7)  # and rdx,7
                a.cmp_r64_imm("rdx", 1)  # cmp rdx,TAG_INT
                a.jcc('e', l_int)
                a.cmp_r64_imm("rdx", 0)  # cmp rdx,TAG_PTR
                a.jcc('e', l_ptr)
                a.jmp(l_fail)

                a.mark(l_int)
                a.neg_rax()
                a.add_rax_imm8(2)
                a.jmp(l_end)

                a.mark(l_ptr)
                a.mov_r32_membase_disp("edx", "rax", 0)  # mov edx,[rax]
                a.cmp_r32_imm("edx", OBJ_FLOAT)
                a.jcc('ne', l_fail)
                a.movsd_xmm_membase_disp("xmm0", "rax", 8)  # movsd xmm0,[rax+8]
                a.xorpd_xmm_xmm("xmm1", "xmm1")  # xorpd xmm1,xmm1
                a.subsd_xmm_xmm("xmm1", "xmm0")  # subsd xmm1,xmm0
                a.movapd_xmm_xmm("xmm0", "xmm1")  # movapd xmm0,xmm1
                self.emit_normalize_xmm0_to_value()
                a.jmp(l_end)

                a.mark(l_fail)
                # Strict void: unary '-' on void is a runtime error.
                vid = self.new_label_id()
                l_nvoid = f"uminus_nvoid_{vid}"
                a.mov_r64_r64("rdx", "rax")
                a.and_r64_imm("rdx", 7)
                a.cmp_r64_imm("rdx", TAG_VOID)
                a.jcc('ne', l_nvoid)
                if hasattr(self, 'emit_dbg_line'):
                    try:
                        self.emit_dbg_line(e)
                    except Exception:
                        pass
                self._emit_make_error_const(ERR_VOID_OP, "Cannot apply unary '-' to void")
                self._emit_auto_errprop()
                a.jmp(l_end)
                a.mark(l_nvoid)
                a.mov_rax_imm64(enc_void())

                a.mark(l_end)
                return
            if e.op == 'not':
                # compute truthy, then invert -> bool
                lbl_false = f"not_false_{a.pos}"
                lbl_end = f"not_end_{a.pos}"

                # default assume true -> if false jump
                # if falsy -> set true (inverted)
                # We'll branch based on truthy:
                # if cond false -> result true
                # else -> result false

                # Strict void: unary 'not' on void is a runtime error.
                vid = self.new_label_id()
                l_nvoid = f"not_nvoid_{vid}"
                a.mov_r64_r64("rdx", "rax")
                a.and_r64_imm("rdx", 7)
                a.cmp_r64_imm("rdx", TAG_VOID)
                a.jcc('ne', l_nvoid)
                if hasattr(self, 'emit_dbg_line'):
                    try:
                        self.emit_dbg_line(e)
                    except Exception:
                        pass
                self._emit_make_error_const(ERR_VOID_OP, "Cannot apply unary 'not' to void")
                self._emit_auto_errprop()
                a.jmp(lbl_end)
                a.mark(l_nvoid)

                # Jump if false to lbl_false
                self.emit_jmp_if_false_rax(lbl_false)

                # truthy => not => false
                a.mov_rax_imm64(enc_bool(False))
                a.jmp(lbl_end)

                a.mark(lbl_false)
                a.mov_rax_imm64(enc_bool(True))

                a.mark(lbl_end)
                return

            if e.op == '~':
                # bitwise NOT: int only (tagged ints)
                lid = self.new_label_id()
                l_ok = f"bnot_ok_{lid}"
                l_fail = f"bnot_fail_{lid}"
                l_end = f"bnot_end_{lid}"

                # tag check
                a.mov_r64_r64("rdx", "rax")
                a.and_r64_imm("rdx", 7)
                a.cmp_r64_imm("rdx", TAG_INT)
                a.jcc('e', l_ok)
                a.jmp(l_fail)

                a.mark(l_ok)
                # untag -> ~ -> retag
                a.sar_r64_imm8("rax", 3)
                a.xor_r64_imm("rax", -1)
                a.shl_r64_imm8("rax", 3)
                a.or_rax_imm8(TAG_INT)
                a.jmp(l_end)

                a.mark(l_fail)
                # Strict void: unary '~' on void is a runtime error.
                vid = self.new_label_id()
                l_nvoid = f"bnot_nvoid_{vid}"
                a.mov_r64_r64("rdx", "rax")
                a.and_r64_imm("rdx", 7)
                a.cmp_r64_imm("rdx", TAG_VOID)
                a.jcc('ne', l_nvoid)
                if hasattr(self, 'emit_dbg_line'):
                    try:
                        self.emit_dbg_line(e)
                    except Exception:
                        pass
                self._emit_make_error_const(ERR_VOID_OP, "Cannot apply unary '~' to void")
                self._emit_auto_errprop()
                a.jmp(l_end)
                a.mark(l_nvoid)
                a.mov_rax_imm64(enc_void())

                a.mark(l_end)
                return

            raise self.error(f"Unsupported unary op: {e.op}", e)

        if isinstance(e, ml.Bin):
            # logical short-circuit
            if e.op in ('and', 'or'):
                if e.op == 'and':
                    lid = self.new_label_id()
                    lbl_false = f"and_false_{lid}"
                    lbl_end = f"and_end_{lid}"
                    self.emit_expr(e.left)
                    # Strict void: boolean ops on void are runtime errors.
                    vid = self.new_label_id()
                    l_nvoid = f"and_nvoid_{vid}"
                    a.mov_r64_r64("rdx", "rax")
                    a.and_r64_imm("rdx", 7)
                    a.cmp_r64_imm("rdx", TAG_VOID)
                    a.jcc('ne', l_nvoid)
                    if hasattr(self, 'emit_dbg_line'):
                        try:
                            self.emit_dbg_line(e)
                        except Exception:
                            pass
                    self._emit_make_error_const(ERR_VOID_OP, "Cannot apply 'and' to void")
                    self._emit_auto_errprop()
                    a.jmp(lbl_end)
                    a.mark(l_nvoid)
                    self.emit_jmp_if_false_rax(lbl_false)
                    self.emit_expr(e.right)
                    vidr = self.new_label_id()
                    l_rnvoid = f"and_rnvoid_{vidr}"
                    a.mov_r64_r64("rdx", "rax")
                    a.and_r64_imm("rdx", 7)
                    a.cmp_r64_imm("rdx", TAG_VOID)
                    a.jcc('ne', l_rnvoid)
                    if hasattr(self, 'emit_dbg_line'):
                        try:
                            self.emit_dbg_line(e)
                        except Exception:
                            pass
                    self._emit_make_error_const(ERR_VOID_OP, "Cannot apply 'and' to void")
                    self._emit_auto_errprop()
                    a.jmp(lbl_end)
                    a.mark(l_rnvoid)
                    # result = truthy(right)
                    lbl_rfalse = f"and_rfalse_{lid}"
                    self.emit_jmp_if_false_rax(lbl_rfalse)
                    a.mov_rax_imm64(enc_bool(True))
                    a.jmp(lbl_end)
                    a.mark(lbl_rfalse)
                    a.mov_rax_imm64(enc_bool(False))
                    a.jmp(lbl_end)
                    a.mark(lbl_false)
                    a.mov_rax_imm64(enc_bool(False))
                    a.mark(lbl_end)
                    return

                if e.op == 'or':
                    lid = self.new_label_id()
                    lbl_end = f"or_end_{lid}"
                    self.emit_expr(e.left)
                    vid = self.new_label_id()
                    l_nvoid = f"or_nvoid_{vid}"
                    a.mov_r64_r64("rdx", "rax")
                    a.and_r64_imm("rdx", 7)
                    a.cmp_r64_imm("rdx", TAG_VOID)
                    a.jcc('ne', l_nvoid)
                    if hasattr(self, 'emit_dbg_line'):
                        try:
                            self.emit_dbg_line(e)
                        except Exception:
                            pass
                    self._emit_make_error_const(ERR_VOID_OP, "Cannot apply 'or' to void")
                    self._emit_auto_errprop()
                    a.jmp(lbl_end)
                    a.mark(l_nvoid)
                    # if truthy -> result true
                    lbl_eval_right = f"or_eval_{lid}"
                    self.emit_jmp_if_false_rax(lbl_eval_right)
                    a.mov_rax_imm64(enc_bool(True))
                    a.jmp(lbl_end)
                    a.mark(lbl_eval_right)
                    self.emit_expr(e.right)
                    vidr = self.new_label_id()
                    l_rnvoid = f"or_rnvoid_{vidr}"
                    a.mov_r64_r64("rdx", "rax")
                    a.and_r64_imm("rdx", 7)
                    a.cmp_r64_imm("rdx", TAG_VOID)
                    a.jcc('ne', l_rnvoid)
                    if hasattr(self, 'emit_dbg_line'):
                        try:
                            self.emit_dbg_line(e)
                        except Exception:
                            pass
                    self._emit_make_error_const(ERR_VOID_OP, "Cannot apply 'or' to void")
                    self._emit_auto_errprop()
                    a.jmp(lbl_end)
                    a.mark(l_rnvoid)
                    lbl_rfalse = f"or_rfalse_{lid}"
                    self.emit_jmp_if_false_rax(lbl_rfalse)
                    a.mov_rax_imm64(enc_bool(True))
                    a.jmp(lbl_end)
                    a.mark(lbl_rfalse)
                    a.mov_rax_imm64(enc_bool(False))
                    a.mark(lbl_end)
                    return

            # normal binary: preserve left/right across calls by spilling to nested-safe temp slots
            base = self.alloc_expr_temps(16)
            self.emit_expr(e.left)
            a.mov_rsp_disp32_rax(base + 0)
            self.emit_expr(e.right)
            a.mov_rsp_disp32_rax(base + 8)

            # load left -> r10, right -> r11
            a.mov_rax_rsp_disp32(base + 0)
            a.mov_r10_rax()
            a.mov_rax_rsp_disp32(base + 8)
            a.mov_r11_rax()

            self.free_expr_temps(16)

            # -------------------------
            # Numeric ops (int + float)
            # -------------------------

            # -------------------------
            # Bitwise ops (ints)
            # -------------------------
            if e.op in ('&', '|', '^'):
                lid = self.new_label_id()
                l_fail = f"bit_fail_{lid}"
                l_done = f"bit_done_{lid}"

                # both operands must be TAG_INT
                a.mov_rax_r10()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_INT)
                a.jcc('ne', l_fail)
                a.mov_rax_r11()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_INT)
                a.jcc('ne', l_fail)

                a.mov_rax_r10()
                if e.op == '&':
                    a.and_r64_r64("rax", "r11")
                elif e.op == '|':
                    a.or_r64_r64("rax", "r11")
                else:  # '^'
                    a.xor_r64_r64("rax", "r11")
                    a.or_rax_imm8(TAG_INT)  # fix tag bits (1^1 -> 0)

                a.jmp(l_done)

                a.mark(l_fail)
                # Strict void: bitwise ops on void are runtime errors.
                vid = self.new_label_id()
                l_nvoid = f"bit_nvoid_{vid}"
                l_isvoid = f"bit_isvoid_{vid}"
                a.mov_r64_r64("rax", "r10")
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_VOID)
                a.jcc('e', l_isvoid)
                a.mov_r64_r64("rax", "r11")
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_VOID)
                a.jcc('ne', l_nvoid)
                a.mark(l_isvoid)
                if hasattr(self, 'emit_dbg_line'):
                    try:
                        self.emit_dbg_line(e)
                    except Exception:
                        pass
                self._emit_make_error_const(ERR_VOID_OP, f"Cannot apply '{e.op}' to void")
                self._emit_auto_errprop()
                a.jmp(l_done)
                a.mark(l_nvoid)
                a.mov_rax_imm64(enc_void())
                a.mark(l_done)
                return

            if e.op in ('<<', '>>'):
                # Variable shifts for tagged ints.
                # Semantics: arithmetic shift right for '>>' (matches Python / interpreter for ints).
                lid = self.new_label_id()
                l_fail = f"sh_fail_{lid}"
                l_done = f"sh_done_{lid}"

                # lhs must be TAG_INT
                a.mov_rax_r10()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_INT)
                a.jcc('ne', l_fail)

                # rhs must be TAG_INT
                a.mov_rax_r11()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_INT)
                a.jcc('ne', l_fail)

                # rax = untagged lhs
                a.mov_rax_r10()
                a.sar_r64_imm8("rax", 3)

                # rcx = untagged rhs (shift amount), masked to 0..63
                a.mov_r64_r64("rcx", "r11")
                a.sar_r64_imm8("rcx", 3)
                # negative shift counts are invalid -> void
                a.cmp_r64_imm("rcx", 0)
                a.jcc('l', l_fail)
                a.and_r64_imm("rcx", 63)

                if e.op == '<<':
                    a.shl_r64_cl("rax")
                else:
                    a.sar_r64_cl("rax")

                # retag
                a.shl_r64_imm8("rax", 3)
                a.or_rax_imm8(TAG_INT)
                a.jmp(l_done)

                a.mark(l_fail)
                                # Strict void: shift ops on void are runtime errors.
                vid = self.new_label_id()
                l_nvoid = f"sh_nvoid_{vid}"
                l_isvoid = f"sh_isvoid_{vid}"
                a.mov_r64_r64("rax", "r10")
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_VOID)
                a.jcc('e', l_isvoid)
                a.mov_r64_r64("rax", "r11")
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_VOID)
                a.jcc('ne', l_nvoid)
                a.mark(l_isvoid)
                if hasattr(self, 'emit_dbg_line'):
                    try:
                        self.emit_dbg_line(e)
                    except Exception:
                        pass
                self._emit_make_error_const(ERR_VOID_OP, f"Cannot apply '{e.op}' to void")
                self._emit_auto_errprop()
                a.jmp(l_done)
                a.mark(l_nvoid)
                a.mov_rax_imm64(enc_void())
                a.mark(l_done)
                return

                lid = self.new_label_id()
                l_fail = f"sh_fail_{lid}"
                l_done = f"sh_done_{lid}"

                # lhs must be TAG_INT
                a.mov_rax_r10()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_INT)
                a.jcc('ne', l_fail)

                a.mov_rax_r10()
                # untag
                a.sar_r64_imm8("rax", 3)
                # compile-time check: negative literal shift -> void
                if sh < 0:
                    a.jmp(l_fail)
                if e.op == '<<':
                    a.shl_r64_imm8("rax", sh)
                else:
                    a.sar_r64_imm8("rax", sh)
                # retag
                a.shl_r64_imm8("rax", 3)
                a.or_rax_imm8(TAG_INT)
                a.jmp(l_done)

                a.mark(l_fail)
                a.mov_rax_imm64(enc_void())
                a.mark(l_done)
                return

            # '/' : always numeric division (float), normalize if exact int (matches interpreter)
            if e.op == '/':
                lid = self.new_label_id()
                l_fail = f"div_fail_{lid}"
                l_done = f"div_done_{lid}"

                # Strict void: division on void is a runtime error.
                vidv = self.new_label_id()
                l_nvoid = f"div_nvoid_{vidv}"
                l_isvoid = f"div_isvoid_{vidv}"
                a.mov_r64_r64("rax", "r10")
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_VOID)
                a.jcc('e', l_isvoid)
                a.mov_r64_r64("rax", "r11")
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_VOID)
                a.jcc('ne', l_nvoid)
                a.mark(l_isvoid)
                if hasattr(self, 'emit_dbg_line'):
                    try:
                        self.emit_dbg_line(e)
                    except Exception:
                        pass
                self._emit_make_error_const(ERR_VOID_OP, "Cannot apply '/' to void")
                self._emit_auto_errprop()
                a.jmp(l_done)
                a.mark(l_nvoid)

                a.mov_rax_r10()
                self.emit_to_double_xmm(0, l_fail)
                a.mov_rax_r11()
                self.emit_to_double_xmm(1, l_fail)

                # division by 0 -> fail (return void)
                a.xorpd_xmm_xmm("xmm2", "xmm2")  # xorpd xmm2,xmm2
                a.ucomisd_xmm_xmm("xmm1", "xmm2")  # ucomisd xmm1,xmm2
                a.jcc('e', l_fail)

                a.divsd_xmm_xmm("xmm0", "xmm1")  # divsd xmm0,xmm1
                self.emit_normalize_xmm0_to_value()
                a.jmp(l_done)

                a.mark(l_fail)
                a.mov_rax_imm64(enc_void())
                a.mark(l_done)
                return

            # '+' : numeric addition if both operands are numeric; otherwise string concatenation
            # (matches interpreter: numbers add, lists concat, else string concat)
            if e.op == '+':
                lid = self.new_label_id()
                l_check_numeric = f"add_checknum_{lid}"
                l_num2_check = f"add_checknum2_{lid}"
                l_float_add = f"add_float_{lid}"
                l_bytes = f"add_bytes_{lid}"
                l_bytes_fail = f"add_bytes_fail_{lid}"
                l_bytes_check2 = f"add_bytes_check2_{lid}"
                l_bytes_after = f"add_bytes_after_{lid}"
                l_str = f"add_str_{lid}"
                l_done = f"add_done_{lid}"
                l_arrcheck = f"add_arrcheck_{lid}"

                # Strict void: '+' on void is a runtime error unless used in string concatenation.
                vidv = self.new_label_id()
                l_nvoid = f"add_nvoid_{vidv}"
                l_isvoid = f"add_isvoid_{vidv}"
                l_void_lhs = f"add_voidlhs_{vidv}"
                l_void_rhs = f"add_voidrhs_{vidv}"

                # if lhs is void, allow only when rhs is string
                a.mov_r64_r64("rax", "r10")
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_VOID)
                a.jcc('e', l_void_lhs)

                # if rhs is void, allow only when lhs is string
                a.mov_r64_r64("rax", "r11")
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_VOID)
                a.jcc('e', l_void_rhs)
                a.jmp(l_nvoid)

                a.mark(l_void_lhs)
                a.mov_r64_r64("rax", "r11")
                a.mov_r64_r64("rdx", "rax")
                a.and_r64_imm("rdx", 7)
                a.cmp_r64_imm("rdx", TAG_PTR)
                a.jcc('ne', l_isvoid)
                a.mov_r32_membase_disp("edx", "rax", 0)
                a.cmp_r32_imm("edx", OBJ_STRING)
                a.jcc('e', l_nvoid)
                a.jmp(l_isvoid)

                a.mark(l_void_rhs)
                a.mov_r64_r64("rax", "r10")
                a.mov_r64_r64("rdx", "rax")
                a.and_r64_imm("rdx", 7)
                a.cmp_r64_imm("rdx", TAG_PTR)
                a.jcc('ne', l_isvoid)
                a.mov_r32_membase_disp("edx", "rax", 0)
                a.cmp_r32_imm("edx", OBJ_STRING)
                a.jcc('e', l_nvoid)
                a.jmp(l_isvoid)

                a.mark(l_isvoid)
                if hasattr(self, 'emit_dbg_line'):
                    try:
                        self.emit_dbg_line(e)
                    except Exception:
                        pass
                self._emit_make_error_const(ERR_VOID_OP, "Cannot apply '+' to void")
                self._emit_auto_errprop()
                a.jmp(l_done)
                a.mark(l_nvoid)

                # ---- int fast path (both TAG_INT) ----
                a.mov_rax_r10()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_INT)
                a.jcc('ne', l_check_numeric)
                a.mov_rax_r11()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_INT)
                a.jcc('ne', l_check_numeric)

                a.mov_rax_r10()
                a.add_r64_r64("rax", "r11")  # add rax,r11
                a.sub_rax_imm8(1)
                a.jmp(l_done)

                # ---- non-int: if both numeric (int/float), do float add, else string concat ----
                a.mark(l_check_numeric)

                # check operand1 is numeric (TAG_INT or boxed float)
                a.mov_rax_r10()
                a.mov_r64_r64("rdx", "rax")  # mov rdx,rax
                a.and_r64_imm("rdx", 7)  # and rdx,7
                a.cmp_r64_imm("rdx", 1)  # cmp rdx,TAG_INT
                a.jcc('e', l_num2_check)
                a.cmp_r64_imm("rdx", 0)  # cmp rdx,TAG_PTR
                a.jcc('ne', l_arrcheck)
                a.mov_r32_membase_disp("edx", "rax", 0)  # mov edx,[rax]
                a.cmp_r32_imm("edx", OBJ_FLOAT)
                a.jcc('ne', l_arrcheck)

                # check operand2 is numeric
                a.mark(l_num2_check)
                a.mov_rax_r11()
                a.mov_r64_r64("rdx", "rax")  # mov rdx,rax
                a.and_r64_imm("rdx", 7)  # and rdx,7
                a.cmp_r64_imm("rdx", 1)  # cmp rdx,TAG_INT
                a.jcc('e', l_float_add)
                a.cmp_r64_imm("rdx", 0)  # cmp rdx,TAG_PTR
                a.jcc('ne', l_arrcheck)
                a.mov_r32_membase_disp("edx", "rax", 0)  # mov edx,[rax]
                a.cmp_r32_imm("edx", OBJ_FLOAT)
                a.jcc('ne', l_arrcheck)

                # ---- float add (covers int+float, float+int, float+float) ----
                a.mark(l_float_add)
                a.mov_rax_r10()
                self.emit_to_double_xmm(0, l_str)
                a.mov_rax_r11()
                self.emit_to_double_xmm(1, l_str)
                a.addsd_xmm_xmm("xmm0", "xmm1")  # addsd xmm0,xmm1
                self.emit_normalize_xmm0_to_value()
                a.jmp(l_done)

                # ---- bytes concat check (bytes + bytes) ----
                # If either operand is bytes:
                #   - bytes + bytes => bytes concat
                #   - bytes + other => void
                a.mark(l_arrcheck)

                # if op1 is bytes -> l_bytes
                a.mov_rax_r10()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_PTR)
                a.jcc('ne', l_bytes_check2)
                a.mov_rax_r10()
                a.mov_r32_membase_disp("edx", "rax", 0)
                a.cmp_r32_imm("edx", OBJ_BYTES)
                a.jcc('e', l_bytes)

                # else if op2 is bytes -> l_bytes_fail (mixed)
                a.mark(l_bytes_check2)
                a.mov_rax_r11()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_PTR)
                a.jcc('ne', l_bytes_after)
                a.mov_rax_r11()
                a.mov_r32_membase_disp("edx", "rax", 0)
                a.cmp_r32_imm("edx", OBJ_BYTES)
                a.jcc('e', l_bytes_fail)

                a.mark(l_bytes_after)

                # ---- array concat check (list + list) ----
                # operand1 must be ptr to OBJ_ARRAY
                a.mov_rax_r10()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_PTR)
                a.jcc('ne', l_str)
                a.mov_rax_r10()
                a.mov_r32_membase_disp("edx", "rax", 0)  # mov edx,[rax]
                a.cmp_r32_imm("edx", OBJ_ARRAY)
                a.jcc('ne', l_str)

                # operand2 must be ptr to OBJ_ARRAY
                a.mov_rax_r11()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_PTR)
                a.jcc('ne', l_str)
                a.mov_rax_r11()
                a.mov_r32_membase_disp("edx", "rax", 0)  # mov edx,[rax]
                a.cmp_r32_imm("edx", OBJ_ARRAY)
                a.jcc('ne', l_str)

                # call fn_add_array(rcx=r10, rdx=r11)
                a.mov_r64_r64("rcx", "r10")  # mov rcx,r10
                a.mov_r64_r64("rdx", "r11")  # mov rdx,r11
                a.call('fn_add_array')
                a.jmp(l_done)

                # ---- bytes concat (bytes + bytes) ----
                a.mark(l_bytes)
                # operand2 must be ptr to OBJ_BYTES
                a.mov_rax_r11()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_PTR)
                a.jcc('ne', l_bytes_fail)
                a.mov_rax_r11()
                a.mov_r32_membase_disp("edx", "rax", 0)
                a.cmp_r32_imm("edx", OBJ_BYTES)
                a.jcc('ne', l_bytes_fail)

                a.mov_r64_r64("rcx", "r10")
                a.mov_r64_r64("rdx", "r11")
                a.call('fn_add_bytes')
                a.jmp(l_done)

                # bytes mixed types => void
                a.mark(l_bytes_fail)
                a.mov_rax_imm64(enc_void())
                a.jmp(l_done)

                # ---- string concat fallback ----
                a.mark(l_str)
                a.mov_r64_r64("rcx", "r10")  # mov rcx,r10
                a.mov_r64_r64("rdx", "r11")  # mov rdx,r11
                a.call('fn_add_string')
                a.jmp(l_done)

                a.mark(l_done)
                return

            # - * % : int fast-path, otherwise float numeric path
            if e.op in ('-', '*', '%'):
                lid = self.new_label_id()
                l_float = f"arith_float_{lid}"
                l_fail = f"arith_fail_{lid}"
                l_done = f"arith_done_{lid}"

                # check both int-tags
                a.mov_rax_r10()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_INT)
                a.jcc('ne', l_float)
                a.mov_rax_r11()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_INT)
                a.jcc('ne', l_float)

                # ---- int fast path ----
                if e.op == '-':
                    a.mov_rax_r10()
                    a.sub_rax_r11()
                    a.add_rax_imm8(1)
                    a.jmp(l_done)

                elif e.op == '*':
                    a.mov_rax_r10()
                    a.sar_rax_imm8(3)
                    a.sar_r64_imm8("r11", 3)  # sar r11,3
                    a.imul_r64_r64("rax", "r11")  # imul rax,r11
                    a.shl_rax_imm8(3)
                    a.or_rax_imm8(TAG_INT)
                    a.jmp(l_done)

                elif e.op == '%':
                    # integer modulo with Python semantics: remainder has sign of divisor
                    a.mov_rax_r10()
                    a.sar_rax_imm8(3)
                    a.sar_r64_imm8("r11", 3)  # sar r11,3

                    # modulo by 0 -> fail (avoid CPU exception)
                    a.test_r64_r64("r11", "r11")  # test r11,r11
                    a.jcc('e', l_fail)
                    a.cqo()  # cqo
                    a.idiv_r64("r11")  # idiv r11

                    # rdx = remainder (CPU remainder, sign of dividend). Adjust to Python semantics:
                    # if rdx != 0 and sign(rdx) != sign(divisor) then rdx += divisor
                    l_mod_ok = f"mod_ok_{lid}"
                    a.test_r64_r64("rdx", "rdx")  # test rdx,rdx
                    a.jcc('e', l_mod_ok)
                    a.mov_r64_r64("rax", "rdx")  # mov rax,rdx
                    a.xor_r64_r64("rax", "r11")  # xor rax,r11
                    a.test_r64_r64("rax", "rax")  # test rax,rax
                    a.jcc('ge', l_mod_ok)
                    a.add_r64_r64("rdx", "r11")  # add rdx,r11
                    a.mark(l_mod_ok)

                    a.mov_r64_r64("rax", "rdx")  # mov rax,rdx
                    a.shl_rax_imm8(3)
                    a.or_rax_imm8(TAG_INT)
                    a.jmp(l_done)

                # ---- float numeric path ----
                a.mark(l_float)

                a.mov_rax_r10()
                self.emit_to_double_xmm(0, l_fail)
                a.mov_rax_r11()
                self.emit_to_double_xmm(1, l_fail)

                if e.op == '-':
                    a.subsd_xmm_xmm("xmm0", "xmm1")  # subsd xmm0,xmm1
                elif e.op == '*':
                    a.mulsd_xmm_xmm("xmm0", "xmm1")  # mulsd xmm0,xmm1
                elif e.op == '%':
                    # float modulo with Python semantics: r = a - floor(a/b)*b
                    # divisor == 0 ?
                    a.xorpd_xmm_xmm("xmm2", "xmm2")  # xorpd xmm2,xmm2
                    a.ucomisd_xmm_xmm("xmm1", "xmm2")  # ucomisd xmm1,xmm2
                    a.jcc('e', l_fail)

                    # preserve dividend in xmm3
                    a.movapd_xmm_xmm("xmm3", "xmm0")  # movapd xmm3,xmm0

                    # q = a / b
                    a.divsd_xmm_xmm("xmm0", "xmm1")  # divsd xmm0,xmm1

                    # floor(q) into xmm2 (round down)
                    a.roundsd_xmm_xmm_imm8("xmm2", "xmm0", 1)  # roundsd xmm2,xmm0,1

                    # trunc(q) * b
                    a.mulsd_xmm_xmm("xmm2", "xmm1")  # mulsd xmm2,xmm1

                    # r = a - trunc(q)*b
                    a.subsd_xmm_xmm("xmm3", "xmm2")  # subsd xmm3,xmm2

                    # move result to xmm0
                    a.movapd_xmm_xmm("xmm0", "xmm3")  # movapd xmm0,xmm3

                self.emit_normalize_xmm0_to_value()
                a.jmp(l_done)

                a.mark(l_fail)
                a.mov_rax_imm64(enc_void())
                a.mark(l_done)
                return

            # comparisons
            cmp_map = {'==': ('e', 'e'), '!=': ('ne', 'ne'), '<': ('l', 'b'), '<=': ('le', 'be'), '>': ('g', 'a'),
                       '>=': ('ge', 'ae'), }
            if e.op in cmp_map:
                lid = self.new_label_id()
                l_float = f"cmp_float_{lid}"
                l_fail = f"cmp_fail_{lid}"
                l_done = f"cmp_done_{lid}"

                int_cc, float_cc = cmp_map[e.op]

                # int fast-path if both tagged ints
                a.mov_rax_r10()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_INT)
                a.jcc('ne', l_float)
                a.mov_rax_r11()
                a.and_rax_imm8(7)
                a.cmp_rax_imm8(TAG_INT)
                a.jcc('ne', l_float)

                # compare encoded ints directly
                a.cmp_r64_r64("r10", "r11")  # cmp r10, r11
                a.setcc_al(int_cc)
                a.movzx_eax_al()
                a.shl_rax_imm8(3)
                a.or_rax_imm8(TAG_BOOL)
                a.jmp(l_done)

                # float numeric compare
                a.mark(l_float)
                a.mov_rax_r10()
                self.emit_to_double_xmm(0, l_fail)
                a.mov_rax_r11()
                self.emit_to_double_xmm(1, l_fail)
                a.ucomisd_xmm_xmm("xmm0", "xmm1")  # ucomisd xmm0,xmm1

                # Handle unordered (NaN) comparisons like Python:
                #   NaN == x  -> False
                #   NaN != x  -> True
                #   NaN <,<=,>,>= x -> False
                if e.op == '==':
                    # result = (ZF==1 and PF==0)
                    a.setcc_al('e')
                    a.setcc_r8("dl", "p")  # setp dl
                    a.xor_r8_imm8("dl", 1)  # xor dl,1
                    a.and_r8_r8("al", "dl")  # and al,dl
                elif e.op == '!=':
                    # result = (ZF==0 or PF==1)
                    a.setcc_al('ne')
                    a.setcc_r8("dl", "p")  # setp dl
                    a.or_r8_r8("al", "dl")  # or al,dl
                else:
                    # ordered compare; if unordered -> false
                    a.setcc_al(float_cc)
                    a.setcc_r8("dl", "p")  # setp dl
                    a.xor_r8_imm8("dl", 1)  # xor dl,1
                    a.and_r8_r8("al", "dl")  # and al,dl

                a.movzx_eax_al()
                a.shl_rax_imm8(3)
                a.or_rax_imm8(TAG_BOOL)
                a.jmp(l_done)

                # fallback
                a.mark(l_fail)
                if e.op in ('==', '!='):
                    # Full value equality (strings/arrays by content, numeric mix incl. bool).
                    # Special-case bytes here because older fn_val_eq versions don't know OBJ_BYTES.
                    eid = self.new_label_id()
                    l_lhs_not_bytes = f"eq_lhs_not_bytes_{eid}"
                    l_rhs_not_bytes = f"eq_rhs_not_bytes_{eid}"
                    l_bytes_only = f"eq_bytes_only_{eid}"
                    l_call_val = f"eq_call_val_{eid}"
                    l_done_eq = f"eq_done_{eid}"


                    # Enum equality extensions (== / !=):
                    # - enum == enum: compare ordinal (variant_id) only (cross-enum allowed)
                    # - enum == int: compare ordinal to int
                    # - enum == string/other: always false (or true for !=)
                    cc = 'e' if e.op == '==' else 'ne'
                    eeid = self.new_label_id()
                    l_no_enum = f"eq_no_enum_{eeid}"
                    l_lhs_enum = f"eq_lhs_enum_{eeid}"
                    l_rhs_enum = f"eq_rhs_enum_{eeid}"
                    l_enum_enum = f"eq_enum_enum_{eeid}"
                    l_enum_int = f"eq_enum_int_{eeid}"
                    l_int_enum = f"eq_int_enum_{eeid}"

                    # if lhs is enum -> l_lhs_enum
                    a.mov_rax_r10()
                    a.and_rax_imm8(7)
                    a.cmp_rax_imm8(TAG_ENUM)
                    a.jcc('e', l_lhs_enum)
                    # else if rhs is enum -> l_rhs_enum
                    a.mov_rax_r11()
                    a.and_rax_imm8(7)
                    a.cmp_rax_imm8(TAG_ENUM)
                    a.jcc('e', l_rhs_enum)
                    a.jmp(l_no_enum)

                    a.mark(l_lhs_enum)
                    # rhs enum?
                    a.mov_rax_r11()
                    a.and_rax_imm8(7)
                    a.cmp_rax_imm8(TAG_ENUM)
                    a.jcc('e', l_enum_enum)
                    # rhs int?
                    a.cmp_rax_imm8(TAG_INT)
                    a.jcc('e', l_enum_int)
                    # else: non-int rhs
                    a.xor_r32_r32('eax', 'eax')
                    if e.op == '!=':
                        a.inc_r32('eax')
                    a.shl_rax_imm8(3)
                    a.or_rax_imm8(TAG_BOOL)
                    a.jmp(l_done_eq)

                    a.mark(l_rhs_enum)
                    # lhs int?
                    a.mov_rax_r10()
                    a.and_rax_imm8(7)
                    a.cmp_rax_imm8(TAG_INT)
                    a.jcc('e', l_int_enum)
                    # else: non-int lhs
                    a.xor_r32_r32('eax', 'eax')
                    if e.op == '!=':
                        a.inc_r32('eax')
                    a.shl_rax_imm8(3)
                    a.or_rax_imm8(TAG_BOOL)
                    a.jmp(l_done_eq)

                    a.mark(l_enum_enum)
                    # compare ordinals (variant_id)
                    a.mov_r64_r64('r8', 'r10')
                    a.shr_r64_imm8('r8', 11)   # (v>>3)>>8
                    a.mov_r64_r64('r9', 'r11')
                    a.shr_r64_imm8('r9', 11)
                    a.cmp_r64_r64('r8', 'r9')
                    a.setcc_al(cc)
                    a.movzx_eax_al()
                    a.shl_rax_imm8(3)
                    a.or_rax_imm8(TAG_BOOL)
                    a.jmp(l_done_eq)

                    a.mark(l_enum_int)
                    # enum ordinal vs int
                    a.mov_r64_r64('r8', 'r10')
                    a.shr_r64_imm8('r8', 11)
                    a.mov_r64_r64('r9', 'r11')
                    a.sar_r64_imm8('r9', 3)
                    a.cmp_r64_r64('r8', 'r9')
                    a.setcc_al(cc)
                    a.movzx_eax_al()
                    a.shl_rax_imm8(3)
                    a.or_rax_imm8(TAG_BOOL)
                    a.jmp(l_done_eq)

                    a.mark(l_int_enum)
                    a.mov_r64_r64('r8', 'r10')
                    a.sar_r64_imm8('r8', 3)
                    a.mov_r64_r64('r9', 'r11')
                    a.shr_r64_imm8('r9', 11)
                    a.cmp_r64_r64('r8', 'r9')
                    a.setcc_al(cc)
                    a.movzx_eax_al()
                    a.shl_rax_imm8(3)
                    a.or_rax_imm8(TAG_BOOL)
                    a.jmp(l_done_eq)

                    a.mark(l_no_enum)

                    # --- check if lhs is bytes ---
                    a.mov_r64_r64('rax', 'r10')
                    a.mov_r64_r64('r9', 'rax')
                    a.and_r64_imm('r9', 7)
                    a.cmp_r64_imm('r9', TAG_PTR)
                    a.jcc('ne', l_lhs_not_bytes)
                    a.mov_r32_membase_disp('r9d', 'rax', 0)
                    a.cmp_r32_imm('r9d', OBJ_BYTES)
                    a.jcc('ne', l_lhs_not_bytes)

                    # lhs is bytes: check rhs is bytes
                    a.mov_r64_r64('rax', 'r11')
                    a.mov_r64_r64('r9', 'rax')
                    a.and_r64_imm('r9', 7)
                    a.cmp_r64_imm('r9', TAG_PTR)
                    a.jcc('ne', l_bytes_only)
                    a.mov_r32_membase_disp('r9d', 'rax', 0)
                    a.cmp_r32_imm('r9d', OBJ_BYTES)
                    a.jcc('ne', l_bytes_only)

                    # both bytes -> call fn_bytes_eq
                    a.mov_r64_r64('rcx', 'r10')
                    a.mov_r64_r64('rdx', 'r11')
                    a.call('fn_bytes_eq')
                    if e.op == '!=':
                        a.xor_r64_imm('rax', 8)  # invert encoded bool
                    a.jmp(l_done_eq)

                    # --- lhs not bytes ---
                    a.mark(l_lhs_not_bytes)
                    # if rhs is bytes => bytes_only
                    a.mov_r64_r64('rax', 'r11')
                    a.mov_r64_r64('r9', 'rax')
                    a.and_r64_imm('r9', 7)
                    a.cmp_r64_imm('r9', TAG_PTR)
                    a.jcc('ne', l_call_val)
                    a.mov_r32_membase_disp('r9d', 'rax', 0)
                    a.cmp_r32_imm('r9d', OBJ_BYTES)
                    a.jcc('e', l_bytes_only)

                    # neither bytes -> call fn_val_eq
                    a.mark(l_call_val)
                    a.mov_r64_r64('rcx', 'r10')
                    a.mov_r64_r64('rdx', 'r11')
                    a.call('fn_val_eq')
                    if e.op == '!=':
                        a.xor_r64_imm('rax', 8)
                    a.jmp(l_done_eq)

                    # one side bytes => (== false) or (!= true)
                    a.mark(l_bytes_only)
                    a.xor_r32_r32('eax', 'eax')
                    if e.op == '!=':
                        a.inc_r32('eax')
                    a.shl_rax_imm8(3)
                    a.or_rax_imm8(TAG_BOOL)

                    a.mark(l_done_eq)
                else:
                    # Strict void: ordered comparisons on void are runtime errors.
                    vidv = self.new_label_id()
                    l_nvoid = f"cmp_nvoid_{vidv}"
                    l_isvoid = f"cmp_isvoid_{vidv}"
                    a.mov_r64_r64("rax", "r10")
                    a.and_rax_imm8(7)
                    a.cmp_rax_imm8(TAG_VOID)
                    a.jcc('e', l_isvoid)
                    a.mov_r64_r64("rax", "r11")
                    a.and_rax_imm8(7)
                    a.cmp_rax_imm8(TAG_VOID)
                    a.jcc('ne', l_nvoid)
                    a.mark(l_isvoid)
                    if hasattr(self, 'emit_dbg_line'):
                        try:
                            self.emit_dbg_line(e)
                        except Exception:
                            pass
                    self._emit_make_error_const(ERR_VOID_OP, f"Cannot apply '{e.op}' to void")
                    self._emit_auto_errprop()
                    a.jmp(l_done)
                    a.mark(l_nvoid)
                    if hasattr(self, 'emit_dbg_line'):
                        try:
                            self.emit_dbg_line(e)
                        except Exception:
                            pass
                    self._emit_make_error_const(ERR_VOID_OP, f"Cannot apply '{e.op}' to non-numeric values")
                    self._emit_auto_errprop()

                a.mark(l_done)
                return

            raise self.error(f"Unsupported binary op: {e.op}", e)

        # -------- arrays --------

        if isinstance(e, ml.ArrayLit):
            # IMPORTANT: array literals can contain nested array literals.
            # Many helper/builtin calls clobber volatile registers (including r11),
            # so we must preserve the base pointer of the *outer* array across
            # element evaluation.
            n = len(e.items)
            size = 8 + n * 8
            # allocate bytes via fn_alloc(size)
            a.mov_rcx_imm32(size)
            a.call('fn_alloc')

            # spill base pointer (rax) into expression-temp area
            base_off = self.alloc_expr_temps(8)
            a.mov_rsp_disp32_rax(base_off)

            # base pointer in r11 for header writes
            a.mov_r11_rax()

            # header: type/len
            # mov dword [r11], OBJ_ARRAY
            a.mov_membase_disp_imm32("r11", 0, OBJ_ARRAY, qword=False)
            # mov dword [r11+4], n
            a.mov_membase_disp_imm32("r11", 4, n, qword=False)

            # fill elements
            for i, it in enumerate(e.items):
                self.emit_expr(it)
                # restore outer base pointer into r11 (do NOT clobber rax)
                a.mov_r64_membase_disp("r11", "rsp", base_off)  # mov r11,[rsp+base_off]
                disp = 8 + i * 8
                # mov [r11+disp32], rax
                a.mov_membase_disp_r64("r11", disp, "rax")

            # return ptr in rax
            a.mov_rax_rsp_disp32(base_off)
            self.free_expr_temps(8)
            return

        if isinstance(e, ml.Index):
            lid = self.new_label_id()
            l_arr = f"idx_arr_{lid}"
            l_bytes = f"idx_bytes_{lid}"
            l_str = f"idx_str_{lid}"
            l_fail = f"idx_fail_{lid}"
            l_done = f"idx_done_{lid}"

            # eval target
            self.emit_expr(e.target)

            # Strict void: indexing void is a runtime error.
            vid = self.new_label_id()
            l_nvoid = f"idx_nvoid_{vid}"
            a.mov_r64_r64("r10", "rax")
            a.and_r64_imm("r10", 7)
            a.cmp_r64_imm("r10", TAG_VOID)
            a.jcc("ne", l_nvoid)
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(e)
                except Exception:
                    pass
            self._emit_make_error_const(ERR_VOID_OP, "Cannot index void")
            self._emit_auto_errprop()
            a.jmp(l_done)
            a.mark(l_nvoid)

            # spill target (rax) into expr temp so index eval can't clobber it
            base_off = self.alloc_expr_temps(8)
            # NOTE: Some nested emitters (notably inline expansion cleanup)
            # may temporarily restore expr_temp_top to an earlier checkpoint.
            # That can break LIFO freeing here and cause us to clear the *wrong*
            # slot (e.g. clobbering an outer binary-op spill). We compute the
            # expected top *from the returned offset* and pin expr_temp_top to
            # at least that value before/after emitting the index expression.
            try:
                need_top = int(base_off - int(getattr(self, 'expr_temp_base', 0) or 0) + 8)
            except Exception:
                need_top = None
            try:
                if isinstance(need_top, int):
                    cur_top0 = int(getattr(self, 'expr_temp_top', 0) or 0)
                    if cur_top0 < need_top:
                        self.expr_temp_top = need_top
            except Exception:
                pass
            a.mov_rsp_disp32_rax(base_off)

            # eval index
            self.emit_expr(e.index)

            # Pin expr_temp_top so freeing `base_off` cannot underflow into
            # outer allocations.
            try:
                if isinstance(need_top, int):
                    cur_top1 = int(getattr(self, 'expr_temp_top', 0) or 0)
                    if cur_top1 < need_top:
                        self.expr_temp_top = need_top
            except Exception:
                pass

            # Strict void: using void as index is a runtime error.
            vid2 = self.new_label_id()
            l_iok = f"idx_iok_{vid2}"
            a.mov_r64_r64("r10", "rax")
            a.and_r64_imm("r10", 7)
            a.cmp_r64_imm("r10", TAG_VOID)
            a.jcc("ne", l_iok)
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(e)
                except Exception:
                    pass
            self._emit_make_error_const(ERR_VOID_OP, "Cannot use void as index")
            self._emit_auto_errprop()
            # IMPORTANT: Do not call free_expr_temps() here.
            # Codegen is linear and will also emit the non-void path below,
            # which frees the same spill slot. Freeing in both branches causes
            # compile-time expr_temp underflow and corrupts outer allocations
            # (e.g. a[i] ^ b[i]). We only clear the spill slot at runtime.
            a.mov_membase_disp_imm32("rsp", base_off, enc_void(), qword=True)
            a.jmp(l_done)
            a.mark(l_iok)

            # rcx = decoded index
            a.mov_r64_r64("rcx", "rax")
            a.sar_r64_imm8("rcx", 3)

            # restore target -> r11
            a.mov_r64_membase_disp("r11", "rsp", base_off)

            # free temp (clobbers RAX only, safe here)
            self.free_expr_temps(8)

            # --- safety: target must be TAG_PTR and non-null ---
            a.mov_r64_r64("r10", "r11")
            a.and_r64_imm("r10", 7)
            a.cmp_r64_imm("r10", TAG_PTR)  # TAG_PTR == 0
            a.jcc("ne", l_fail)
            a.test_r64_r64("r11", "r11")
            a.jcc("e", l_fail)

            # dispatch by obj type
            a.mov_r32_membase_disp("edx", "r11", 0)  # type
            a.cmp_r32_imm("edx", OBJ_ARRAY)
            a.jcc('e', l_arr)
            a.cmp_r32_imm("edx", OBJ_STRING)
            a.jcc('e', l_str)
            a.cmp_r32_imm("edx", OBJ_BYTES)
            a.jcc('e', l_bytes)
            a.jmp(l_fail)

            # ---- array indexing ----
            a.mark(l_arr)
            a.mov_r32_membase_disp("edx", "r11", 4)  # len
            # support negative indices: if idx < 0 => idx += len
            l_a_ok = f"idx_a_ok_{lid}"
            a.cmp_r32_imm("ecx", 0)
            a.jcc('ge', l_a_ok)
            a.add_r32_r32("ecx", "edx")
            a.mark(l_a_ok)
            # bounds check after normalization
            a.cmp_r32_imm("ecx", 0)
            a.jcc('l', l_fail)
            a.cmp_r32_r32("ecx", "edx")
            a.jcc('ge', l_fail)
            a.mov_r64_mem_bis("rax", "r11", "rcx", 8, 8)
            a.jmp(l_done)

            # ---- bytes indexing -> int (0..255) ----
            a.mark(l_bytes)
            a.mov_r32_membase_disp("edx", "r11", 4)  # len
            # support negative indices: if idx < 0 => idx += len
            l_b_ok = f"idx_b_ok_{lid}"
            a.cmp_r32_imm("ecx", 0)
            a.jcc('ge', l_b_ok)
            a.add_r32_r32("ecx", "edx")
            a.mark(l_b_ok)
            # bounds check after normalization
            a.cmp_r32_imm("ecx", 0)
            a.jcc('l', l_fail)
            a.cmp_r32_r32("ecx", "edx")
            a.jcc('ge', l_fail)

            # addr = r11 + 8 + i
            a.mov_r64_r64("rax", "r11")
            a.add_r64_r64("rax", "rcx")
            a.add_rax_imm8(8)

            # eax = byte [rax]
            a.movzx_r32_membase_disp("eax", "rax", 0)
            # tag int
            a.shl_rax_imm8(3)
            a.or_rax_imm8(TAG_INT)
            a.jmp(l_done)
            # ---- string indexing -> 1-char string ----
            a.mark(l_str)
            a.mov_r32_membase_disp("edx", "r11", 4)  # len
            # support negative indices: if idx < 0 => idx += len
            l_s_ok = f"idx_s_ok_{lid}"
            a.cmp_r32_imm("ecx", 0)
            a.jcc('ge', l_s_ok)
            a.add_r32_r32("ecx", "edx")
            a.mark(l_s_ok)
            # bounds check after normalization
            a.cmp_r32_imm("ecx", 0)
            a.jcc('l', l_fail)
            a.cmp_r32_r32("ecx", "edx")
            a.jcc('ge', l_fail)

            a.mov_r64_r64("rax", "r11")
            a.add_r64_r64("rax", "rcx")
            a.add_rax_imm8(8)
            a.mov_r8_membase_disp("dl", "rax", 0)
            # Save the byte across the call (calls clobber RDX/DL). Use the outgoing-args area,
            # which is not part of the GC root slots.
            a.mov_membase_disp_r8("rsp", 0x20, "dl")

            a.mov_rcx_imm32(10)
            a.call('fn_alloc')

            a.mov_r11_rax()
            a.mov_membase_disp_imm32("r11", 0, OBJ_STRING, qword=False)
            a.mov_membase_disp_imm32("r11", 4, 1, qword=False)
            a.mov_r8_membase_disp("dl", "rsp", 0x20)
            a.mov_membase_disp_r8("r11", 8, "dl")
            a.mov_membase_disp_imm8("r11", 9, 0)
            a.mov_rax_r11()
            a.jmp(l_done)

            a.mark(l_fail)
            a.mov_rax_imm64(enc_void())
            a.mark(l_done)
            return

        # -------- builtin calls --------

        if isinstance(e, ml.Call):
            # Update debug line for this call expression so errors created in builtins
            # can report the exact callsite.
            if hasattr(self, 'emit_dbg_line'):
                try:
                    self.emit_dbg_line(e)
                except Exception:
                    pass

            def _has_global_prefix(base: str) -> bool:
                # Returns True if any known global symbol starts with "<base>."
                try:
                    pref = str(base) + "."
                except Exception:
                    return False
                for pool_name in ("user_functions", "extern_sigs", "struct_fields", "enum_id"):
                    pool = getattr(self, pool_name, None) or {}
                    try:
                        for k in pool.keys():
                            if isinstance(k, str) and k.startswith(pref):
                                return True
                    except Exception:
                        continue
                return False

            # Support qualified-name calls like fubar.a() and fubar.Point(...).
            # The frontend may encode these either as Var('fubar.a') or as a Member-chain
            # (Member(Var('fubar'), 'a')). We flatten Member-chains here.
            def _qname_exists(qn: str) -> bool:
                if not isinstance(qn, str) or not qn:
                    return False
                try:
                    if qn in (getattr(self, 'user_functions', {}) or {}):
                        return True
                    if qn in (getattr(self, 'extern_sigs', {}) or {}):
                        return True
                    if qn in (getattr(self, 'struct_fields', {}) or {}):
                        return True
                    if hasattr(self, 'resolve_binding') and callable(getattr(self, 'resolve_binding')):
                        return self.resolve_binding(qn) is not None
                except Exception:
                    return False
                return False

            def _qname_with_prefixes(qn: str) -> List[str]:
                # Try exact, then current function prefix, then current file package prefix.
                cands: List[str] = [qn]
                try:
                    qpref = str(getattr(self, 'current_qname_prefix', '') or '')
                except Exception:
                    qpref = ''
                try:
                    fpref = str(getattr(self, 'current_file_prefix', '') or '')
                except Exception:
                    fpref = ''
                if qpref and not qpref.endswith('.'):
                    qpref += '.'
                if fpref and not fpref.endswith('.'):
                    fpref += '.'
                if qpref and not qn.startswith(qpref):
                    cands.append(qpref + qn)
                if fpref and not qn.startswith(fpref):
                    cands.append(fpref + qn)
                return cands

            def _qname_of(expr: Any) -> Optional[str]:
                """Resolve compile-time qualified-name calls (Var or Member-chain).

                Returns a qualified name only when it can be resolved to a known
                callable/decl (function/extern/struct/const binding). This avoids
                misclassifying real runtime member calls as namespace calls when
                an identifier collides with an import alias.
                """
                if expr is None:
                    return None

                if isinstance(expr, ml.Var):
                    return self._qualify_identifier(str(expr.name), expr)

                if not (hasattr(ml, 'Member') and isinstance(expr, ml.Member)):
                    return None

                def _qname_parts(expr2: Any) -> Optional[List[str]]:
                    if isinstance(expr2, ml.Var):
                        nm2 = str(getattr(expr2, 'name', ''))
                        return nm2.split('.') if '.' in nm2 else [nm2]
                    if hasattr(ml, 'Member') and isinstance(expr2, ml.Member):
                        tgt2 = getattr(expr2, 'target', None)
                        if tgt2 is None:
                            tgt2 = getattr(expr2, 'obj', None)
                        base2 = _qname_parts(tgt2)
                        if base2 is None:
                            return None
                        nm2 = getattr(expr2, 'name', None)
                        if nm2 is None:
                            nm2 = getattr(expr2, 'field', None)
                        if nm2 is None:
                            return None
                        return base2 + [str(nm2)]
                    return None

                parts2 = _qname_parts(expr)
                if not parts2:
                    return None

                full = ".".join(parts2)
                full_m = self._apply_import_alias(full)

                # Binding/shadowing check on the left-most identifier.
                base0 = parts2[0]
                b0 = None
                if hasattr(self, 'resolve_binding') and callable(getattr(self, 'resolve_binding')):
                    try:
                        b0 = self.resolve_binding(base0)
                    except Exception:
                        b0 = None
                kind0 = getattr(b0, 'kind', None)
                base_localish = (b0 is not None) and (kind0 is not None) and (kind0 != 'global')

                # Static struct method reference: StructName.method -> hoisted static function
                struct_qn = ".".join(parts2[:-1])
                meth = parts2[-1]
                struct_qn_m = self._apply_import_alias(struct_qn)
                smap = getattr(self, 'struct_static_methods', {}) or {}
                for sq in _qname_with_prefixes(struct_qn_m):
                    md = smap.get(sq) or {}
                    fn_qn = md.get(meth)
                    if fn_qn:
                        return str(fn_qn)

                # If this Member-chain denotes a compile-time struct type ref (StructName.method),
                # allow it even if `StructName` is a visible *global* binding. But if it is shadowed
                # by a local/param, treat it as a runtime value.
                is_struct_type_ref = False
                try:
                    for sq in _qname_with_prefixes(struct_qn_m):
                        if sq in (getattr(self, 'struct_fields', {}) or {}):
                            if not base_localish:
                                is_struct_type_ref = True
                            break
                except Exception:
                    is_struct_type_ref = False

                # Import-alias base: treat as namespace unless shadowed by local/param.
                aliases0 = getattr(self, 'import_aliases', None) or {}
                if base0 in aliases0 and not base_localish:
                    for cand in _qname_with_prefixes(full_m):
                        if _qname_exists(cand):
                            return cand
                    return None

                # Struct type ref: only if it resolves.
                if is_struct_type_ref:
                    for cand in _qname_with_prefixes(full_m):
                        if _qname_exists(cand):
                            return cand
                    return None

                # Otherwise: if base is a visible runtime binding, keep it dynamic.
                if b0 is not None:
                    return None

                # Unbound base: treat as qualified only if it resolves.
                for cand in _qname_with_prefixes(full_m):
                    if _qname_exists(cand):
                        return cand

                return None

            callee_expr = getattr(e, 'callee', None)
            if callee_expr is None:
                callee_expr = getattr(e, 'func', None)

            # --- OOP-style struct methods: obj.method(args...)  (implicit `this`) ---
            # Compiled as dynamic dispatch on receiver.struct_id -> direct call of the hoisted method function.
            if isinstance(callee_expr, ml.Member) and _qname_of(callee_expr) is None:
                mname = getattr(callee_expr, 'name', None)
                if mname is None:
                    mname = getattr(callee_expr, 'field', None)
                mname = str(mname) if mname is not None else None

                tgt = getattr(callee_expr, 'target', None)
                if tgt is None:
                    tgt = getattr(callee_expr, 'obj', None)

                if mname and (getattr(self, 'struct_methods', {}) or {}):
                    args = list(getattr(e, 'args', []) or [])
                    total = 1 + len(args)  # receiver + explicit args

                    # Candidates: structs that implement this method with matching arity.
                    candidates = []
                    for s_qn, md in (getattr(self, 'struct_methods', {}) or {}).items():
                        fn_qn = (md or {}).get(mname)
                        if not fn_qn:
                            continue
                        fn_def = (getattr(self, 'user_functions', {}) or {}).get(fn_qn)
                        if fn_def is None:
                            continue
                        exp = len(getattr(fn_def, 'params', []) or [])
                        if exp != total:
                            continue
                        sid = (getattr(self, 'struct_id', {}) or {}).get(s_qn)
                        if sid is None:
                            continue
                        candidates.append((int(sid), str(fn_qn)))

                    if candidates:
                        a = self.asm
                        fid = self.new_label_id()
                        l_ok = f"mcall_ok_{fid}"
                        l_fail = f"mcall_fail_{fid}"
                        l_done = f"mcall_done_{fid}"

                        base = self.alloc_expr_temps(total * 8)

                        # Evaluate receiver + args into temp slots (left-to-right).
                        self.emit_expr(tgt)
                        a.mov_rsp_disp32_rax(base)
                        for i, aa in enumerate(args):
                            self.emit_expr(aa)
                            a.mov_rsp_disp32_rax(base + (i + 1) * 8)

                        # Marshal args (rcx, rdx, r8, r9, then stack at rsp+0x20).
                        if total >= 1:
                            a.mov_r64_membase_disp("rcx", "rsp", base + 0 * 8)
                        if total >= 2:
                            a.mov_r64_membase_disp("rdx", "rsp", base + 1 * 8)
                        if total >= 3:
                            a.mov_r64_membase_disp("r8", "rsp", base + 2 * 8)
                        if total >= 4:
                            a.mov_r64_membase_disp("r9", "rsp", base + 3 * 8)
                        if total > 4:
                            for i in range(4, total):
                                a.mov_r64_membase_disp("r10", "rsp", base + i * 8)
                                disp = 0x20 + (i - 4) * 8
                                a.mov_membase_disp_r64("rsp", disp, "r10")

                        # Load receiver into r11 and validate it's a struct; load struct_id into r10d.
                        a.mov_r64_membase_disp("r11", "rsp", base)
                        a.mov_r64_r64("r10", "r11")
                        a.and_r64_imm("r10", 7)
                        a.cmp_r64_imm("r10", TAG_PTR)
                        a.jcc("ne", l_fail)

                        a.mov_r32_membase_disp("r10d", "r11", 0)
                        a.cmp_r32_imm("r10d", OBJ_STRUCT)
                        a.jcc("ne", l_fail)

                        a.mov_r32_membase_disp("r10d", "r11", 8)  # struct_id

                        # Dispatch by struct_id.
                        for sid, fn_qn in candidates:
                            l_case = f"mcall_case_{fid}_{sid}"
                            a.cmp_r32_imm("r10d", sid)
                            a.jcc("e", l_case)
                        a.jmp(l_fail)

                        for sid, fn_qn in candidates:
                            l_case = f"mcall_case_{fid}_{sid}"
                            a.mark(l_case)
                            a.mov_r64_imm64("r10", enc_void())  # closure env (top-level methods)
                            a.call(f"fn_user_{fn_qn}")
                            a.jmp(l_done)

                        a.mark(l_fail)
                        self._emit_make_error_const(ERR_METHOD_NOT_FOUND,
                                                    f"No matching method '{mname}' for receiver")

                        a.mark(l_done)

                        # Automatic error propagation (unless suppressed by try()).
                        if int(getattr(self, '_errprop_suppression', 0) or 0) == 0:
                            lidp = self.new_label_id()
                            l_noerr = f"errprop_noerr_{lidp}"
                            # Check: TAG_PTR + OBJ_STRUCT + struct_id == ERROR_STRUCT_ID
                            a.mov_r64_r64("r10", "rax")
                            a.and_r64_imm("r10", 7)
                            a.cmp_r64_imm("r10", TAG_PTR)
                            a.jcc("ne", l_noerr)
                            a.mov_r32_membase_disp("r10d", "rax", 0)
                            a.cmp_r32_imm("r10d", OBJ_STRUCT)
                            a.jcc("ne", l_noerr)
                            a.mov_r32_membase_disp("r10d", "rax", 8)
                            a.cmp_r32_imm("r10d", ERROR_STRUCT_ID)
                            a.jcc("ne", l_noerr)

                            if bool(getattr(self, 'in_function', False)) and getattr(self, 'func_ret_label', None):
                                a.jmp(self.func_ret_label)
                            else:
                                a.mov_r64_r64("rcx", "rax")
                                a.call('fn_unhandled_error_exit')

                            a.mark(l_noerr)

                        # --- GC safety: clear temps + outgoing stack args ---
                        self.free_expr_temps(total * 8)

                        void_imm = enc_void()
                        if total > 4:
                            for i in range(4, total):
                                disp = 0x20 + (i - 4) * 8
                                a.mov_membase_disp_imm32("rsp", disp, void_imm, qword=True)

                        return

            callee_name = _qname_of(callee_expr) if callee_expr is not None else None
            if callee_name is not None:
                callee_name = self._apply_import_alias(str(callee_name))

            # --- Type-qualified helper calls for struct instance methods (no `this` usage) ---
            # Allow calling an instance method through the struct type name without passing a
            # receiver, *if* the method body never references `this`. Example:
            #   struct S
            #     function helper(x) return x+1 end function
            #     static function f(x) return S.helper(x) end function
            #   end struct
            # This is compiled by injecting a dummy receiver value as the implicit first arg.
            # We use `void` (not a null pointer) so that if a `this` access slips through,
            # runtime errors are safer than a null dereference.
            call_args = list(getattr(e, 'args', []) or [])

            def _fn_uses_this(fn_node) -> bool:
                # Conservative AST scan for Var('this') in the function body. Cached on node.
                try:
                    v = getattr(fn_node, '_ml_uses_this', None)
                    if v is not None:
                        return bool(v)
                except Exception:
                    pass

                ml = self.ml

                def _expr_has_this(x) -> bool:
                    if x is None:
                        return False
                    if isinstance(x, ml.Var):
                        return str(getattr(x, 'name', '')) == 'this'
                    if isinstance(x, (ml.Num, ml.Str, ml.Bool, getattr(ml, 'VoidLit', ()) )):
                        return False
                    if isinstance(x, ml.Unary):
                        return _expr_has_this(getattr(x, 'right', None))
                    if isinstance(x, ml.Bin):
                        return _expr_has_this(getattr(x, 'left', None)) or _expr_has_this(getattr(x, 'right', None))
                    if isinstance(x, ml.IsType):
                        return _expr_has_this(getattr(x, 'expr', None))
                    if isinstance(x, ml.Call):
                        if _expr_has_this(getattr(x, 'callee', None)):
                            return True
                        for aa in list(getattr(x, 'args', []) or []):
                            if _expr_has_this(aa):
                                return True
                        return False
                    if isinstance(x, ml.Index):
                        return _expr_has_this(getattr(x, 'target', None)) or _expr_has_this(getattr(x, 'index', None))
                    if hasattr(ml, 'Member') and isinstance(x, ml.Member):
                        return _expr_has_this(getattr(x, 'target', None))
                    if isinstance(x, ml.ArrayLit):
                        for it in list(getattr(x, 'items', []) or []):
                            if _expr_has_this(it):
                                return True
                        return False
                    # Unknown expression node: be conservative and assume it may use `this`.
                    return True

                def _stmt_has_this(st) -> bool:
                    if st is None:
                        return False
                    # Expressions inside statements
                    for attr in ('expr', 'cond', 'value', 'target', 'index', 'start', 'end', 'iterable'):
                        if hasattr(st, attr):
                            if _expr_has_this(getattr(st, attr, None)):
                                return True
                    # Assignments
                    if hasattr(ml, 'Assign') and isinstance(st, ml.Assign):
                        if _expr_has_this(getattr(st, 'target', None)) or _expr_has_this(getattr(st, 'value', None)):
                            return True
                    # If/While/For bodies
                    if isinstance(st, ml.If):
                        if _expr_has_this(getattr(st, 'cond', None)):
                            return True
                        for bb in list(getattr(st, 'then_body', []) or []):
                            if _stmt_has_this(bb):
                                return True
                        for _c, _b in list(getattr(st, 'elifs', []) or []):
                            if _expr_has_this(_c):
                                return True
                            for bb in list(_b or []):
                                if _stmt_has_this(bb):
                                    return True
                        for bb in list(getattr(st, 'else_body', []) or []):
                            if _stmt_has_this(bb):
                                return True
                        return False
                    if isinstance(st, ml.While) or isinstance(st, getattr(ml, 'DoWhile', ())):
                        if _expr_has_this(getattr(st, 'cond', None)):
                            return True
                        for bb in list(getattr(st, 'body', []) or []):
                            if _stmt_has_this(bb):
                                return True
                        return False
                    if isinstance(st, ml.For):
                        if _expr_has_this(getattr(st, 'start', None)) or _expr_has_this(getattr(st, 'end', None)):
                            return True
                        for bb in list(getattr(st, 'body', []) or []):
                            if _stmt_has_this(bb):
                                return True
                        return False
                    if isinstance(st, getattr(ml, 'ForEach', ())):
                        if _expr_has_this(getattr(st, 'iterable', None)):
                            return True
                        for bb in list(getattr(st, 'body', []) or []):
                            if _stmt_has_this(bb):
                                return True
                        return False
                    if isinstance(st, ml.Switch):
                        if _expr_has_this(getattr(st, 'expr', None)):
                            return True
                        for cs in list(getattr(st, 'cases', []) or []):
                            for vv in list(getattr(cs, 'values', []) or []):
                                if _expr_has_this(vv):
                                    return True
                            if _expr_has_this(getattr(cs, 'range_start', None)) or _expr_has_this(getattr(cs, 'range_end', None)):
                                return True
                            for bb in list(getattr(cs, 'body', []) or []):
                                if _stmt_has_this(bb):
                                    return True
                        for bb in list(getattr(st, 'default_body', []) or []):
                            if _stmt_has_this(bb):
                                return True
                        return False
                    # Nested function defs: scan them too (conservative).
                    if isinstance(st, ml.FunctionDef):
                        for bb in list(getattr(st, 'body', []) or []):
                            if _stmt_has_this(bb):
                                return True
                        return False
                    # Generic: walk common body-like attributes
                    for attr in ('body',):
                        if hasattr(st, attr):
                            for bb in list(getattr(st, attr, []) or []):
                                if _stmt_has_this(bb):
                                    return True
                    return False

                uses = False
                try:
                    for st in list(getattr(fn_node, 'body', []) or []):
                        if _stmt_has_this(st):
                            uses = True
                            break
                except Exception:
                    uses = True

                try:
                    setattr(fn_node, '_ml_uses_this', bool(uses))
                except Exception:
                    pass
                return bool(uses)

            def _is_instance_method_qname(fn_qn: str) -> bool:
                # Lazy build reverse map: function_qname -> (struct_qname, method_name)
                rev = getattr(self, '_struct_method_rev', None)
                if rev is None:
                    rev = {}
                    try:
                        for _s, _md in (getattr(self, 'struct_methods', {}) or {}).items():
                            for _m, _fn in (_md or {}).items():
                                rev[str(_fn)] = (str(_s), str(_m))
                    except Exception:
                        rev = {}
                    try:
                        setattr(self, '_struct_method_rev', rev)
                    except Exception:
                        pass
                return bool(fn_qn in (rev or {}))

            if callee_name is not None and _is_instance_method_qname(str(callee_name)):
                fn_def = (getattr(self, 'user_functions', {}) or {}).get(str(callee_name))
                if fn_def is not None:
                    expected = len(getattr(fn_def, 'params', []) or [])

                    # For type-qualified references to instance methods we can enforce arity at compile time:
                    # - `S.m(obj, ...)`  -> explicit receiver (expects `expected` args)
                    # - `S.m(...)`      -> implicit/dummy receiver (only allowed when method never uses `this`)
                    if len(call_args) == expected - 1:
                        if not _fn_uses_this(fn_def):
                            # Placeholder: emitted as `void` during argument materialization.
                            call_args = [None] + call_args
                        else:
                            raise self.error(
                                f"Cannot call instance method '{callee_name}' without receiver because it uses 'this'. "
                                f"Call it on an instance (obj.method(...)) or pass the receiver explicitly "
                                f"({callee_name}(... with receiver as first arg)) or make it static.",
                                e,
                            )
                    elif len(call_args) != expected:
                        exp_implicit = expected - 1 if expected > 0 else 0
                        raise self.error(
                            f"Method {callee_name} expects either {exp_implicit} args (implicit receiver) "
                            f"or {expected} args (explicit receiver), got {len(call_args)}",
                            e,
                        )

            # Native-only heap debug builtins (no args):
            #   heap_bytes_committed() = heap_end - heap_base
            #   heap_bytes_reserved()  = heap_reserve_end - heap_base
            if callee_name in ('heap_bytes_committed', 'heap_bytes_reserved') and len(e.args) == 0:
                if callee_name == 'heap_bytes_committed':
                    a.mov_rax_rip_qword('heap_end')
                else:
                    a.mov_rax_rip_qword('heap_reserve_end')
                a.mov_rdx_rip_qword('heap_base')
                a.sub_r64_r64('rax', 'rdx')  # bytes
                a.shl_r64_imm8('rax', 3)  # tag
                a.or_rax_imm8(TAG_INT)
                return

            # Builtin input() / input(prompt)
            if callee_name == 'input':
                if len(e.args) == 1:
                    # prompt: only supports string objects for now
                    self.emit_expr(e.args[0])
                    # tag check: r10 = rax & 7
                    a.mov_r10_rax()
                    a.and_r64_imm("r10", 7)
                    lbl_prompt_done = f"in_prompt_done_{a.pos}"
                    # if tag != PTR -> skip
                    a.cmp_r64_imm("r10", 0)
                    a.jcc('ne', lbl_prompt_done)
                    # if type != OBJ_STRING -> skip
                    a.mov_r32_membase_disp("edx", "rax", 0)  # mov edx,[rax]
                    a.cmp_r32_imm("edx", OBJ_STRING)
                    a.jcc('ne', lbl_prompt_done)
                    # r8d=len, rdx=ptr
                    a.mov_r32_membase_disp("r8d", "rax", 4)  # mov r8d,[rax+4]
                    a.lea_r64_membase_disp("rdx", "rax", 8)  # lea rdx,[rax+8]
                    self.emit_writefile_ptr_len()
                    a.mark(lbl_prompt_done)
                    a.call('fn_input')
                    return
                if len(e.args) == 0:
                    a.call('fn_input')
                    return
                raise self.error('input() nimmt 0 oder 1 Argument', e)

            # Builtin len(x)
            if callee_name == 'len' and len(e.args) == 1:
                self.emit_expr(e.args[0])

                # Strict-void: len(void) must raise an error, not silently return 0.
                lid = self.new_label_id()
                l_ok = f"len_ok_{lid}"
                l_done = f"len_done_{lid}"
                a.mov_r64_r64("r10", "rax")
                a.and_r64_imm("r10", 7)
                a.cmp_r64_imm("r10", TAG_VOID)
                a.jcc('ne', l_ok)
                self._emit_make_error_const(ERR_VOID_OP, "Cannot apply 'len' to void")
                self._emit_auto_errprop()
                a.jmp(l_done)

                a.mark(l_ok)
                a.mov_r64_r64("rcx", "rax")  # arg
                a.call('fn_builtin_len')

                a.mark(l_done)

                return

            # Builtin decode(bytes[, encoding]) -> string
            if callee_name == 'decode':
                if len(e.args) not in (1, 2):
                    raise self.error('decode() expects 1 or 2 arguments', e)

                nargs = len(call_args)
                tmp_off = self.alloc_expr_temps(16 if nargs == 2 else 8)

                # eval bytes arg
                self.emit_expr(e.args[0])
                a.mov_rsp_disp32_rax(tmp_off)

                # eval encoding arg (optional)
                if nargs == 2:
                    self.emit_expr(e.args[1])
                    a.mov_rsp_disp32_rax(tmp_off + 8)

                lid = self.new_label_id()
                l_fail = f'decode_fail_{lid}'
                l_done = f'decode_done_{lid}'

                # If encoding provided: must be a string (content currently ignored)
                if nargs == 2:
                    a.mov_r64_membase_disp('rax', 'rsp', tmp_off + 8)
                    a.mov_r64_r64('r10', 'rax')
                    a.and_r64_imm('r10', 7)
                    a.cmp_r64_imm('r10', TAG_PTR)
                    a.jcc('ne', l_fail)
                    a.mov_r32_membase_disp('edx', 'rax', 0)
                    a.cmp_r32_imm('edx', OBJ_STRING)
                    a.jcc('ne', l_fail)

                # call fn_decode(bytes)
                a.mov_r64_membase_disp('rax', 'rsp', tmp_off)
                a.mov_r64_r64('rcx', 'rax')
                a.call('fn_decode')
                a.jmp(l_done)

                a.mark(l_fail)
                a.mov_rax_imm64(enc_void())

                a.mark(l_done)
                self.free_expr_temps(16 if nargs == 2 else 8)
                return

            # Builtin hex(bytes) -> string
            if callee_name == 'hex' and len(e.args) == 1:
                self.emit_expr(e.args[0])
                a.mov_r64_r64('rcx', 'rax')
                a.call('fn_hex')
                return

            # Builtin fromHex(string) -> bytes
            if callee_name == 'fromHex' and len(e.args) == 1:
                self.emit_expr(e.args[0])
                a.mov_r64_r64('rcx', 'rax')
                a.call('fn_fromHex')
                return

            # Builtin slice(bytes, off, len) -> bytes (copy)
            if callee_name == 'slice':
                if len(e.args) != 3:
                    raise self.error('slice() expects exactly 3 arguments', e)

                tmp_off = self.alloc_expr_temps(24)

                # eval args left-to-right and spill
                self.emit_expr(e.args[0])
                a.mov_rsp_disp32_rax(tmp_off)
                self.emit_expr(e.args[1])
                a.mov_rsp_disp32_rax(tmp_off + 8)
                self.emit_expr(e.args[2])
                a.mov_rsp_disp32_rax(tmp_off + 16)

                # load into ABI regs
                a.mov_r64_membase_disp('rcx', 'rsp', tmp_off)
                a.mov_r64_membase_disp('rdx', 'rsp', tmp_off + 8)
                a.mov_r64_membase_disp('r8', 'rsp', tmp_off + 16)

                a.call('fn_slice')

                self.free_expr_temps(24)
                return

            # Builtin bytes(...) / byteBuffer(...)
            #
            # Interpreter supports: bytes(), bytes(size[, fill]), bytes(string), bytes(bytes).
            # Native backend historically only supported bytes(size[, fill]); this extends it to
            # bytes() / bytes(string) / bytes(bytes) as well (UTF-8 payload copy).
            if callee_name in ('bytes', 'byteBuffer'):
                nargs = len(e.args)
                if nargs > 2:
                    raise self.error("bytes()/byteBuffer() expects 0, 1 or 2 arguments", e)

                # bytes() -> empty buffer
                if nargs == 0:
                    a.xor_r32_r32("ecx", "ecx")
                    a.xor_r32_r32("edx", "edx")
                    a.call('fn_bytes_alloc')
                    return

                # bytes(size, fill) -> filled buffer
                if nargs == 2:
                    tmp_off = self.alloc_expr_temps(16)

                    # eval size
                    self.emit_expr(e.args[0])
                    a.mov_rsp_disp32_rax(tmp_off)

                    # eval fill
                    self.emit_expr(e.args[1])
                    a.mov_rsp_disp32_rax(tmp_off + 8)

                    lid = self.new_label_id()
                    l_fail = f"bytes_fail_{lid}"
                    l_done = f"bytes_done_{lid}"

                    # load + validate size (tagged int >= 0, fits i32)
                    a.mov_r64_membase_disp("rax", "rsp", tmp_off)
                    a.mov_r64_r64("r10", "rax")
                    a.and_r64_imm("r10", 7)
                    a.cmp_r64_imm("r10", TAG_INT)
                    a.jcc("ne", l_fail)
                    a.sar_r64_imm8("rax", 3)  # decoded size
                    a.cmp_r64_imm("rax", 0)
                    a.jcc("l", l_fail)
                    a.cmp_r64_imm("rax", 0x7FFFFFFF)
                    a.jcc("g", l_fail)
                    a.mov_r32_r32("ecx", "eax")  # len u32

                    # validate fill (tagged int 0..255)
                    a.mov_r64_membase_disp("rax", "rsp", tmp_off + 8)
                    a.mov_r64_r64("r10", "rax")
                    a.and_r64_imm("r10", 7)
                    a.cmp_r64_imm("r10", TAG_INT)
                    a.jcc("ne", l_fail)
                    a.sar_r64_imm8("rax", 3)  # decoded fill
                    a.cmp_r64_imm("rax", 0)
                    a.jcc("l", l_fail)
                    a.cmp_r64_imm("rax", 255)
                    a.jcc("g", l_fail)
                    a.mov_r32_r32("edx", "eax")

                    a.call('fn_bytes_alloc')
                    a.jmp(l_done)

                    a.mark(l_fail)
                    a.mov_rax_imm64(enc_void())

                    a.mark(l_done)
                    self.free_expr_temps(16)
                    return

                # bytes(x) where x is: size(int) | string | bytes
                tmp_off = self.alloc_expr_temps(16)  # [0]=arg, [8]=dest (for copies)

                self.emit_expr(e.args[0])
                a.mov_rsp_disp32_rax(tmp_off)

                lid = self.new_label_id()
                l_fail = f"bytes1_fail_{lid}"
                l_done = f"bytes1_done_{lid}"
                l_int = f"bytes1_int_{lid}"
                l_ptr = f"bytes1_ptr_{lid}"
                l_str = f"bytes1_str_{lid}"
                l_bcopy = f"bytes1_bcopy_{lid}"
                l_arr = f"bytes1_arr_{lid}"

                # rax = arg0
                a.mov_r64_membase_disp("rax", "rsp", tmp_off)
                a.mov_r64_r64("r10", "rax")
                a.and_r64_imm("r10", 7)

                # int? -> bytes(size)
                a.cmp_r64_imm("r10", TAG_INT)
                a.jcc("e", l_int)
                # ptr? -> string/bytes
                a.cmp_r64_imm("r10", TAG_PTR)
                a.jcc("e", l_ptr)
                a.jmp(l_fail)

                a.mark(l_int)
                a.sar_r64_imm8("rax", 3)  # decoded size
                a.cmp_r64_imm("rax", 0)
                a.jcc("l", l_fail)
                a.cmp_r64_imm("rax", 0x7FFFFFFF)
                a.jcc("g", l_fail)
                a.mov_r32_r32("ecx", "eax")  # len u32
                a.xor_r32_r32("edx", "edx")  # fill=0
                a.call('fn_bytes_alloc')
                a.jmp(l_done)

                a.mark(l_ptr)
                # dispatch on obj type
                a.mov_r32_membase_disp("edx", "rax", 0)
                a.cmp_r32_imm("edx", OBJ_STRING)
                a.jcc("e", l_str)
                a.cmp_r32_imm("edx", OBJ_BYTES)
                a.jcc("e", l_bcopy)
                a.cmp_r32_imm("edx", OBJ_ARRAY)
                a.jcc("e", l_arr)
                a.jmp(l_fail)

                a.mark(l_str)
                # len = [str+4]
                a.mov_r32_membase_disp("ecx", "rax", 4)
                a.xor_r32_r32("edx", "edx")
                a.call('fn_bytes_alloc')  # rax = dest bytes
                a.mov_membase_disp_r64("rsp", tmp_off + 8, "rax")  # stash dest

                # src -> r11
                a.mov_r64_membase_disp("r11", "rsp", tmp_off)
                # len -> ecx
                a.mov_r32_membase_disp("ecx", "r11", 4)
                # dest -> r10
                a.mov_r64_membase_disp("r10", "rsp", tmp_off + 8)

                a.push_reg("rsi")
                a.push_reg("rdi")
                a.lea_r64_membase_disp("rsi", "r11", 8)
                a.lea_r64_membase_disp("rdi", "r10", 8)
                a.rep_movsb()
                a.pop_reg("rdi")
                a.pop_reg("rsi")

                a.mov_r64_membase_disp("rax", "rsp", tmp_off + 8)
                a.jmp(l_done)

                a.mark(l_arr)
                # bytes(array<int>) -> copy elements to bytes payload.
                # - requires every element to be a TAG_INT in range 0..255
                # - otherwise returns void (keeps legacy behavior: "soft" failure)

                # len = [arr+4]
                a.mov_r32_membase_disp("ecx", "rax", 4)
                a.xor_r32_r32("edx", "edx")
                a.call('fn_bytes_alloc')  # rax = dest bytes
                a.mov_membase_disp_r64("rsp", tmp_off + 8, "rax")

                # src -> r11, dest -> r10
                a.mov_r64_membase_disp("r11", "rsp", tmp_off)
                a.mov_r64_membase_disp("r10", "rsp", tmp_off + 8)

                # r8d = len, r9d = i
                a.mov_r32_membase_disp("r8d", "r11", 4)
                a.xor_r32_r32("r9d", "r9d")

                l_loop_arr = f"bytes1_arr_loop_{lid}"
                l_done_arr = f"bytes1_arr_done_{lid}"
                l_fail_arr = f"bytes1_arr_fail_{lid}"

                a.mark(l_loop_arr)
                a.cmp_r32_r32("r9d", "r8d")
                a.jcc('ge', l_done_arr)

                # load element: rax = [src + 8 + i*8]
                a.mov_r64_mem_bis("rax", "r11", "r9", 8, 8)

                # element must be TAG_INT
                a.mov_r64_r64("rdx", "rax")
                a.and_r64_imm("rdx", 7)
                a.cmp_r64_imm("rdx", TAG_INT)
                a.jcc('ne', l_fail_arr)

                # decode and range check 0..255
                a.sar_r64_imm8("rax", 3)
                a.cmp_r64_imm("rax", 0)
                a.jcc('l', l_fail_arr)
                a.cmp_r64_imm("rax", 255)
                a.jcc('g', l_fail_arr)

                # store low byte to dest payload: [dest + 8 + i]
                a.lea_r64_mem_bis("rdx", "r10", "r9", 1, 8)
                a.mov_membase_disp_r8("rdx", 0, "al")

                a.inc_r32("r9d")
                a.jmp(l_loop_arr)

                a.mark(l_fail_arr)
                a.mov_rax_imm64(enc_void())
                a.jmp(l_done)

                a.mark(l_done_arr)
                a.mov_r64_membase_disp("rax", "rsp", tmp_off + 8)
                a.jmp(l_done)

                a.mark(l_bcopy)
                # len = [bytes+4]
                a.mov_r32_membase_disp("ecx", "rax", 4)
                a.xor_r32_r32("edx", "edx")
                a.call('fn_bytes_alloc')  # rax = dest bytes
                a.mov_membase_disp_r64("rsp", tmp_off + 8, "rax")  # stash dest

                # src -> r11
                a.mov_r64_membase_disp("r11", "rsp", tmp_off)
                # len -> ecx
                a.mov_r32_membase_disp("ecx", "r11", 4)
                # dest -> r10
                a.mov_r64_membase_disp("r10", "rsp", tmp_off + 8)

                a.push_reg("rsi")
                a.push_reg("rdi")
                a.lea_r64_membase_disp("rsi", "r11", 8)
                a.lea_r64_membase_disp("rdi", "r10", 8)
                a.rep_movsb()
                a.pop_reg("rdi")
                a.pop_reg("rsi")

                a.mov_r64_membase_disp("rax", "rsp", tmp_off + 8)
                a.jmp(l_done)

                a.mark(l_fail)
                a.mov_rax_imm64(enc_void())

                a.mark(l_done)
                self.free_expr_temps(16)
                return

            # Builtin decodeZ(bytes) -> string (scan until NUL or end)
            if callee_name == 'decodeZ' and len(e.args) == 1:
                tmp_off = self.alloc_expr_temps(16)

                self.emit_expr(e.args[0])  # -> RAX
                lid = self.new_label_id()
                l_fail = f"decodeZ_fail_{lid}"
                l_scan = f"decodeZ_scan_{lid}"
                l_done = f"decodeZ_done_{lid}"
                l_after = f"decodeZ_after_{lid}"

                # type check: bytes
                a.mov_r64_r64("r10", "rax")
                a.and_r64_imm("r10", 7)
                a.cmp_r64_imm("r10", TAG_PTR)
                a.jcc("ne", l_fail)
                a.mov_r32_membase_disp("edx", "rax", 0)
                a.cmp_r32_imm("edx", OBJ_BYTES)
                a.jcc("ne", l_fail)

                # stash bytes obj (GC root)
                a.mov_membase_disp_r64("rsp", tmp_off, "rax")

                # r9d = cap bytes, r10 = payload
                a.mov_r32_membase_disp("r9d", "rax", 4)
                a.lea_r64_membase_disp("r10", "rax", 8)

                # r8d = len (scan)
                a.xor_r32_r32("r8d", "r8d")
                a.mark(l_scan)
                a.cmp_r32_r32("r8d", "r9d")
                a.jcc("ge", l_done)
                a.mov_r64_r64("r11", "r10")
                a.add_r64_r64("r11", "r8")
                a.movzx_r32_membase_disp("eax", "r11", 0)
                a.cmp_r8_imm8("al", 0)
                a.je(l_done)
                a.inc_r32("r8d")
                a.jmp(l_scan)

                a.mark(l_done)

                # stash len as TAG_INT
                a.mov_r64_r64("r11", "r8")
                a.shl_r64_imm8("r11", 3)
                a.or_r64_imm8("r11", TAG_INT)
                a.mov_membase_disp_r64("rsp", tmp_off + 8, "r11")

                # alloc size = 8 + len + 1
                a.mov_r32_r32("ecx", "r8d")
                a.add_r32_imm("ecx", 9)
                a.call("fn_alloc")

                a.mov_r11_rax()
                a.mov_membase_disp_imm32("r11", 0, OBJ_STRING, qword=False)

                # reload len -> r8d
                a.mov_r64_membase_disp("r8", "rsp", tmp_off + 8)
                a.sar_r64_imm8("r8", 3)
                a.mov_r32_r32("r8d", "r8d")
                a.mov_membase_disp_r32("r11", 4, "r8d")

                # reload bytes obj -> r10
                a.mov_r64_membase_disp("r10", "rsp", tmp_off)

                # copy payload[0:len] into string
                a.push_reg("rsi")
                a.push_reg("rdi")
                a.lea_r64_membase_disp("rsi", "r10", 8)
                a.lea_r64_membase_disp("rdi", "r11", 8)
                a.mov_r32_r32("ecx", "r8d")
                a.rep_movsb()
                a.pop_reg("rdi")
                a.pop_reg("rsi")

                # NUL at [base+8+len]
                a.mov_r64_r64("rax", "r11")
                a.add_r64_r64("rax", "r8")
                a.add_rax_imm8(8)
                a.mov_membase_disp_imm8("rax", 0, 0)

                a.mov_rax_r11()
                a.jmp(l_after)

                a.mark(l_fail)
                a.mov_rax_imm64(enc_void())

                a.mark(l_after)
                self.free_expr_temps(16)
                return

            # Builtin decode16Z(bytes) -> string (UTF-16LE, scan until 0x0000 or end)
            if callee_name == 'decode16Z' and len(e.args) == 1:
                tmp_off = self.alloc_expr_temps(32)  # bytes_obj, wlen, out_len, out_base

                self.emit_expr(e.args[0])  # -> RAX
                lid = self.new_label_id()
                l_fail = f"decode16Z_fail_{lid}"
                l_scan = f"decode16Z_scan_{lid}"
                l_done = f"decode16Z_done_{lid}"
                l_after = f"decode16Z_after_{lid}"

                # type check: bytes
                a.mov_r64_r64("r10", "rax")
                a.and_r64_imm("r10", 7)
                a.cmp_r64_imm("r10", TAG_PTR)
                a.jcc("ne", l_fail)
                a.mov_r32_membase_disp("edx", "rax", 0)
                a.cmp_r32_imm("edx", OBJ_BYTES)
                a.jcc("ne", l_fail)

                # stash bytes obj (GC root)
                a.mov_membase_disp_r64("rsp", tmp_off, "rax")

                # r9d = cap bytes; wcap = cap/2
                a.mov_r32_membase_disp("r9d", "rax", 4)
                a.shr_r64_imm8("r9", 1)

                # r10 = payload
                a.lea_r64_membase_disp("r10", "rax", 8)

                # r8d = wlen (scan)
                a.xor_r32_r32("r8d", "r8d")
                a.mark(l_scan)
                a.cmp_r32_r32("r8d", "r9d")
                a.jcc("ge", l_done)

                # ptr = payload + r8*2
                a.lea_r64_mem_bis("r11", "r10", "r8", 2, 0)
                a.movzx_r32_membase_disp("eax", "r11", 0)
                a.cmp_r8_imm8("al", 0)
                a.jcc("ne", f"decode16Z_cont_{lid}")

                a.movzx_r32_membase_disp("edx", "r11", 1)
                a.cmp_r8_imm8("dl", 0)
                a.je(l_done)

                a.mark(f"decode16Z_cont_{lid}")
                a.inc_r32("r8d")
                a.jmp(l_scan)

                a.mark(l_done)

                # stash wlen as TAG_INT
                a.mov_r64_r64("r11", "r8")
                a.shl_r64_imm8("r11", 3)
                a.or_r64_imm8("r11", TAG_INT)
                a.mov_membase_disp_r64("rsp", tmp_off + 8, "r11")

                # Query required UTF-8 bytes: WideCharToMultiByte(CP_UTF8, 0, src, wlen, NULL, 0, NULL, NULL)
                a.mov_rcx_imm32(65001)
                a.xor_r32_r32("edx", "edx")
                a.mov_r64_membase_disp("r8", "rsp", tmp_off)
                a.lea_r64_membase_disp("r8", "r8", 8)
                a.mov_r64_membase_disp("r9", "rsp", tmp_off + 8)
                a.sar_r64_imm8("r9", 3)
                a.mov_r32_r32("r9d", "r9d")
                a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)
                a.mov_membase_disp_imm32("rsp", 0x28, 0, qword=True)
                a.mov_membase_disp_imm32("rsp", 0x30, 0, qword=True)
                a.mov_membase_disp_imm32("rsp", 0x38, 0, qword=True)
                a.mov_rax_rip_qword("iat_WideCharToMultiByte")
                a.call_rax()

                a.cmp_rax_imm8(0)
                a.je(l_fail)

                # stash out_len as TAG_INT
                a.mov_r64_r64("r10", "rax")
                a.shl_r64_imm8("r10", 3)
                a.or_r64_imm8("r10", TAG_INT)
                a.mov_membase_disp_r64("rsp", tmp_off + 16, "r10")

                # alloc size = 8 + out_len + 1
                a.mov_r32_r32("ecx", "eax")
                a.add_r32_imm("ecx", 9)
                a.call("fn_alloc")

                a.mov_r11_rax()
                a.mov_membase_disp_imm32("r11", 0, OBJ_STRING, qword=False)

                # reload out_len -> r10d
                a.mov_r64_membase_disp("r10", "rsp", tmp_off + 16)
                a.sar_r64_imm8("r10", 3)
                a.mov_r32_r32("r10d", "r10d")
                a.mov_membase_disp_r32("r11", 4, "r10d")

                # preserve base across API call (GC root)
                a.mov_membase_disp_r64("rsp", tmp_off + 24, "r11")

                # Convert into payload: WideCharToMultiByte(CP_UTF8, 0, src, wlen, dst, out_len, NULL, NULL)
                a.mov_rcx_imm32(65001)
                a.xor_r32_r32("edx", "edx")
                a.mov_r64_membase_disp("r8", "rsp", tmp_off)
                a.lea_r64_membase_disp("r8", "r8", 8)
                a.mov_r64_membase_disp("r9", "rsp", tmp_off + 8)
                a.sar_r64_imm8("r9", 3)
                a.mov_r32_r32("r9d", "r9d")

                a.mov_r64_membase_disp("r11", "rsp", tmp_off + 24)
                a.lea_r64_membase_disp("rax", "r11", 8)
                a.mov_membase_disp_r64("rsp", 0x20, "rax")
                a.mov_r64_membase_disp("rax", "rsp", tmp_off + 16)
                a.sar_r64_imm8("rax", 3)
                a.mov_membase_disp_r64("rsp", 0x28, "rax")
                a.mov_membase_disp_imm32("rsp", 0x30, 0, qword=True)
                a.mov_membase_disp_imm32("rsp", 0x38, 0, qword=True)
                a.mov_rax_rip_qword("iat_WideCharToMultiByte")
                a.call_rax()

                a.cmp_rax_imm8(0)
                a.je(l_fail)

                # NUL at [base+8+out_len]
                a.mov_r64_membase_disp("r11", "rsp", tmp_off + 24)
                a.mov_r64_membase_disp("r10", "rsp", tmp_off + 16)
                a.sar_r64_imm8("r10", 3)
                a.mov_r64_r64("rax", "r11")
                a.add_r64_r64("rax", "r10")
                a.add_rax_imm8(8)
                a.mov_membase_disp_imm8("rax", 0, 0)

                a.mov_rax_r11()
                a.jmp(l_after)

                a.mark(l_fail)
                a.mov_rax_imm64(enc_void())

                a.mark(l_after)
                self.free_expr_temps(32)
                return

            # Special form: try(expr) suppresses automatic error propagation for calls inside expr
            if callee_name == 'try' and len(e.args) == 1:
                old_sup = int(getattr(self, '_errprop_suppression', 0) or 0)
                setattr(self, '_errprop_suppression', old_sup + 1)
                self.emit_expr(e.args[0])
                setattr(self, '_errprop_suppression', old_sup)
                return

            # Builtin toNumber(x)
            if callee_name == 'toNumber' and len(e.args) == 1:
                self.emit_expr(e.args[0])
                a.mov_r64_r64("rcx", "rax")  # mov rcx,rax
                a.call('fn_toNumber')
                return

            # Builtin typeof(x)
            if callee_name == 'typeof' and len(e.args) == 1:
                arg = e.args[0]
                arg_name = _qname_of(arg)
                if arg_name is not None:
                    arg_name = self._apply_import_alias(str(arg_name))
                # Special case: typeof(<struct_name>) should be "struct".
                if arg_name is not None and arg_name in self.struct_fields:
                    a.lea_rax_rip('obj_type_struct')
                    return
                # Special case: typeof(<enum_name>) or typeof(<enum_name.variant>) should be "enum".
                if arg_name is not None:
                    if hasattr(self, "enum_id") and arg_name in getattr(self, "enum_id", {}):
                        a.lea_rax_rip('obj_type_enum')
                        return
                    if "." in arg_name and hasattr(self, "enum_variants"):
                        base, var = self._apply_import_alias(arg_name).rsplit(".", 1)
                        if base in getattr(self, "enum_id", {}) and var in getattr(self, "enum_variants", {}).get(base,
                                                                                                                  []):
                            a.lea_rax_rip('obj_type_enum')
                            return

                self.emit_expr(arg)
                a.mov_r64_r64("rcx", "rax")  # mov rcx,rax
                a.call('fn_typeof')
                return

            # Builtin typeName(x)
            if callee_name == 'typeName' and len(e.args) == 1:
                arg = e.args[0]
                arg_name = _qname_of(arg)
                if arg_name is not None:
                    arg_name = self._apply_import_alias(str(arg_name))

                # Special case: typeName(<struct_name>) -> "<struct_name>".
                if arg_name is not None and arg_name in self.struct_fields:
                    lbl = None
                    try:
                        lbl = getattr(self, 'typename_struct_by_qname', {}).get(arg_name)
                    except Exception:
                        lbl = None
                    if isinstance(lbl, str) and lbl:
                        a.lea_rax_rip(lbl)
                    else:
                        # fallback
                        a.lea_rax_rip('obj_type_struct')
                    return

                # Special case: typeName(<enum_name>) or typeName(<enum_name.variant>) -> "<enum_name>".
                if arg_name is not None:
                    try:
                        if hasattr(self, 'enum_id') and arg_name in getattr(self, 'enum_id', {}):
                            lbl = getattr(self, 'typename_enum_by_qname', {}).get(arg_name)
                            if isinstance(lbl, str) and lbl:
                                a.lea_rax_rip(lbl)
                            else:
                                a.lea_rax_rip('obj_type_enum')
                            return

                        if "." in arg_name and hasattr(self, 'enum_variants'):
                            base, var = arg_name.rsplit(".", 1)
                            base = self._apply_import_alias(base)
                            if base in getattr(self, 'enum_id', {}) and var in getattr(self, 'enum_variants', {}).get(base, []):
                                lbl = getattr(self, 'typename_enum_by_qname', {}).get(base)
                                if isinstance(lbl, str) and lbl:
                                    a.lea_rax_rip(lbl)
                                else:
                                    a.lea_rax_rip('obj_type_enum')
                                return
                    except Exception:
                        pass

                # General case: evaluate expression and dispatch in runtime helper.
                self.emit_expr(arg)
                a.mov_r64_r64('rcx', 'rax')
                a.call('fn_typeName')
                return

            # Builtin heap_count()
            if callee_name == 'heap_count' and len(e.args) == 0:
                a.call('fn_heap_count')
                return

            # Builtin heap_bytes_used()
            if callee_name == 'heap_bytes_used' and len(e.args) == 0:
                a.call('fn_heap_bytes_used')
                return

            # Builtin heap_free_bytes()
            if callee_name == 'heap_free_bytes' and len(e.args) == 0:
                a.call('fn_heap_free_bytes')
                return

            # Builtin heap_free_blocks()
            if callee_name == 'heap_free_blocks' and len(e.args) == 0:
                a.call('fn_heap_free_blocks')
                return

            # Builtin gc_collect()
            if callee_name == 'gc_collect' and len(e.args) == 0:
                a.call('fn_gc_collect')
                a.mov_rax_imm64(enc_void())
                return

            # Builtin heap_bytes_committed()
            if callee_name == "heap_bytes_committed":
                a.call('fn_heap_bytes_committed')
                return

            # Builtin heap_bytes_reserved()
            if callee_name == "heap_bytes_reserved":
                a.call('fn_heap_bytes_reserved')
                return

            # Builtin callStats() -> array<callStat> (enabled only with --profile-calls)
            if callee_name == 'callStats' and len(e.args) == 0:
                if bool(getattr(self, 'call_profile', False)):
                    a.call('fn_callStats')
                    return

            # Inline function expansion (direct calls only).
            if callee_name is not None and callee_name in (getattr(self, 'inline_functions', {}) or {}):
                b = None
                try:
                    b = self.resolve_binding(callee_name)
                except Exception:
                    b = None
                # Only inline if the identifier refers to the global function binding.
                if b is None or getattr(b, 'kind', None) == 'global':
                    self._emit_inline_call(e, callee_name)

                    # Automatic error propagation for inlined calls (unless suppressed by try()).
                    # Normally this is emitted after a real CALL; inlining removes that site.
                    if int(getattr(self, '_errprop_suppression', 0) or 0) == 0:
                        lidp = self.new_label_id()
                        l_noerr = f"errprop_noerr_{lidp}"
                        # Check: TAG_PTR + OBJ_STRUCT + struct_id == ERROR_STRUCT_ID
                        a.mov_r64_r64("r10", "rax")
                        a.and_r64_imm("r10", 7)
                        a.cmp_r64_imm("r10", TAG_PTR)
                        a.jcc("ne", l_noerr)
                        a.mov_r32_membase_disp("r10d", "rax", 0)
                        a.cmp_r32_imm("r10d", OBJ_STRUCT)
                        a.jcc("ne", l_noerr)
                        a.mov_r32_membase_disp("r10d", "rax", 8)
                        a.cmp_r32_imm("r10d", ERROR_STRUCT_ID)
                        a.jcc("ne", l_noerr)

                        # Is error: propagate to caller (function return) or abort at top-level.
                        if bool(getattr(self, 'in_function', False)) and getattr(self, 'func_ret_label', None):
                            a.jmp(self.func_ret_label)
                        else:
                            a.mov_r64_r64("rcx", "rax")
                            a.call('fn_unhandled_error_exit')

                        a.mark(l_noerr)

                    return

            # Extern calls are handled via stub-only OBJ_BUILTIN values.
            # Extern identifiers are hoisted as global bindings and initialized to
            # OBJ_BUILTIN stubs in CodegenStmt.

            # Struct constructor call: StructName(arg0, arg1, ...)
            if callee_name is not None and callee_name in self.struct_fields:
                sname = callee_name
                fields = self.struct_fields[sname]
                n = len(fields)

                # Built-in `error(code, message)` constructor:
                # even though the underlying struct has more fields, we keep the
                # surface API at 2 args and auto-fill script/func/line.
                if sname == 'error':
                    if len(e.args) != 2:
                        raise self.error(f"Struct {sname} expects 2 args, got {len(e.args)}", e)
                    n = 5
                else:
                    if len(e.args) != n:
                        raise self.error(f"Struct {sname} expects {n} args, got {len(e.args)}", e)

                size = 16 + n * 8
                a.mov_rcx_imm32(size)
                a.call('fn_alloc')

                # spill base pointer (rax) into expression-temp area
                base_off = self.alloc_expr_temps(8)
                a.mov_rsp_disp32_rax(base_off)
                a.mov_r11_rax()

                # header: type / nfields / struct_id / pad
                a.mov_membase_disp_imm32("r11", 0, OBJ_STRUCT, qword=False)
                a.mov_membase_disp_imm32("r11", 4, n, qword=False)
                sid = self.struct_id.get(sname, 0)
                a.mov_membase_disp_imm32("r11", 8, sid, qword=False)
                a.mov_membase_disp_imm32("r11", 12, 0, qword=False)

                # fill fields in order
                for i, arg in enumerate(e.args):
                    self.emit_expr(arg)
                    # restore base pointer into r11 (do NOT clobber rax)
                    a.mov_r64_membase_disp("r11", "rsp", base_off)
                    disp = 16 + i * 8
                    a.mov_membase_disp_r64("r11", disp, "rax")

                # Auto-fill error origin fields: script, func, line
                if sname == 'error':
                    a.mov_r64_membase_disp("r11", "rsp", base_off)
                    a.mov_rax_rip_qword('dbg_loc_script')
                    a.mov_membase_disp_r64('r11', 16 + 2 * 8, 'rax')
                    a.mov_rax_rip_qword('dbg_loc_func')
                    a.mov_membase_disp_r64('r11', 16 + 3 * 8, 'rax')
                    a.mov_rax_rip_qword('dbg_loc_line')
                    a.mov_membase_disp_r64('r11', 16 + 4 * 8, 'rax')

                # return ptr in rax
                a.mov_rax_rsp_disp32(base_off)
                self.free_expr_temps(8)
                return
            # If the callee is a known user function (by qualified name), enforce arity at compile time.
            # This keeps "foo expects N args" as a compile-time error for direct calls like foo(...),
            # while still allowing function values of unknown provenance to be called (runtime-checked).
            if callee_name is not None and callee_name in self.user_functions:
                # Only enforce arity if this identifier currently resolves to the *global* function binding.
                # If it is shadowed by a local (e.g. nested function statement `function foo`), we must not
                # treat it as the top-level function.
                b = None
                try:
                    b = self.resolve_binding(callee_name)
                except Exception:
                    b = None
                if b is None or getattr(b, "kind", None) == "global":
                    fn = self.user_functions.get(callee_name)
                    expected = len(getattr(fn, "params", []) or []) if fn is not None else 0
                    if len(call_args) != expected:
                        raise self.error(f"Function {callee_name} expects {expected} args, got {len(call_args)}", e)

            # If the callee is a known extern (by qualified name), enforce arity at compile time for
            # direct calls like `MessageBoxA(...)`. This keeps "expects N args" as a compile-time error
            # even though externs are stub-only values (OBJ_BUILTIN), while still allowing calls through
            # unknown function values (e.g. `f = MessageBoxA; f(...)`) to be runtime-checked.
            if callee_name is not None and callee_name in self.extern_sigs:
                b = None
                try:
                    b = self.resolve_binding(callee_name)
                except Exception:
                    b = None
                if b is None or getattr(b, "kind", None) == "global":
                    sig = self.extern_sigs.get(callee_name) or {}
                    expected = len(list(sig.get("params", []) or []))
                    if len(call_args) != expected:
                        raise self.error(f"Extern {callee_name} expects {expected} args, got {len(call_args)}", e)

            # Indirect call: evaluate callee expression to a function value and call via code_ptr.
            #
            # This implements first-class functions:
            #   f = add
            #   f(1,2)
            if callee_expr is None:
                raise self.error("Invalid call node (missing callee)", e)

            nargs = len(call_args)

            # Only method-style calls (obj.member(...)) should produce a runtime error when
            # the member is missing / not callable. Plain indirect calls keep the historical
            # behavior of evaluating to void on type mismatch.
            callee_is_member = hasattr(ml, 'Member') and isinstance(callee_expr, ml.Member)
            callee_desc = None
            if callee_is_member:
                def _qname_parts_any(x: Any) -> Optional[List[str]]:
                    if isinstance(x, ml.Var):
                        nm = str(getattr(x, 'name', ''))
                        return nm.split('.') if nm else None
                    if hasattr(ml, 'Member') and isinstance(x, ml.Member):
                        tgt2 = getattr(x, 'target', None)
                        if tgt2 is None:
                            tgt2 = getattr(x, 'obj', None)
                        base2 = _qname_parts_any(tgt2)
                        if base2 is None:
                            return None
                        nm2 = getattr(x, 'name', None)
                        if nm2 is None:
                            nm2 = getattr(x, 'field', None)
                        if nm2 is None:
                            return None
                        return base2 + [str(nm2)]
                    return None

                try:
                    p = _qname_parts_any(callee_expr)
                    if p is not None and len(p) > 0:
                        callee_desc = ".".join(p)
                except Exception:
                    callee_desc = None
                if not callee_desc:
                    # fall back to the immediate member name
                    try:
                        nm = getattr(callee_expr, 'name', None)
                        if nm is None:
                            nm = getattr(callee_expr, 'field', None)
                        callee_desc = str(nm) if nm is not None else None
                    except Exception:
                        callee_desc = None

            # Evaluate callee + args into a nested-safe temp area: [callee, arg0, arg1, ...]
            base = self.alloc_expr_temps((nargs + 1) * 8 + 24)  # +24 reserved for member-call diag temp slots
            # Init diag temp slots to void (GC-safe even on first use)
            void_imm = enc_void()
            a.mov_membase_disp_imm32("rsp", base + (nargs + 1) * 8 + 0, void_imm, qword=True)
            a.mov_membase_disp_imm32("rsp", base + (nargs + 1) * 8 + 8, void_imm, qword=True)
            a.mov_membase_disp_imm32("rsp", base + (nargs + 1) * 8 + 16, void_imm, qword=True)


            self.emit_expr(callee_expr)
            a.mov_rsp_disp32_rax(base)

            for i, arg in enumerate(call_args):
                if arg is None:
                    # injected dummy receiver for type-qualified helper instance method calls
                    a.mov_rax_imm64(enc_void())
                else:
                    self.emit_expr(arg)
                a.mov_rsp_disp32_rax(base + (i + 1) * 8)

            # Load register args (Windows x64): RCX,RDX,R8,R9
            if nargs >= 1:
                a.mov_rax_rsp_disp32(base + 8)
                a.mov_r64_r64("rcx", "rax")
            if nargs >= 2:
                a.mov_rax_rsp_disp32(base + 16)
                a.mov_r64_r64("rdx", "rax")
            if nargs >= 3:
                a.mov_rax_rsp_disp32(base + 24)
                a.mov_r64_r64("r8", "rax")
            if nargs >= 4:
                a.mov_rax_rsp_disp32(base + 32)
                a.mov_r64_r64("r9", "rax")

            # Stack args (arg5+): placed right above caller shadow space at [rsp+0x20]...
            if nargs > 4:
                for i in range(4, nargs):
                    a.mov_rax_rsp_disp32(base + (i + 1) * 8)
                    a.mov_rsp_disp32_rax(0x20 + (i - 4) * 8)

            # r11 = callee value
            a.mov_r64_membase_disp("r11", "rsp", base)

            fid = self.new_label_id()
            l_fail = f"icall_fail_{fid}"
            l_done = f"icall_done_{fid}"

            # Tag check: must be pointer
            a.mov_r64_r64("r10", "r11")
            a.and_r64_imm("r10", 7)
            a.cmp_r64_imm("r10", TAG_PTR)
            a.jcc("ne", l_fail)

            # Type check: must be OBJ_FUNCTION or OBJ_STRUCTTYPE or OBJ_BUILTIN
            a.mov_r32_membase_disp("r10d", "r11", 0)
            l_fun = f"icall_fun_{fid}"
            l_stt = f"icall_stt_{fid}"
            l_blt = f"icall_blt_{fid}"

            a.cmp_r32_imm("r10d", OBJ_FUNCTION)
            a.jcc("e", l_fun)
            a.cmp_r32_imm("r10d", OBJ_STRUCTTYPE)
            a.jcc("e", l_stt)
            a.cmp_r32_imm("r10d", OBJ_BUILTIN)
            a.jcc("e", l_blt)
            a.jmp(l_fail)

            a.mark(l_fun)
            # Arity check
            a.mov_r32_membase_disp("r10d", "r11", 4)
            a.cmp_r32_imm("r10d", nargs)
            a.jcc("ne", l_fail)

            # Load code pointer and call
            a.mov_r64_membase_disp("rax", "r11", 8)
            a.mov_r64_membase_disp("r10", "r11", 16)  # closure env (Step 6.2b-1 prep)
            a.call_rax()
            a.jmp(l_done)

            a.mark(l_blt)
            # Arity range check: min <= nargs <= max
            a.mov_r32_membase_disp("r10d", "r11", 4)  # min
            a.cmp_r32_imm("r10d", nargs)
            a.jcc("g", l_fail)
            a.mov_r32_membase_disp("r10d", "r11", 8)  # max
            a.cmp_r32_imm("r10d", nargs)
            a.jcc("l", l_fail)

            # Pass nargs in r10d for builtin stubs (internal convention)
            a.mov_r32_imm32("r10d", nargs)

            # Load code pointer and call
            a.mov_r64_membase_disp("rax", "r11", 16)
            a.call_rax()
            a.jmp(l_done)

            a.mark(l_stt)
            # Arity check (nfields)
            a.mov_r32_membase_disp("r10d", "r11", 4)
            a.cmp_r32_imm("r10d", nargs)
            a.jcc("ne", l_fail)

            # Special-case: built-in `error(code, message)` constructor.
            # The surface API keeps 2 args, but the underlying struct has 5 fields:
            #   error(code, message, script, func, line)
            # We auto-fill script/func/line from the current debug-loc globals so
            # runtime/builtin-generated errors still report the correct callsite.
            if nargs == 2:
                lid_err = self.new_label_id()
                l_stt_normal = f"icall_stt_normal_{lid_err}"

                # if struct_id != ERROR_STRUCT_ID -> normal struct construction
                a.mov_r32_membase_disp("r10d", "r11", 8)  # struct_id (u32)
                a.cmp_r32_imm("r10d", ERROR_STRUCT_ID)
                a.jcc("ne", l_stt_normal)

                # Allocate 5-field error struct: 16 header + 5*8 = 56 bytes
                a.mov_rcx_imm32(56)
                a.call("fn_alloc")

                # keep struct base pointer in r11 so we can freely use rax as scratch
                a.mov_r11_rax()

                # header: type / nfields / struct_id / pad
                a.mov_membase_disp_imm32("r11", 0, OBJ_STRUCT, qword=False)
                a.mov_membase_disp_imm32("r11", 4, 5, qword=False)
                a.mov_membase_disp_imm32("r11", 8, ERROR_STRUCT_ID, qword=False)
                a.mov_membase_disp_imm32("r11", 12, 0, qword=False)

                # field0/1 from temp args (code, message)
                a.mov_r64_membase_disp("r10", "rsp", base + 8)
                a.mov_membase_disp_r64("r11", 16, "r10")
                a.mov_r64_membase_disp("r10", "rsp", base + 16)
                a.mov_membase_disp_r64("r11", 24, "r10")

                # field2/3/4 from debug-loc globals
                a.mov_rax_rip_qword('dbg_loc_script')
                a.mov_membase_disp_r64('r11', 32, 'rax')
                a.mov_rax_rip_qword('dbg_loc_func')
                a.mov_membase_disp_r64('r11', 40, 'rax')
                a.mov_rax_rip_qword('dbg_loc_line')
                a.mov_membase_disp_r64('r11', 48, 'rax')

                # return ptr in rax
                a.mov_rax_r11()

                a.jmp(l_done)

                a.mark(l_stt_normal)

            # Allocate struct instance (payload 16 + nargs * 8 bytes)
            a.mov_rcx_imm32(16 + nargs * 8)
            a.call("fn_alloc")

            # reload callee in r11 (fn_alloc clobbers r10/r11)
            a.mov_r64_membase_disp("r11", "rsp", base)

            # header: type / nfields / struct_id / pad
            a.mov_membase_disp_imm32("rax", 0, OBJ_STRUCT, qword=False)
            a.mov_membase_disp_imm32("rax", 4, nargs, qword=False)
            a.mov_r32_membase_disp("r10d", "r11", 8)  # struct_id (u32)
            a.mov_membase_disp_r32("rax", 8, "r10d")
            a.mov_membase_disp_imm32("rax", 12, 0, qword=False)

            # fill fields in order from temp args
            for i in range(nargs):
                a.mov_r64_membase_disp("r10", "rsp", base + (i + 1) * 8)
                a.mov_membase_disp_r64("rax", 16 + i * 8, "r10")

            a.jmp(l_done)
            a.mark(l_fail)
            # Strict void:
            # - calling void() must raise an error
            # - calling a missing member (member lookup returned void) should report "no such function"
            # Keep legacy behavior for other non-callables (return void) for non-member calls.
            lidv = self.new_label_id()
            l_not_void = f"icall_not_void_{lidv}"
            a.mov_r64_r64("r10", "r11")
            a.and_r64_imm("r10", 7)
            a.cmp_r64_imm("r10", TAG_VOID)
            a.jcc("ne", l_not_void)

            if callee_is_member:
                recv = callee_desc or "receiver"
                meth = None
                if isinstance(callee_desc, str) and "." in callee_desc:
                    recv, meth = callee_desc.rsplit(".", 1)
                if not meth:
                    meth = callee_desc or "member"
                self._emit_make_error_const(ERR_CALL_NOT_CALLABLE, f"'{recv}' has no function '{meth}'")
            else:
                self._emit_make_error_const(ERR_CALL_NOT_CALLABLE, "Cannot call void")

            a.jmp(l_done)

            a.mark(l_not_void)
            if callee_is_member:
                # Improve diagnostics for member-call failures (wrong arity / non-callable).
                # When the callee is a function/builtin/structtype value, we can read the expected arity
                # from the object header and format a helpful error string at runtime.
                desc_s = str(callee_desc or "member")

                # Constant string fragments in .rdata
                lbl_desc = f"objstr_{len(self.rdata.labels)}"
                self.rdata.add_obj_string(lbl_desc, desc_s)
                lbl_p0 = f"objstr_{len(self.rdata.labels)}"
                self.rdata.add_obj_string(lbl_p0, "Cannot call '")
                lbl_p1 = f"objstr_{len(self.rdata.labels)}"
                self.rdata.add_obj_string(lbl_p1, "' with ")
                lbl_p2 = f"objstr_{len(self.rdata.labels)}"
                self.rdata.add_obj_string(lbl_p2, " args (expected ")
                lbl_p3 = f"objstr_{len(self.rdata.labels)}"
                self.rdata.add_obj_string(lbl_p3, "..")
                lbl_p4 = f"objstr_{len(self.rdata.labels)}"
                self.rdata.add_obj_string(lbl_p4, ")")

                # temp slots: msg_ptr, min, max (all tagged values / pointers)
                tmp = base + (nargs + 1) * 8  # diag temp slots (reserved with base)

                lidm = self.new_label_id()
                l_simple = f"icall_mdiag_simple_{lidm}"
                l_fun = f"icall_mdiag_fun_{lidm}"
                l_blt = f"icall_mdiag_blt_{lidm}"
                l_stt = f"icall_mdiag_stt_{lidm}"
                l_done_msg = f"icall_mdiag_done_{lidm}"

                # if not ptr -> simple message
                a.mov_r64_r64("r10", "r11")
                a.and_r64_imm("r10", 7)
                a.cmp_r64_imm("r10", TAG_PTR)
                a.jcc("ne", l_simple)

                # type dispatch
                a.mov_r32_membase_disp("r10d", "r11", 0)
                a.cmp_r32_imm("r10d", OBJ_FUNCTION)
                a.jcc("e", l_fun)
                a.cmp_r32_imm("r10d", OBJ_BUILTIN)
                a.jcc("e", l_blt)
                a.cmp_r32_imm("r10d", OBJ_STRUCTTYPE)
                a.jcc("e", l_stt)
                a.jmp(l_simple)

                # -------- function: expected exact arity --------
                a.mark(l_fun)
                a.mov_r32_membase_disp("r10d", "r11", 4)  # expected (u32)
                a.mov_r64_r64("r10", "r10")               # zero-extend
                a.shl_r64_imm8("r10", 3)
                a.or_r64_imm("r10", TAG_INT)
                a.mov_membase_disp_r64("rsp", tmp + 8, "r10")  # tmp+8 = expected

                # Build message string into RAX
                a.lea_rax_rip(lbl_p0)
                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_desc)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")  # "Cannot call '" + desc

                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_p1)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")  # + "' with "

                a.mov_r64_r64("rcx", "rax")
                a.mov_r64_imm64("rdx", enc_int(nargs))
                a.call("fn_add_string")  # + got

                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_p2)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")  # + " args (expected "

                a.mov_r64_r64("rcx", "rax")
                a.mov_r64_membase_disp("rdx", "rsp", tmp + 8)  # expected
                a.call("fn_add_string")  # + expected

                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_p4)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")  # + ")"

                a.mov_membase_disp_r64("rsp", tmp, "rax")  # tmp+0 = msg_ptr

                # Allocate error(code,msg,script,func,line) into RAX
                a.mov_rcx_imm32(56)
                a.call("fn_alloc")
                a.mov_r11_rax()
                a.mov_membase_disp_imm32("r11", 0, OBJ_STRUCT, qword=False)
                a.mov_membase_disp_imm32("r11", 4, 5, qword=False)
                a.mov_membase_disp_imm32("r11", 8, ERROR_STRUCT_ID, qword=False)
                a.mov_membase_disp_imm32("r11", 12, 0, qword=False)
                a.mov_rax_imm64(enc_int(int(ERR_CALL_NOT_CALLABLE)))
                a.mov_membase_disp_r64("r11", 16, "rax")
                a.mov_r64_membase_disp("r10", "rsp", tmp)  # msg_ptr
                a.mov_membase_disp_r64("r11", 24, "r10")
                a.mov_rax_rip_qword("dbg_loc_script")
                a.mov_membase_disp_r64("r11", 32, "rax")
                a.mov_rax_rip_qword("dbg_loc_func")
                a.mov_membase_disp_r64("r11", 40, "rax")
                a.mov_rax_rip_qword("dbg_loc_line")
                a.mov_membase_disp_r64("r11", 48, "rax")
                a.mov_rax_r11()
                a.jmp(l_done_msg)

                # -------- builtin: expected min..max --------
                a.mark(l_blt)
                # min
                a.mov_r32_membase_disp("r10d", "r11", 4)
                a.mov_r64_r64("r10", "r10")
                a.shl_r64_imm8("r10", 3)
                a.or_r64_imm("r10", TAG_INT)
                a.mov_membase_disp_r64("rsp", tmp + 8, "r10")
                # max
                a.mov_r32_membase_disp("r10d", "r11", 8)
                a.mov_r64_r64("r10", "r10")
                a.shl_r64_imm8("r10", 3)
                a.or_r64_imm("r10", TAG_INT)
                a.mov_membase_disp_r64("rsp", tmp + 16, "r10")

                # Build message: Cannot call '<desc>' with N args (expected MIN..MAX)
                a.lea_rax_rip(lbl_p0)
                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_desc)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_p1)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.mov_r64_imm64("rdx", enc_int(nargs))
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_p2)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.mov_r64_membase_disp("rdx", "rsp", tmp + 8)  # min
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_p3)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.mov_r64_membase_disp("rdx", "rsp", tmp + 16)  # max
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_p4)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")

                a.mov_membase_disp_r64("rsp", tmp, "rax")  # msg_ptr

                a.mov_rcx_imm32(56)
                a.call("fn_alloc")
                a.mov_r11_rax()
                a.mov_membase_disp_imm32("r11", 0, OBJ_STRUCT, qword=False)
                a.mov_membase_disp_imm32("r11", 4, 5, qword=False)
                a.mov_membase_disp_imm32("r11", 8, ERROR_STRUCT_ID, qword=False)
                a.mov_membase_disp_imm32("r11", 12, 0, qword=False)
                a.mov_rax_imm64(enc_int(int(ERR_CALL_NOT_CALLABLE)))
                a.mov_membase_disp_r64("r11", 16, "rax")
                a.mov_r64_membase_disp("r10", "rsp", tmp)
                a.mov_membase_disp_r64("r11", 24, "r10")
                a.mov_rax_rip_qword("dbg_loc_script")
                a.mov_membase_disp_r64("r11", 32, "rax")
                a.mov_rax_rip_qword("dbg_loc_func")
                a.mov_membase_disp_r64("r11", 40, "rax")
                a.mov_rax_rip_qword("dbg_loc_line")
                a.mov_membase_disp_r64("r11", 48, "rax")
                a.mov_rax_r11()
                a.jmp(l_done_msg)

                # -------- structtype: expected exact field count --------
                a.mark(l_stt)
                a.mov_r32_membase_disp("r10d", "r11", 4)  # expected (u32)
                a.mov_r64_r64("r10", "r10")
                a.shl_r64_imm8("r10", 3)
                a.or_r64_imm("r10", TAG_INT)
                a.mov_membase_disp_r64("rsp", tmp + 8, "r10")

                a.lea_rax_rip(lbl_p0)
                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_desc)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_p1)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.mov_r64_imm64("rdx", enc_int(nargs))
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_p2)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.mov_r64_membase_disp("rdx", "rsp", tmp + 8)  # expected
                a.call("fn_add_string")

                a.mov_r64_r64("rcx", "rax")
                a.lea_rax_rip(lbl_p4)
                a.mov_r64_r64("rdx", "rax")
                a.call("fn_add_string")

                a.mov_membase_disp_r64("rsp", tmp, "rax")

                a.mov_rcx_imm32(56)
                a.call("fn_alloc")
                a.mov_r11_rax()
                a.mov_membase_disp_imm32("r11", 0, OBJ_STRUCT, qword=False)
                a.mov_membase_disp_imm32("r11", 4, 5, qword=False)
                a.mov_membase_disp_imm32("r11", 8, ERROR_STRUCT_ID, qword=False)
                a.mov_membase_disp_imm32("r11", 12, 0, qword=False)
                a.mov_rax_imm64(enc_int(int(ERR_CALL_NOT_CALLABLE)))
                a.mov_membase_disp_r64("r11", 16, "rax")
                a.mov_r64_membase_disp("r10", "rsp", tmp)
                a.mov_membase_disp_r64("r11", 24, "r10")
                a.mov_rax_rip_qword("dbg_loc_script")
                a.mov_membase_disp_r64("r11", 32, "rax")
                a.mov_rax_rip_qword("dbg_loc_func")
                a.mov_membase_disp_r64("r11", 40, "rax")
                a.mov_rax_rip_qword("dbg_loc_line")
                a.mov_membase_disp_r64("r11", 48, "rax")
                a.mov_rax_r11()
                a.jmp(l_done_msg)

                # -------- fallback: old constant message --------
                a.mark(l_simple)
                msg = f"Cannot call '{desc_s}' with {nargs} args"
                self._emit_make_error_const(ERR_CALL_NOT_CALLABLE, msg)

                a.mark(l_done_msg)
            else:
                a.mov_rax_imm64(enc_void())

            a.mark(l_done)

            # Automatic error propagation (unless suppressed by try()).
            if int(getattr(self, '_errprop_suppression', 0) or 0) == 0:
                lidp = self.new_label_id()
                l_noerr = f"errprop_noerr_{lidp}"
                # Check: TAG_PTR + OBJ_STRUCT + struct_id == ERROR_STRUCT_ID
                a.mov_r64_r64("r10", "rax")
                a.and_r64_imm("r10", 7)
                a.cmp_r64_imm("r10", TAG_PTR)
                a.jcc("ne", l_noerr)
                a.mov_r32_membase_disp("r10d", "rax", 0)
                a.cmp_r32_imm("r10d", OBJ_STRUCT)
                a.jcc("ne", l_noerr)
                a.mov_r32_membase_disp("r10d", "rax", 8)
                a.cmp_r32_imm("r10d", ERROR_STRUCT_ID)
                a.jcc("ne", l_noerr)

                # Is error: propagate to caller (function return) or abort at top-level.
                if bool(getattr(self, 'in_function', False)) and getattr(self, 'func_ret_label', None):
                    a.jmp(self.func_ret_label)
                else:
                    a.mov_r64_r64("rcx", "rax")
                    a.call('fn_unhandled_error_exit')

                a.mark(l_noerr)

            # --- GC safety: clear temps + outgoing stack args ---
            self.free_expr_temps((nargs + 1) * 8 + 24)

            void_imm = enc_void()
            if nargs > 4:
                for i in range(4, nargs):
                    disp = 0x20 + (i - 4) * 8
                    a.mov_membase_disp_imm32("rsp", disp, void_imm, qword=True)

            return

        if isinstance(e, self.ml.Str):
            # boxed string value in .rdata
            lbl = f"objstr_{len(self.rdata.labels)}"
            self.rdata.add_obj_string(lbl, e.value)
            a.lea_rax_rip(lbl)
            return

        raise self.error(f"Unsupported expression type: {type(e).__name__}", e)
