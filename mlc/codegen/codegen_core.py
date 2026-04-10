"""
MiniLang -> x86-64 machine code generation for Windows (PE32+).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from ..asm import Asm
from ..constants import (TAG_INT, TAG_FLOAT, OBJ_STRING, OBJ_ARRAY, OBJ_BYTES, OBJ_FLOAT, ERROR_STRUCT_ID, CALLSTAT_STRUCT_ID, WIDEBUF_SIZE, INBUF_SIZE, )
from ..context import BreakableCtx
from ..data import DataBuilder, RDataBuilder, BssBuilder
from ..errors import CompileError
from ..pe import KERNEL32, MSVCRT
from ..tools import align_up, enc_int, enc_void


class ExprValueTemp:
    __slots__ = ("off", "reg", "dirty")

    def __init__(self, off: int, reg: Optional[str]) -> None:
        self.off = int(off)
        self.reg = str(reg) if isinstance(reg, str) and reg else None
        self.dirty = False


class CodegenCore:
    def __init__(self, minilang_mod: Any, source: str, filename: str, *, heap_config: Optional[Dict[str, Any]] = None,
                 import_aliases: Optional[Dict[str, str]] = None, extern_sigs: Optional[Dict[str, Any]] = None,
                 extern_structs: Optional[Dict[str, Any]] = None, call_profile: bool = False, trace_calls: bool = False,
                 subsystem: str = 'console'):
        self.ml = minilang_mod
        self.source = source
        self.filename = filename

        # Root directory of the entry file (used for stable, short script paths).
        try:
            self.entry_root = os.path.dirname(os.path.realpath(os.path.abspath(filename)))
        except Exception:
            self.entry_root = ""

        def _pretty_script(p: str) -> str:
            """Prefer a short, stable display path (relative to entry root when possible)."""
            try:
                rp = os.path.realpath(os.path.abspath(p))
                rr = os.path.realpath(os.path.abspath(self.entry_root)) if self.entry_root else ""
                if rr:
                    rel = os.path.relpath(rp, rr)
                    if not rel.startswith('..' + os.sep) and rel != '..':
                        return rel.replace('\\', '/')
                return rp.replace('\\', '/')
            except Exception:
                return str(p).replace('\\', '/')

        # Expose helper for other mixins.
        self._pretty_script = _pretty_script

        self.call_profile = bool(call_profile)
        self.profile_calls = self.call_profile

        # Runtime debug: print each entered function name.
        # Enabled via CLI flag --trace-calls.
        self.trace_calls = bool(trace_calls)

        # PE/runtime subsystem selection (console or windows).
        self.subsystem = str(subsystem or 'console').lower()
        self.is_windows_subsystem = self.subsystem == 'windows'

        # `import ... as alias` maps alias -> package name (compile-time only)
        self.import_aliases: Dict[str, str] = dict(import_aliases or {})

        # `extern function` declarations collected by the compiler (qname -> signature dict)
        self.extern_sigs: Dict[str, Any] = dict(extern_sigs or {})

        # `extern struct` declarations collected by the compiler (qname -> layout dict)
        self.extern_structs: Dict[str, Any] = dict(extern_structs or {})

        # Heap/GC configuration passed from CLI (Step 2+)
        self.heap_config = heap_config or {}
        self.asm = Asm()

        # Track which internal runtime helpers (fn_*) are actually called.
        # This lets us emit only the helpers that are needed by the compiled program.
        self.used_helpers = set()
        self._emitted_helpers = set()
        self._expr_temp_reg_order = ("r12", "r13", "r14")
        self._expr_temp_reg_live: list[ExprValueTemp] = []
        self._expr_temp_reg_live_by_reg: Dict[str, ExprValueTemp] = {}
        self._expr_temp_reg_reserved: Dict[str, int] = {}

        def _track_call_label(lbl: str) -> None:
            if isinstance(lbl, str) and lbl.startswith('fn_') and not lbl.startswith('fn_user_'):
                self.used_helpers.add(lbl)

        # Asm.call() invokes this hook (if present).
        self.asm._on_call_label = _track_call_label
        self.asm._before_call = self._spill_live_expr_value_temps

        self.rdata = RDataBuilder()
        self.data = DataBuilder()
        self.bss = BssBuilder()

        self.var_slots: Dict[str, str] = {}  # var -> data label
        self.break_stack: List[BreakableCtx] = []

        # compile-time type tables
        self.struct_fields: Dict[str, List[str]] = {}
        self.struct_id: Dict[str, int] = {}
        # struct_qname -> {method_name -> function_qname}
        self.struct_methods: Dict[str, Dict[str, str]] = {}
        # struct_qname -> {static_method_name -> function_qname}
        self.struct_static_methods: Dict[str, Dict[str, str]] = {}
        self.enum_variants: Dict[str, List[str]] = {}
        self.enum_id: Dict[str, int] = {}

        # Reserved identifiers (cannot be used as variable/function/param/etc. names).
        # `try(...)` is a special-form propagation stopper.
        # `error(...)` is the built-in error struct constructor.
        self.reserved_identifiers: set[str] = {"try", "error"}

        # Built-in struct names (reserved). Used by declaration collector to avoid
        # assigning huge user struct IDs when ERROR_STRUCT_ID is large.
        self.builtin_struct_names: set[str] = {"error"}

        # built-in `error` struct type (reserved)
        # Fields:
        #   code (int), message (string), script (string|void), func (string|void), line (int|void)
        self.struct_fields["error"] = ["code", "message", "script", "func", "line"]
        self.struct_id["error"] = ERROR_STRUCT_ID

        # built-in call profiling record struct (enabled only with --profile-calls)
        if self.call_profile:
            self.reserved_identifiers.update({"callStats", "callStat"})
            self.builtin_struct_names.add("callStat")
            self.struct_fields["callStat"] = ["name", "calls"]
            self.struct_id["callStat"] = CALLSTAT_STRUCT_ID


        # standard constants
        self.rdata.add_bytes('nl', b"\n")
        self.rdata.add_str('true_s', 'true', add_newline=True)
        self.rdata.add_str('false_s', 'false', add_newline=True)

        # No-newline variants (for array element printing)
        self.rdata.add_str('true_nn', 'true', add_newline=False)
        self.rdata.add_str('false_nn', 'false', add_newline=False)
        self.rdata.add_str('uns_nn', '<unsupported>', add_newline=False)
        self.rdata.add_str('array_nn', '<array>', add_newline=False)

        # With-newline variants (for general printing / fallbacks)
        self.rdata.add_str('uns_s', '<unsupported>', add_newline=True)

        # Boxed string constants used by internal helpers (e.g. string concatenation)
        self.rdata.add_obj_string('obj_true', 'true')
        self.rdata.add_obj_string('obj_false', 'false')
        self.rdata.add_obj_string('obj_uns', '<unsupported>')
        self.rdata.add_obj_string('obj_array', '<array>')
        self.rdata.add_obj_string('obj_bytes', '<bytes>')
        self.rdata.add_obj_string('obj_void', 'void')
        self.rdata.add_obj_string('obj_empty_string', '')

        # Dense cache for 1-byte strings used by string indexing / foreach.
        # Layout per entry (16-byte stride):
        #   [u32 OBJ_STRING][u32 len=1][u8 byte][u8 0][6 pad]
        self.rdata.pad_align(16)
        char_objs = bytearray()
        for i in range(256):
            char_objs += int(OBJ_STRING).to_bytes(4, "little", signed=False)
            char_objs += (1).to_bytes(4, "little", signed=False)
            char_objs += bytes((i, 0))
            char_objs += b"\x00" * 6
        self.rdata.add_bytes('obj_char_table', bytes(char_objs))

        # Boxed string constants for typeof(x) (no heap alloc)
        self.rdata.add_obj_string('obj_type_int', 'int')
        self.rdata.add_obj_string('obj_type_bool', 'bool')
        self.rdata.add_obj_string('obj_type_void', 'void')
        self.rdata.add_obj_string('obj_type_enum', 'enum')
        self.rdata.add_obj_string('obj_type_string', 'string')
        self.rdata.add_obj_string('obj_type_array', 'array')
        self.rdata.add_obj_string('obj_type_bytes', 'bytes')
        self.rdata.add_obj_string('obj_type_float', 'float')
        self.rdata.add_obj_string('obj_type_function', 'function')
        self.rdata.add_obj_string('obj_type_struct', 'struct')
        self.rdata.add_obj_string('obj_type_error', 'error')
        self.rdata.add_obj_string('obj_type_unknown', 'unknown')
        # Hex lookup table (for hex()/fromHex())
        self.rdata.add_bytes('hex_tbl', b"0123456789abcdef")
        self.rdata.add_bytes('lbrack', b"[")
        self.rdata.add_bytes('rbrack', b"]")
        self.rdata.add_bytes('comma_sp', b", ")

        # Unhandled error message parts
        self.rdata.add_str('err_occ_prefix', 'Error occured: no=', add_newline=False)
        self.rdata.add_str('err_occ_mid', ' message=', add_newline=False)
        self.rdata.add_str('err_occ_at', '  at ', add_newline=False)
        self.rdata.add_str('err_occ_colon', ':', add_newline=False)
        self.rdata.add_str('err_occ_in', ' in ', add_newline=False)

        # Print buffer too short message
        self.rdata.add_str(f'printbuf_short_msg',
                           f'ERROR: print buffer (= {WIDEBUF_SIZE * 2} bytes) too small to print given string',
                           add_newline=True)

        # OOM message
        self.rdata.add_str('oom_msg', 'ERROR: out of memory (MiniLang heap exhausted)')

        # global writable data
        # IMPORTANT (heap corruption hardening):
        # Allocate heap/GC globals *before* any large scratch buffers.
        #
        # Rationale:
        # - Several runtime helpers use fixed-size scratch buffers in .data
        #   (widebuf*, inbuf, floatbuf, ...).
        # - Any accidental overrun in those helpers would otherwise smash

        # Debug callsite location (used to attach script/func/line to errors created in builtins).
        # These are updated by codegen (function prolog + callsites).
        self.data.add_u64('dbg_loc_script', enc_void())
        self.data.add_u64('dbg_loc_func', enc_void())
        self.data.add_u64('dbg_loc_line', enc_int(0))
        self.data.add_u32('cpu_has_avx2', 0)
        #   the heap globals (heap_base/heap_end/...), leading to spurious
        #   "MiniLang heap exhausted" errors with nonsense committed values.
        # - By placing heap/GC globals at the start of .data, overruns hit
        #   later scratch space instead of the allocator's control words.
        if hasattr(self, 'ensure_gc_data'):
            self.ensure_gc_data()

        # Zero-length bytes are immutable in practice (no valid in-bounds writes), so a
        # single writable process-global instance avoids repeated heap churn for empty results.
        self.data.pad_align(8)
        self.data.add_bytes(
            'obj_empty_bytes',
            int(OBJ_BYTES).to_bytes(4, "little", signed=False) + (0).to_bytes(4, "little", signed=False) + b"\x00" * 8,
        )

        self.data.add_u32('bytesWritten', 0)
        self.data.add_u32('bytesRead', 0)
        # argv / argc storage for main(args)
        self.data.add_u32('ml_argc', 0)
        self.data.add_u64('ml_argvw', 0)

        self.data.add_u64('printSrcPtr', 0)
        self.data.add_u32('printSrcLen', 0)

        self.data.add_bytes('intbuf', b"\x00" * 32)
        self.data.add_bytes('floatbuf', b"\x00" * 64)
        # A default UTF-16 scratch buffer used by print()/string helpers.
        self.data.add_bytes('widebuf', b"\x00" * WIDEBUF_SIZE)  # bytes

        # Additional UTF-16 scratch buffers for extern wstr argument conversion.
        # Many WinAPI calls take multiple UTF-16 strings (e.g., MessageBoxW(text, caption)).
        # Using a single shared buffer would overwrite earlier arguments.
        for i in range(1, 4):
            self.data.add_bytes(f'widebuf{i}', b"\x00" * WIDEBUF_SIZE)

        # Pool used by CodegenExpr extern helpers (wstr conversions)
        self.ext_widebuf_labels = ['widebuf', 'widebuf1', 'widebuf2', 'widebuf3']
        self.data.add_bytes('inbuf', b"\x00" * INBUF_SIZE)
        # a label pointing to end of buffer (same section)
        # We'll create it as a u64 placeholder overwritten by relocation math at runtime is not needed.
        # Instead, label it as current offset (which equals intbuf+32).
        self.data.labels['intbuf_end'] = self.data.labels['intbuf'] + 32

        # Imports (filled later)
        self.imports = {KERNEL32: ['GetStdHandle', 'ReadFile', 'WriteFile', 'WriteConsoleW', 'MultiByteToWideChar',
                                   'SetConsoleOutputCP', 'FreeConsole', 'ExitProcess', 'VirtualAlloc', 'VirtualFree',
                                   'GetCommandLineW', 'LocalFree', 'WideCharToMultiByte'], MSVCRT: ['_gcvt', 'fmod'],
            'shell32.dll': ['CommandLineToArgvW'],

        }

        # Extend PE imports from `extern function` declarations.
        self._add_extern_imports()

        self._label_id = 0
        # user function defs (top-level)
        self.user_functions: Dict[str, Any] = {}
        self._in_function = False
        self.func_param_offsets: Dict[str, int] = {}
        self.func_ret_label: Optional[str] = None

        # function locals (stack slots, in addition to parameters)
        self.func_local_offsets: Dict[str, int] = {}

        # base offset for stack temps used for evaluating call arguments
        # (0x80 for main program, per-function computed for functions)
        self.call_temp_base: int = 0x30
        # additional stack temp area for nested expression spilling
        # (separate from call arguments temps)
        self.expr_temp_base: int = self.call_temp_base + 0x40
        self.expr_temp_top: int = 0
        self.expr_temp_max: int = 0x400
        self._current_root_rec_off: Optional[int] = None
        self._current_root_static_qwords: int = 0

        # ------------------------------------------------------------
        # Inline functions (function inline ...)
        # ------------------------------------------------------------
        # Stack of {param_name -> [rsp+disp]} overrides used while emitting an
        # inlined function body expression.
        self._inline_param_stack: list[dict[str, int]] = []
        # Detect recursion/mutual recursion during inlining.
        self._inline_call_stack: list[str] = []

        # ------------------------------------------------------------
        # Lexical scope support (CodegenScope mixin)
        # ------------------------------------------------------------
        if hasattr(self, "scope_setup"):
            self.scope_setup()
            # Expose scope-allocated global slots to GC scanning.
            # (codegen_memory.py looks for `self.global_slots`)
            if hasattr(self, "scope_global_slots"):
                self.global_slots = self.scope_global_slots

    # ---------- function mode (also isolates lexical scope stacks) ----------

    @property
    def in_function(self) -> bool:
        return bool(getattr(self, "_in_function", False))

    @in_function.setter
    def in_function(self, value: bool) -> None:
        value = bool(value)
        cur = bool(getattr(self, "_in_function", False))
        if cur == value:
            self._in_function = value
            return

        # If scope system is active, isolate scopes per function so locals declared inside a function
        # never leak into program/global code generation, BUT keep globals visible.
        #
        # Layout:
        #   _scope_stack[0] : global bindings (shared)
        #   _scope_stack[1] : function root locals
        if hasattr(self, "_scope_stack") and hasattr(self, "_scope_declared"):
            if value:
                # entering a function: save current scope universe
                self._saved_scope_stack = self._scope_stack
                self._saved_scope_declared = self._scope_declared

                gscope = self._saved_scope_stack[0] if self._saved_scope_stack else {}
                gdecls = self._saved_scope_declared[0] if self._saved_scope_declared else []

                # keep global scope as depth 0, add a new function-local root scope above it
                self._scope_stack = [gscope, {}]
                self._scope_declared = [gdecls, []]
            else:
                # leaving a function: restore previous scope universe
                if hasattr(self, "_saved_scope_stack") and hasattr(self, "_saved_scope_declared"):
                    self._scope_stack = self._saved_scope_stack
                    self._scope_declared = self._saved_scope_declared

        self._in_function = value

    def new_label_id(self) -> int:
        self._label_id += 1
        return self._label_id

    # ---------- PE imports ----------

    def add_import_symbol(self, dll: str, symbol: str) -> None:
        """Ensure (dll, symbol) is present in the PE import list (.idata / IAT)."""
        dll = str(dll or "").strip().lower()
        symbol = str(symbol or "").strip()
        if not dll or not symbol:
            return
        if dll not in self.imports:
            self.imports[dll] = []
        if symbol not in self.imports[dll]:
            self.imports[dll].append(symbol)

    def _add_extern_imports(self) -> None:
        """Extend `self.imports` with all `extern function` declarations collected by the compiler."""
        if not getattr(self, "extern_sigs", None):
            return

        by_dll: Dict[str, set[str]] = {}
        for qname, sig in dict(self.extern_sigs).items():
            if not isinstance(sig, dict):
                continue
            dll = sig.get("dll")
            if not isinstance(dll, str) or not dll.strip():
                continue
            dll_n = dll.strip().lower()

            sym = sig.get("symbol")
            if not isinstance(sym, str) or not sym.strip():
                # fall back to the last component of the qualified name
                sym = str(qname).split(".")[-1] if qname else ""
            sym = str(sym).strip()
            if not sym:
                continue

            by_dll.setdefault(dll_n, set()).add(sym)

        # Deterministic ordering (reproducible binaries).
        for dll in sorted(by_dll.keys()):
            for sym in sorted(by_dll[dll]):
                self.add_import_symbol(dll, sym)

    def _pos(self, node: Any) -> Optional[int]:
        return getattr(node, '_pos', None)

    def _flatten_member_chain_as_qualname(self, e: Any) -> Optional[str]:
        """Flatten a Var/Member chain into a dotted qualified name.

        Examples:
          - Member(Member(Var("a"),"b"),"c") -> "a.b.c"
          - Var("a.b") -> "a.b"

        Returns None if the expression isn't a simple Var/Member chain.
        """
        ml = getattr(self, 'ml', None)
        if ml is None or e is None:
            return None

        if hasattr(ml, 'Var') and isinstance(e, ml.Var):
            nm = getattr(e, 'name', None)
            return nm if isinstance(nm, str) and nm else None

        parts: list[str] = []
        cur = e
        while hasattr(ml, 'Member') and isinstance(cur, ml.Member):
            name = getattr(cur, 'name', None)
            if name is None:
                name = getattr(cur, 'field', None)
            if name is None:
                return None
            parts.append(str(name))
            tgt = getattr(cur, 'target', None)
            if tgt is None:
                tgt = getattr(cur, 'obj', None)
            if tgt is None:
                return None
            cur = tgt

        if hasattr(ml, 'Var') and isinstance(cur, ml.Var):
            base = getattr(cur, 'name', None)
            if not isinstance(base, str) or not base:
                return None
            base_parts = base.split('.') if '.' in base else [base]
            return '.'.join(base_parts + list(reversed(parts)))

        return None

    def error(self, msg: str, node: Any = None) -> CompileError:
        fn = getattr(self, "filename", None)
        if node is not None:
            fn = getattr(node, "_filename", fn)
        return CompileError(msg, self._pos(node) if node is not None else None, fn)

    # ---------- debug callsite location (for error origins) ----------

    def emit_dbg_line(self, node: Any) -> None:
        """Update the current callsite line number.

        This is used by runtime/builtins when they construct an ``error`` value.
        Script/function are set once per function prolog; line is updated at callsites.
        """
        try:
            ln = getattr(node, '_line', None)
        except Exception:
            ln = None
        if isinstance(ln, int) and ln > 0:
            self.asm.mov_rax_imm64(enc_int(int(ln)))
            self.asm.mov_rip_qword_rax('dbg_loc_line')

    # ---------- var slots ----------

    # ---------- expression temp allocation (nested-safe) ----------

    def _sync_expr_temp_root_count(self) -> None:
        rec_off = getattr(self, '_current_root_rec_off', None)
        if rec_off is None:
            return
        base_qwords = int(getattr(self, '_current_root_static_qwords', 0) or 0)
        dyn_qwords = int(getattr(self, 'expr_temp_top', 0) or 0) // 8
        self.asm.mov_membase_disp_imm32("rsp", int(rec_off) + 16, base_qwords + dyn_qwords, qword=True)

    def alloc_expr_temps(self, size: int) -> int:
        """Reserve `size` bytes in the expression temp area and return the absolute [rsp+off] offset."""
        size = align_up(size, 8)
        off = self.expr_temp_base + self.expr_temp_top
        self.expr_temp_top += size
        if self.expr_temp_top > self.expr_temp_max:
            raise CompileError('Expression temp overflow (increase expr_temp_max)', None)
        if size > 0:
            imm = enc_void()
            for disp in range(off, off + size, 8):
                self.asm.mov_membase_disp_imm32("rsp", disp, imm, qword=True)
            self._sync_expr_temp_root_count()
        return off

    def free_expr_temps(self, size: int) -> None:
        size = align_up(size, 8)
        if size <= 0:
            return

        start = self.expr_temp_base + (self.expr_temp_top - size)
        imm = enc_void()  # TAG_VOID

        for disp in range(start, start + size, 8):
            # 48 C7 84 24 disp32 imm32  => mov qword ptr [rsp+disp32], imm32
            self.asm.mov_membase_disp_imm32("rsp", disp, imm, qword=True)

        self.expr_temp_top -= size
        if self.expr_temp_top < 0:
            self.expr_temp_top = 0
        self._sync_expr_temp_root_count()

    def _spill_live_expr_value_temps(self) -> None:
        for tmp in list(getattr(self, '_expr_temp_reg_live', []) or []):
            if not isinstance(tmp, ExprValueTemp):
                continue
            reg = getattr(tmp, 'reg', None)
            if not reg or not bool(getattr(tmp, 'dirty', False)):
                continue
            self.asm.mov_membase_disp_r64("rsp", int(tmp.off), str(reg))
            tmp.dirty = False

    def reserve_expr_temp_regs(self, *regs: str) -> None:
        for reg in regs:
            reg_s = str(reg or "").lower()
            if not reg_s:
                continue
            live = (getattr(self, '_expr_temp_reg_live_by_reg', {}) or {}).get(reg_s)
            if isinstance(live, ExprValueTemp):
                if bool(getattr(live, 'dirty', False)):
                    self.asm.mov_membase_disp_r64("rsp", int(live.off), reg_s)
                    live.dirty = False
                live.reg = None
                try:
                    self._expr_temp_reg_live.remove(live)
                except ValueError:
                    pass
                try:
                    self._expr_temp_reg_live_by_reg.pop(reg_s, None)
                except Exception:
                    pass
            self._expr_temp_reg_reserved[reg_s] = int(self._expr_temp_reg_reserved.get(reg_s, 0) or 0) + 1

    def release_expr_temp_regs(self, *regs: str) -> None:
        for reg in regs:
            reg_s = str(reg or "").lower()
            if not reg_s:
                continue
            cnt = int(self._expr_temp_reg_reserved.get(reg_s, 0) or 0)
            if cnt <= 1:
                self._expr_temp_reg_reserved.pop(reg_s, None)
            else:
                self._expr_temp_reg_reserved[reg_s] = cnt - 1

    def alloc_expr_value_temp(self, *, prefer_reg: bool = True) -> ExprValueTemp:
        off = self.alloc_expr_temps(8)
        reg = None
        if prefer_reg:
            for cand in tuple(getattr(self, '_expr_temp_reg_order', ()) or ()):
                cand_s = str(cand).lower()
                if (cand_s not in (getattr(self, '_expr_temp_reg_live_by_reg', {}) or {})
                        and int((getattr(self, '_expr_temp_reg_reserved', {}) or {}).get(cand_s, 0) or 0) <= 0):
                    reg = cand_s
                    break
        tmp = ExprValueTemp(off, reg)
        if reg:
            self._expr_temp_reg_live.append(tmp)
            self._expr_temp_reg_live_by_reg[reg] = tmp
        return tmp

    def expr_value_temp_store_rax(self, tmp: ExprValueTemp) -> None:
        if getattr(tmp, 'reg', None):
            self.asm.mov_r64_r64(str(tmp.reg), "rax")
            tmp.dirty = True
            return
        self.asm.mov_rsp_disp32_rax(int(tmp.off))

    def expr_value_temp_store_reg(self, tmp: ExprValueTemp, reg: str) -> None:
        reg_s = str(reg)
        if getattr(tmp, 'reg', None):
            self.asm.mov_r64_r64(str(tmp.reg), reg_s)
            tmp.dirty = True
            return
        self.asm.mov_membase_disp_r64("rsp", int(tmp.off), reg_s)

    def expr_value_temp_load(self, dst: str, tmp: ExprValueTemp) -> None:
        dst_s = str(dst)
        reg = getattr(tmp, 'reg', None)
        if reg:
            if dst_s.lower() != str(reg).lower():
                self.asm.mov_r64_r64(dst_s, str(reg))
            return
        self.asm.mov_r64_membase_disp(dst_s, "rsp", int(tmp.off))

    def expr_value_temp_offset(self, tmp: ExprValueTemp) -> int:
        reg = getattr(tmp, 'reg', None)
        if reg and bool(getattr(tmp, 'dirty', False)):
            self.asm.mov_membase_disp_r64("rsp", int(tmp.off), str(reg))
            tmp.dirty = False
        return int(tmp.off)

    def free_expr_value_temp(self, tmp: ExprValueTemp) -> None:
        try:
            self._expr_temp_reg_live.remove(tmp)
        except ValueError:
            pass
        reg = getattr(tmp, 'reg', None)
        if reg:
            try:
                self._expr_temp_reg_live_by_reg.pop(str(reg).lower(), None)
            except Exception:
                pass
            tmp.reg = None
            tmp.dirty = False
        self.free_expr_temps(8)

    def ensure_var(self, name: str) -> str:
        if name in self.var_slots:
            return self.var_slots[name]
        lbl = f"var_{name}"
        self.data.add_u64(lbl, enc_void())
        self.var_slots[name] = lbl
        return lbl

    # ---------- var access (global or function-params on stack) ----------

    def _apply_import_alias(self, qname: str) -> str:
        """Rewrite qualified names using `import ... as ...` aliases.

        Only applies to names of the form '<alias>.<rest>'. Rewrites repeatedly
        to support chained aliases (with a small cycle guard).
        """
        if not isinstance(qname, str) or '.' not in qname:
            return qname
        aliases = getattr(self, 'import_aliases', None) or {}
        out = qname
        for _ in range(8):
            if '.' not in out:
                break
            base, rest = out.split('.', 1)
            target = aliases.get(base)
            if not target:
                break
            out = f"{target}.{rest}"
        return out

    # ---------- package/namespace local resolution ----------

    def _current_file_package_prefix(self) -> str:
        """Return the active `package` prefix for the current function/file."""
        try:
            mp = getattr(self, '_file_prefix_map', None) or {}
            fn = getattr(self, '_current_fn_file', None)
            if isinstance(fn, str):
                return str(mp.get(fn, '') or '')
        except Exception:
            pass
        return ''

    def _current_function_prefix(self) -> str:
        """Return the current function's qualified prefix ("pkg.ns.")."""
        try:
            qn = getattr(self, '_current_fn_qname', None)
            if isinstance(qn, str) and '.' in qn:
                return qn.rsplit('.', 1)[0] + '.'
        except Exception:
            pass
        return ''

    def _qualify_identifier(self, name: str, node=None, *, kind: str | None = None) -> str:
        """Resolve unqualified identifiers inside `package`/`namespace` files.

        Declarations inside `package X` / `namespace Y` are rewritten to qualified
        names (e.g. `std.time.win32.Sleep`). Source code often calls them
        unqualified within the same file/package (`Sleep(10)`).

        For names without a dot:
          1) Try exact name
          2) Try current function prefix: <fn_prefix><name>
          3) Try current file package prefix: <pkg_prefix><name>
          4) If still not found and pkg_prefix exists, try a UNIQUE suffix match
             within that package: exactly one of {functions, externs, structs, enums}
             startswith pkg_prefix and endswith '.'+name.

        `kind` can be used to restrict the search: 'extern'|'func'|'struct'|'enum'.
        """
        try:
            name_s = self._apply_import_alias(str(name))
        except Exception:
            name_s = str(name)
        if '.' in name_s:
            return name_s

        fn_prefix = self._current_function_prefix()
        pkg_prefix = self._current_file_package_prefix() or fn_prefix

        cands: list[str] = [name_s]
        if fn_prefix:
            cands.append(fn_prefix + name_s)
        if pkg_prefix and (pkg_prefix + name_s) not in cands:
            cands.append(pkg_prefix + name_s)

        # Lexical shadowing first: if any candidate is already a visible binding
        # (local/param/global), prefer that and do NOT redirect to a package-level decl.
        if hasattr(self, 'resolve_binding') and callable(getattr(self, 'resolve_binding')):
            for cand in cands:
                try:
                    if self.resolve_binding(cand) is not None:
                        return cand
                except Exception:
                    continue

        pools: list[object] = []
        try:
            if kind in (None, 'func'):
                pools.append(getattr(self, 'user_functions', {}) or {})
            if kind in (None, 'extern'):
                pools.append(getattr(self, 'extern_sigs', {}) or {})
            if kind in (None, 'struct'):
                pools.append(getattr(self, 'struct_fields', {}) or {})
            if kind in (None, 'enum'):
                pools.append(getattr(self, 'enum_id', {}) or {})
        except Exception:
            pools = []

        # Direct hit for candidates
        for cand in cands:
            for pool in pools:
                try:
                    if cand in pool:
                        return cand
                except Exception:
                    pass

        # Unique suffix match within package
        if pkg_prefix:
            suffix = '.' + name_s
            matches: list[str] = []
            for pool in pools:
                try:
                    for qn in pool.keys():
                        if isinstance(qn, str) and qn.startswith(pkg_prefix) and qn.endswith(suffix):
                            matches.append(qn)
                except Exception:
                    pass
            uniq = list(dict.fromkeys(matches))
            if len(uniq) == 1:
                return uniq[0]

        return name_s

    def emit_load_var(self, name: str, node=None) -> None:
        """Load variable value into RAX.

        Step 9: if CodegenScope is integrated, use lexical scoping rules:
          - reading a name that is not visible is a compile error
          - function parameters are always readable
        Otherwise, fall back to the legacy behavior.
        """
        # Normalize identifier representation (frontend may pass tokens/nodes)
        if hasattr(self, '_coerce_name') and callable(getattr(self, '_coerce_name')):
            name = self._coerce_name(name)
        # Apply compile-time import aliases for qualified names.
        name = self._apply_import_alias(name)
        a = self.asm

        # New scoped semantics (preferred)
        if hasattr(self, "emit_load_var_scoped") and callable(getattr(self, "emit_load_var_scoped")):
            # Params are always visible in functions.
            if self.in_function and name in self.func_param_offsets:
                a.mov_rax_rsp_disp32(self.func_param_offsets[name])
                return

            # Lexical lookup (locals must have been introduced by a prior write)
            self.emit_load_var_scoped(name, node)
            return

        # ------------------------------------------------------------------
        # Legacy semantics (kept as a fallback)
        # ------------------------------------------------------------------
        if self.in_function:
            if name in self.func_param_offsets:
                a.mov_rax_rsp_disp32(self.func_param_offsets[name])
                return

            if name in self.func_local_offsets:
                off = self.func_local_offsets[name]
                lid = self.new_label_id()
                done = f"lv_done_{lid}"

                a.mov_rax_rsp_disp32(off)
                a.cmp_rax_imm8(enc_void())
                a.jcc('ne', done)

                if name not in self.var_slots:
                    self.ensure_var(name)
                a.mov_rax_rip_qword(self.var_slots[name])
                a.mark(done)
                return

        if name not in self.var_slots:
            self.ensure_var(name)
        a.mov_rax_rip_qword(self.var_slots[name])

    def emit_store_var(self, name: str, node=None) -> None:
        """Store RAX into variable.

        Step 9: if CodegenScope is integrated, use lexical scoping rules:
          - first write in a scope introduces a binding in that scope
          - writes update the nearest existing binding (including globals)
          - function parameters always write to their param slots
        Otherwise, fall back to legacy behavior.
        """
        # Normalize identifier representation (frontend may pass tokens/nodes)
        if hasattr(self, '_coerce_name') and callable(getattr(self, '_coerce_name')):
            name = self._coerce_name(name)
        # Apply compile-time import aliases for qualified names.
        name = self._apply_import_alias(name)
        a = self.asm

        # New scoped semantics (preferred)
        if hasattr(self, "emit_store_var_scoped") and callable(getattr(self, "emit_store_var_scoped")):
            # Params always target their stack slots.
            if self.in_function and name in self.func_param_offsets:
                a.mov_rsp_disp32_rax(self.func_param_offsets[name])
                return

            # In functions, ensure local bindings have a concrete stack slot.
            # We keep the v0.6 frame layout (one slot per *name*) for now.
            if self.in_function and hasattr(self, "resolve_binding") and callable(getattr(self, "resolve_binding")):
                if self.resolve_binding(name) is None and name in self.func_local_offsets:
                    # Introduce a local binding in the *current* lexical scope.
                    # (Shadowing without slot re-use is handled in a later step.)
                    if hasattr(self, "declare_local_binding") and callable(getattr(self, "declare_local_binding")):
                        self.declare_local_binding(name, node=node, offset=self.func_local_offsets[name])

            # Delegate actual store to the scope mixin.
            self.emit_store_var_scoped(name, node)

            # Compatibility: root-level globals should remain addressable via var_slots for
            # existing low-level helpers (and older code paths).
            if (not self.in_function) and hasattr(self, "scope_depth") and hasattr(self, "resolve_binding"):
                try:
                    if self.scope_depth == 0:
                        b = self.resolve_binding(name)
                        if b is not None and getattr(b, "kind", None) == "global" and getattr(b, "label", None):
                            self.var_slots[name] = b.label
                except Exception:
                    pass
            return

        # ------------------------------------------------------------------
        # Legacy semantics (kept as a fallback)
        # ------------------------------------------------------------------
        if self.in_function:
            if name in self.func_param_offsets:
                a.mov_rsp_disp32_rax(self.func_param_offsets[name])
                return

            if name in self.func_local_offsets:
                off = self.func_local_offsets[name]
                lid = self.new_label_id()
                lbl_local = f"st_local_{lid}"
                lbl_global = f"st_global_{lid}"
                lbl_done = f"st_done_{lid}"

                a.mov_r10_rax()

                a.mov_rax_rsp_disp32(off)
                a.cmp_rax_imm8(enc_void())
                a.jcc('ne', lbl_local)

                if name not in self.var_slots:
                    self.ensure_var(name)
                a.mov_rax_rip_qword(self.var_slots[name])
                a.cmp_rax_imm8(enc_void())
                a.jcc('ne', lbl_global)

                a.mark(lbl_local)
                a.mov_r64_r64("rax", "r10")
                a.mov_rsp_disp32_rax(off)
                a.jmp(lbl_done)

                a.mark(lbl_global)
                a.mov_r64_r64("rax", "r10")
                a.mov_rip_qword_rax(self.var_slots[name])

                a.mark(lbl_done)
                return

        if name not in self.var_slots:
            self.ensure_var(name)
        a.mov_rip_qword_rax(self.var_slots[name])

    def emit_writefile(self, buf_label: str, length: int) -> None:
        """Write UTF-8 constant buffer (rdata label) to console using WriteConsoleW."""
        # RDX = &buf (UTF-8 bytes)
        self.asm.lea_rdx_rip(buf_label)
        # R8D = length (bytes)
        self.asm.mov_r8d_imm32(length)
        self.emit_writefile_ptr_len()

    def emit_writefile_ptr_len(self) -> None:
        """Write UTF-8 buffer given by (RDX=ptr, R8D=len bytes) to stdout.

        Implementation:
        - Uses WriteFile directly (UTF-8), relying on SetConsoleOutputCP(CP_UTF8).
        - Avoids the MultiByteToWideChar/WriteConsoleW path, which requires stack args
          beyond the 32-byte shadow space and has been a frequent source of ABI bugs.
        """
        a = self.asm

        # WriteFile(h=rbx, buf=rdx, nbytes=r8d, &written, NULL)
        a.mov_rcx_rbx()
        a.lea_r9_rip('bytesWritten')
        a.mov_qword_ptr_rsp20_rax_zero()
        a.mov_rax_rip_qword('iat_WriteFile')
        a.call_rax()

    def emit_writefile_ptr_len_stderr(self) -> None:
        """Write UTF-8 buffer given by (RDX=ptr, R8D=len bytes) to stderr.

        Used for debug tracing such as --trace-calls. We fetch the stderr handle
        on demand so normal stdout handling stays unchanged.
        """
        a = self.asm

        # Preserve ptr/len across GetStdHandle(STD_ERROR_HANDLE=-12).
        a.mov_r64_r64('r10', 'rdx')
        a.mov_r32_r32('r11d', 'r8d')
        a.mov_rcx_imm32(-12)
        a.mov_rax_rip_qword('iat_GetStdHandle')
        a.call_rax()

        # WriteFile(h=rax, buf=r10, nbytes=r11d, &written, NULL)
        a.mov_r64_r64('rcx', 'rax')
        a.mov_r64_r64('rdx', 'r10')
        a.mov_r32_r32('r8d', 'r11d')
        a.lea_r9_rip('bytesWritten')
        a.mov_qword_ptr_rsp20_rax_zero()
        a.mov_rax_rip_qword('iat_WriteFile')
        a.call_rax()

    def emit_writefile_stderr(self, buf_label: str, length: int) -> None:
        """Write UTF-8 constant buffer (rdata label) to stderr using WriteFile."""
        self.asm.lea_rdx_rip(buf_label)
        self.asm.mov_r8d_imm32(length)
        self.emit_writefile_ptr_len_stderr()

    def emit_normalize_xmm0_to_value(self) -> None:
        """Normalize XMM0 numeric result: int when exact, else immediate float32 when exact, else boxed double."""
        a = self.asm
        lid = self.new_label_id()
        l_int = f"norm_int_{lid}"
        l_try_immf = f"norm_try_immf_{lid}"
        l_box = f"norm_box_{lid}"
        l_end = f"norm_end_{lid}"
        # rax = trunc(xmm0)
        a.cvttsd2si_r64_xmm("rax", "xmm0")  # cvttsd2si rax,xmm0
        # xmm1 = float(rax)
        a.cvtsi2sd_xmm_r64("xmm1", "rax")  # cvtsi2sd xmm1,rax
        # compare xmm0,xmm1
        a.ucomisd_xmm_xmm("xmm0", "xmm1")  # ucomisd xmm0,xmm1
        a.jcc('e', l_int)
        a.jmp(l_try_immf)
        # exact integer -> tagged int
        a.mark(l_int)
        a.shl_rax_imm8(3)
        a.or_rax_imm8(TAG_INT)
        a.jmp(l_end)
        # not exact integer -> try exact float32 immediate first
        a.mark(l_try_immf)
        a.cvtsd2ss_xmm_xmm("xmm2", "xmm0")
        a.cvtss2sd_xmm_xmm("xmm3", "xmm2")
        a.ucomisd_xmm_xmm("xmm0", "xmm3")
        a.jcc('ne', l_box)
        a.jcc('p', l_box)
        a.movd_r32_xmm("eax", "xmm2")
        a.shl_rax_imm8(3)
        a.or_rax_imm8(TAG_FLOAT)
        a.jmp(l_end)
        a.mark(l_box)
        a.call('fn_box_float')
        a.mark(l_end)

    def emit_to_double_xmm(self, xmm: int, fail_label: str) -> None:
        """Convert numeric value in RAX (tagged int, immediate float, or boxed float) to XMM0/XMM1.

        xmm: 0 -> XMM0, 1 -> XMM1
        On type mismatch, jumps to fail_label.
        """
        a = self.asm
        lid = self.new_label_id()
        l_int = f"todbl_int_{lid}"
        l_immf = f"todbl_immf_{lid}"
        l_ptr = f"todbl_ptr_{lid}"
        l_done = f"todbl_done_{lid}"

        # rdx = tag
        a.mov_r64_r64("rdx", "rax")  # mov rdx,rax
        a.and_r64_imm("rdx", 7)  # and rdx,7
        a.cmp_r64_imm("rdx", 1)  # cmp rdx,TAG_INT
        a.jcc('e', l_int)
        a.cmp_r64_imm("rdx", TAG_FLOAT)
        a.jcc('e', l_immf)
        a.cmp_r64_imm("rdx", 0)  # cmp rdx,TAG_PTR
        a.jcc('e', l_ptr)
        a.jmp(fail_label)

        a.mark(l_int)
        # rcx = decoded int
        a.mov_r64_r64("rcx", "rax")  # mov rcx,rax
        a.sar_r64_imm8("rcx", 3)  # sar rcx,3
        if xmm == 0:
            a.cvtsi2sd_xmm_r64("xmm0", "rcx")  # cvtsi2sd xmm0,rcx
        else:
            a.cvtsi2sd_xmm_r64("xmm1", "rcx")  # cvtsi2sd xmm1,rcx
        a.jmp(l_done)

        a.mark(l_immf)
        a.mov_r64_r64("rcx", "rax")
        a.shr_r64_imm8("rcx", 3)
        if xmm == 0:
            a.movq_xmm_r64("xmm0", "rcx")
            a.cvtss2sd_xmm_xmm("xmm0", "xmm0")
        else:
            a.movq_xmm_r64("xmm1", "rcx")
            a.cvtss2sd_xmm_xmm("xmm1", "xmm1")
        a.jmp(l_done)

        a.mark(l_ptr)
        # boxed float?
        a.mov_r32_membase_disp("edx", "rax", 0)  # mov edx,[rax]
        a.cmp_r32_imm("edx", OBJ_FLOAT)
        a.jcc('ne', fail_label)
        if xmm == 0:
            a.movsd_xmm_membase_disp("xmm0", "rax", 8)  # movsd xmm0,[rax+8]
        else:
            a.movsd_xmm_membase_disp("xmm1", "rax", 8)  # movsd xmm1,[rax+8]

        a.mark(l_done)

    # ---------- value to string + string concatenation ----------

    def emit_jmp_if_false_rax(self, false_label: str) -> None:
        """Assumes cond Value in RAX. Jumps to false_label if cond is falsy."""
        a = self.asm

        # Create unique internal labels (this helper can be used many times)
        lid = self.new_label_id()
        l_int = f"truthy_int_{lid}"
        l_bool = f"truthy_bool_{lid}"
        l_end = f"truthy_end_{lid}"

        # r10 = rax ; r10 &= 7
        a.mov_r10_rax()
        a.and_r64_imm("r10", 7)  # and r10,7

        # if tag == INT
        a.cmp_r64_imm("r10", 1)  # cmp r10,1
        a.jcc('e', l_int)

        # if tag == BOOL
        a.cmp_r64_imm("r10", 2)  # cmp r10,2
        a.jcc('e', l_bool)

        # if tag == FLOAT => check numeric != 0.0
        l_immf = f"truthy_immf_{lid}"
        a.cmp_r64_imm("r10", TAG_FLOAT)
        a.jcc('e', l_immf)

        # if tag == PTR => check boxed string emptiness
        l_ptr = f"truthy_ptr_{lid}"
        a.cmp_r64_imm("r10", 0)  # cmp r10,0
        a.jcc('e', l_ptr)

        # if tag == VOID => false
        a.cmp_r64_imm("r10", 3)
        a.jcc('e', false_label)

        # otherwise: treat as true
        a.jmp(l_end)

        # --- int case ---
        a.mark(l_int)
        # false iff value == enc_int(0) == 1
        a.cmp_rax_imm8(1)
        a.jcc('e', false_label)
        a.jmp(l_end)

        # --- bool case ---
        a.mark(l_bool)
        # test rax, 8 (bit3)
        a.test_rax_imm32(8)
        a.jcc('z', false_label)
        a.jmp(l_end)

        # --- immediate float case ---
        a.mark(l_immf)
        self.emit_to_double_xmm(0, false_label)
        a.xorpd_xmm_xmm("xmm1", "xmm1")
        a.ucomisd_xmm_xmm("xmm0", "xmm1")
        a.jcc('e', false_label)
        a.jmp(l_end)

        # --- ptr case (boxed string / array) ---
        a.mark(l_ptr)
        # edx = [rax] (obj type)
        a.mov_r32_membase_disp("edx", "rax", 0)
        l_checklen = f"truthy_checklen_{lid}"
        l_float = f"truthy_float_{lid}"

        # if type == OBJ_FLOAT => check numeric != 0.0
        a.cmp_r32_imm("edx", OBJ_FLOAT)
        a.jcc('e', l_float)

        # if type == OBJ_STRING => check len
        a.cmp_r32_imm("edx", OBJ_STRING)
        a.jcc('e', l_checklen)
        # if type == OBJ_ARRAY  => check len
        a.cmp_r32_imm("edx", OBJ_ARRAY)
        a.jcc('e', l_checklen)

        # otherwise: unknown heap object => truthy
        a.jmp(l_end)

        # float case: falsy iff == 0.0
        a.mark(l_float)
        a.movsd_xmm_membase_disp("xmm0", "rax", 8)  # movsd xmm0,[rax+8]
        a.xorpd_xmm_xmm("xmm1", "xmm1")  # xorpd xmm1,xmm1
        a.ucomisd_xmm_xmm("xmm0", "xmm1")  # ucomisd xmm0,xmm1
        a.jcc('e', false_label)
        a.jmp(l_end)

        a.mark(l_checklen)
        # edx = [rax+4] (len)
        a.mov_r32_membase_disp("edx", "rax", 4)
        # test edx,edx
        a.test_r32_r32("edx", "edx")
        a.jcc('z', false_label)
        a.jmp(l_end)

        a.mark(l_end)

    # ---------- structs: shared field dispatch ----------

    def emit_struct_field_index_dispatch(self, field: str, *args, **kwargs) -> None:
        """Dispatch struct_id -> field index.

        After a struct object has been validated and its struct_id is in a 32-bit register
        (default: EDX), this helper emits a compare-chain and:
        - on match: sets OUT register (default: ECX) to the field index and jumps to ok_label
        - on miss: jumps to fail_label

        Supported call styles:
          emit_struct_field_index_dispatch(field, ok_label, fail_label)
          emit_struct_field_index_dispatch(field, struct_id_reg, ok_label, fail_label)
          emit_struct_field_index_dispatch(field, struct_id_reg, out_reg, ok_label, fail_label)

        Keyword args:
          struct_id_reg='edx', out_reg='ecx', ok_label=..., fail_label=..., tag='sfid'

        Note: ok_label/fail_label are required (accepts keyword aliases ok/fail for compatibility).
        """
        a = self.asm

        struct_id_reg = kwargs.get('struct_id_reg', 'edx')
        out_reg = kwargs.get('out_reg', 'ecx')
        # keyword aliases (older call sites used ok/fail)
        ok_label = kwargs.get('ok_label') or kwargs.get('ok') or kwargs.get('ok_lbl') or kwargs.get('oklabel')
        fail_label = kwargs.get('fail_label') or kwargs.get('fail') or kwargs.get('fail_lbl') or kwargs.get('faillabel')
        tag = kwargs.get('tag', 'sfid')

        # Positional arg forms
        if args:
            if len(args) == 2:
                ok_label, fail_label = args
            elif len(args) == 3:
                struct_id_reg, ok_label, fail_label = args
            elif len(args) == 4:
                struct_id_reg, out_reg, ok_label, fail_label = args
            else:
                raise ValueError('emit_struct_field_index_dispatch: bad argument count')

        if not ok_label or not fail_label:
            raise ValueError('emit_struct_field_index_dispatch requires ok_label/fail_label (or ok/fail)')

        pairs = []
        for sname, fields in self.struct_fields.items():
            try:
                fidx = fields.index(field)
            except ValueError:
                continue
            sid = self.struct_id.get(sname, 0)
            if sid:
                pairs.append((sid, fidx))

        if not pairs:
            a.jmp(fail_label)
            return

        lid = self.new_label_id()
        hit_labels = []
        for j, (sid, fidx) in enumerate(pairs):
            l_hit = f"{tag}_hit_{lid}_{j}"
            hit_labels.append((l_hit, fidx))
            a.cmp_r32_imm(struct_id_reg, sid)
            a.jcc('e', l_hit)

        a.jmp(fail_label)

        for l_hit, fidx in hit_labels:
            a.mark(l_hit)
            a.mov_r32_imm32(out_reg, fidx)
            a.jmp(ok_label)

    # Backwards/alternate name (handy for call sites)

    def emit_struct_field_dispatch(self, field: str, *args, **kwargs) -> None:
        self.emit_struct_field_index_dispatch(field, *args, **kwargs)

    # ---------- internal helper pruning ----------

    def reset_helper_tracking(self) -> None:
        if hasattr(self, 'used_helpers'):
            self.used_helpers.clear()
        if hasattr(self, '_emitted_helpers'):
            self._emitted_helpers.clear()

    def emit_used_helpers(self) -> None:
        """Emit only the internal runtime helpers that were referenced (fn_*)."""
        emitters = {'fn_int_to_dec': getattr(self, 'emit_int_to_dec_function', None),
            'fn_cpu_init': getattr(self, 'emit_cpu_init_function', None),
            'fn_strlen': getattr(self, 'emit_strlen_function', None),
            'fn_alloc': getattr(self, 'emit_alloc_function', None),
            'fn_init_argvw': getattr(self, 'emit_init_argvw_function', None),
            'fn_build_args': getattr(self, 'emit_build_args_function', None),
            'fn_incref': getattr(self, 'emit_incref_function', None),
            'fn_decref': getattr(self, 'emit_decref_function', None),
            'fn_input': getattr(self, 'emit_input_function', None),
            'fn_toNumber': getattr(self, 'emit_toNumber_function', None),
            'fn_typeof': getattr(self, 'emit_typeof_function', None),
            'fn_typeName': getattr(self, 'emit_typeName_function', None),
            'fn_unhandled_error_exit': getattr(self, 'emit_unhandled_error_exit_function', None),
            'fn_heap_count': getattr(self, 'emit_heap_count_function', None),
            'fn_heap_bytes_used': getattr(self, 'emit_heap_bytes_used_function', None),
            'fn_heap_bytes_committed': getattr(self, 'emit_heap_bytes_committed_function', None),
            'fn_heap_bytes_reserved': getattr(self, 'emit_heap_bytes_reserved_function', None),
            'fn_heap_free_bytes': getattr(self, 'emit_heap_free_bytes_function', None),
            'fn_heap_free_blocks': getattr(self, 'emit_heap_free_blocks_function', None),
            'fn_heap_grow': getattr(self, 'emit_heap_grow_function', None),
            'fn_gc_collect': getattr(self, 'emit_gc_collect_function', None),
            'fn_mem_eq_bytes': getattr(self, 'emit_mem_eq_bytes_function', None),
            'fn_scan_nul_bytes': getattr(self, 'emit_scan_nul_bytes_function', None),
            'fn_scan_byte2_bytes': getattr(self, 'emit_scan_byte2_bytes_function', None),
            'fn_scan_nul_wchars': getattr(self, 'emit_scan_nul_wchars_function', None),
            'fn_copy_bytes': getattr(self, 'emit_copy_bytes_function', None),
            'fn_fill_bytes': getattr(self, 'emit_fill_bytes_function', None),
            'fn_fill_qwords': getattr(self, 'emit_fill_qwords_function', None),
            'fn_box_float': getattr(self, 'emit_box_float_function', None),
            'fn_value_to_string': getattr(self, 'emit_value_to_string_function', None),
            'fn_str_eq': getattr(self, 'emit_string_eq_function', None),
            'fn_val_eq': getattr(self, 'emit_value_eq_function', None),
            'fn_add_string': getattr(self, 'emit_string_add_function', None),
            'fn_add_array': getattr(self, 'emit_array_add_function', None),
            'fn_bytes_alloc': getattr(self, 'emit_bytes_alloc_function', None),
            'fn_add_bytes': getattr(self, 'emit_bytes_add_function', None),
            'fn_bytes_eq': getattr(self, 'emit_bytes_eq_function', None),
            'fn_decode': getattr(self, 'emit_decode_function', None),
            'fn_decodeZ': getattr(self, 'emit_decodeZ_function', None),
            'fn_decode16Z': getattr(self, 'emit_decode16Z_function', None),
            'fn_hex': getattr(self, 'emit_hex_function', None),
            'fn_fromHex': getattr(self, 'emit_fromHex_function', None),
            'fn_slice': getattr(self, 'emit_slice_function', None),
            'fn_callStats': getattr(self, 'emit_callStats_function', None),

            # Step 5: first-class builtin function values
            'fn_builtin_len': getattr(self, 'emit_builtin_len_function', None),
            'fn_builtin_input': getattr(self, 'emit_builtin_input_function', None),
            'fn_builtin_copyBytes': getattr(self, 'emit_builtin_copyBytes_function', None),
            'fn_builtin_fillBytes': getattr(self, 'emit_builtin_fillBytes_function', None),
            'fn_builtin_gc_collect': getattr(self, 'emit_builtin_gc_collect_function', None),
            'fn_builtin_gc_set_limit': getattr(self, 'emit_builtin_gc_set_limit_function', None), }

        used = getattr(self, 'used_helpers', set())
        emitted = getattr(self, '_emitted_helpers', set())

        pending = set(used) - set(emitted)

        while pending:
            lbl = pending.pop()
            if lbl in emitted:
                continue

            fn = emitters.get(lbl)
            if fn is None:
                raise self.error(f"Unknown internal helper referenced: {lbl}")

            emitted.add(lbl)
            fn()

            used_now = getattr(self, 'used_helpers', set())
            pending |= set(used_now) - set(emitted)

        # persist
        self._emitted_helpers = emitted
