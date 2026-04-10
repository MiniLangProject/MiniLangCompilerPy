"""
Scope support for MiniLang native codegen.

This module is intentionally self-contained: it contains all state and logic
related to lexical scopes, variable bindings, shadowing, and compile-time
"Undefined variable" errors.

Key semantics (agreed):
- Variables become visible on their first write in the current lexical block.
- Reads of variables that have never been written in any visible scope => CompileError.
- Shadowing is allowed (each declaration site gets a distinct binding).
- Inside functions: writes NEVER implicitly update globals; they create/target locals instead.
- Loop variables (for/foreach) are "fresh" bindings and must not clobber outer variables.
- Scope cleanup on exit: bindings introduced in a scope are written to TAG_VOID so GC
  doesn't keep them alive.
- IMPORTANT: emit_cleanup_to_depth() must NOT mutate compiler scope stacks; it only emits
  runtime cleanup for control-flow jumps (break/continue/return).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import re

from ..tools import enc_void
from ..constants import ERR_MODULE_INIT_CYCLE, OBJ_ENV_LOCAL


def _sanitize_ident(name: str) -> str:
    """
    Sanitize an identifier so it can safely be used in labels.

    MiniLang identifiers may contain characters that are not valid for assembler labels.
    We replace unsupported characters with '_' and ensure the identifier does not start
    with a digit.

    Args:
        name: Raw identifier.

    Returns:
        A label-safe identifier string.
    """

    out = []
    for ch in name:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        else:
            out.append("_")
    s = "".join(out) or "v"
    if s[0].isdigit():
        s = "_" + s
    return s


@dataclass
class VarBinding:
    id: int
    name: str
    kind: str  # "global" | "local" | "param"
    label: Optional[str]
    offset: Optional[int]
    depth: int
    boxed: bool = False  # slot stores cell ptr; value is in cell
    capture_depth: int = 0  # number of parent hops in env chain
    capture_index: int | None = None  # slot index in the resolved env frame
    decl_node: Any = None

    # Const bindings: immutable after first init
    is_const: bool = False
    const_expr: Any = None
    const_initialized: bool = False

    # Const compile-time value: used for inlining and constexpr resolution
    const_value_py: Any = None
    const_value_encoded: int | None = None
    const_value_label: str | None = None


class CodegenScope:
    # --------- setup ---------

    def scope_setup(self) -> None:
        # Visible bindings per lexical scope (stack of dicts)
        """
        Initialize internal scope tracking structures.

        This is called once during codegen initialization to set up the lexical-scope stacks,
        binding ids, and global slot tracking.
        """

        self._scope_stack: List[Dict[str, VarBinding]] = [{}]
        # Bindings introduced per lexical scope (for cleanup)
        self._scope_declared: List[List[VarBinding]] = [[]]

        self._binding_id: int = 0

        # Track every global slot label we ever allocate (GC root scan)
        self._global_slots: List[str] = []
        # Convenience mapping for root-level globals
        self._globals: Dict[str, VarBinding] = {}

        # Decl-site bindings (per function, populated by analysis)
        self._decl_site_bindings: Dict[Tuple[int, str], VarBinding] = {}
        # Names of globals explicitly declared via `global x` inside the current function.
        # Only these globals are visible from functions (both read & write).
        self._func_globals: set[str] = set()
        # Map of local name to qualified global name (for global inside namespaces).
        self._func_global_map: Dict[str, str] = {}

        # Function-local bindings declared/used (for frame layout + init)
        self._function_locals: List[VarBinding] = []
        self._function_local_ids: set[int] = set()

        # Qualified-name prefix for implicit resolution inside the current function/namespace.
        # Example: when compiling function std.time.win32.sleep, this is 'std.time.win32.'
        self.current_qname_prefix: str = ''

    @property
    def scope_depth(self) -> int:
        """
        Return the current lexical scope depth.

        Depth 0 refers to the global scope; each pushed block increases depth by 1.
        """

        return len(self._scope_stack) - 1

    @property
    def scope_global_slots(self) -> List[str]:
        # Labels of qword .data slots backing global bindings
        """
        Return labels of all global variable slots.

        These labels back global bindings in the .data section and are used for GC root scanning.
        """

        return list(self._global_slots)

    # --------- name normalization ---------

    def _coerce_name(self, name: object) -> str:
        """Normalize frontend identifier representations to a plain string.

        We see identifiers as:
          - str
          - AST node with .name
          - token with .value/.text/.lexeme
          - nested tokens, tuples, objects with __dict__/__slots__
        We also avoid returning token-kind strings like IDENT where possible.
        """
        if isinstance(name, str):
            return name

        stop = {
            "IDENT", "IDENTIFIER", "NAME", "Token", "VAR", "KIND", "TOK", "TOKEN",
            "Var", "Name", "Id", "ID"
        }

        def is_ident(s: str) -> bool:
            """Is ident.

            Args:
                s:
            """

            return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s))

        def accept(s: str) -> bool:
            """Accept.

            Args:
                s:
            """

            return bool(s) and is_ident(s) and s not in stop

        def search(obj, depth: int) -> Optional[str]:
            """Search.

            Args:
                obj:
                depth:
            """

            if obj is None or depth < 0:
                return None
            if isinstance(obj, str):
                return obj if accept(obj) else None

            # prefer lexeme-like attributes
            for attr in ("value", "text", "lexeme", "ident", "id", "var", "s"):
                v = getattr(obj, attr, None)
                if isinstance(v, str) and accept(v):
                    return v
                if v is not None and v is not obj:
                    r = search(v, depth - 1)
                    if r:
                        return r

            # then name
            v = getattr(obj, "name", None)
            if isinstance(v, str) and accept(v):
                return v
            if v is not None and v is not obj:
                r = search(v, depth - 1)
                if r:
                    return r

            # containers
            if isinstance(obj, dict):
                for vv in obj.values():
                    r = search(vv, depth - 1)
                    if r:
                        return r
            elif isinstance(obj, (list, tuple, set)):
                for vv in obj:
                    r = search(vv, depth - 1)
                    if r:
                        return r

            # sequence-like (namedtuple/custom token)
            try:
                ln = len(obj)  # type: ignore
                if isinstance(ln, int) and 0 < ln <= 8:
                    for i in range(ln):
                        try:
                            vv = obj[i]  # type: ignore
                        except Exception:
                            break
                        r = search(vv, depth - 1)
                        if r:
                            return r
            except Exception:
                pass

            # __slots__
            slots = getattr(obj, "__slots__", None)
            if isinstance(slots, (list, tuple)):
                for s in slots:
                    if not isinstance(s, str):
                        continue
                    try:
                        vv = getattr(obj, s)
                    except Exception:
                        continue
                    r = search(vv, depth - 1)
                    if r:
                        return r

            d = getattr(obj, "__dict__", None)
            if isinstance(d, dict):
                for vv in d.values():
                    r = search(vv, depth - 1)
                    if r:
                        return r
            return None

        r = search(name, 4)
        if r:
            return r

        # Fallback: parse repr/str and take the last acceptable identifier
        try:
            rep = repr(name)
        except Exception:
            rep = ""
        if not rep:
            try:
                rep = str(name)
            except Exception:
                rep = ""

        # quoted candidates first
        for m in re.finditer(r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]", rep):
            cand = m.group(1)
            if accept(cand):
                return cand

        toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", rep)
        for cand in reversed(toks):
            if accept(cand):
                return cand
        if toks:
            return toks[-1]
        return str(name)

    # --------- scopes ---------

    def push_scope(self) -> None:
        """
        Enter a new lexical scope.

        Creates a fresh visible-binding dictionary and a list that tracks bindings introduced
        in this scope (for cleanup on exit).
        """

        self._scope_stack.append({})
        self._scope_declared.append([])

    def pop_scope(self, *, emit_cleanup: bool = True) -> None:
        """
        Exit the current lexical scope.

        Args:
            emit_cleanup: If True, emit runtime writes that clear (TAG_VOID) bindings introduced
                in the scope so the GC does not retain them.
        """

        if len(self._scope_stack) <= 1:
            return
        if emit_cleanup:
            bindings = self._scope_declared[-1]
            if bindings:
                self.emit_cleanup_bindings(bindings)
        self._scope_stack.pop()
        self._scope_declared.pop()

    # --------- bindings ---------

    def _next_binding_id(self) -> int:
        """
        Allocate a fresh binding id.

        Binding ids disambiguate shadowed declarations that share the same source name.

        Returns:
            A monotonically increasing integer id.
        """

        self._binding_id += 1
        return self._binding_id

    def _decl_key(self, node: Any, name: object) -> Tuple[int, str]:
        """
        Create a stable key for declaration-site binding caching.

        Args:
            node: AST node representing the declaration site.
            name: Identifier at that site.

        Returns:
            A string key used in the internal decl-site binding map.
        """

        return (id(node), self._coerce_name(name))

    def resolve_binding(self, name: object) -> Optional[VarBinding]:
        """
        Resolve an identifier for reads.

        Args:
            name: Identifier (string or AST node) to resolve.

        Returns:
            The nearest visible VarBinding, or None if the name is unknown in all visible scopes.
        """

        name = self._coerce_name(name)
        for scope in reversed(self._scope_stack):
            b = scope.get(name)
            if b is None:
                continue
            return b
        return None

    def resolve_binding_for_write(self, name: object) -> Optional[VarBinding]:
        """
        Resolve an identifier for writes.

        Inside functions, unqualified writes do not implicitly target globals: writing to a global
        requires an explicit `global x` declaration (or a qualified name containing a dot).

        Args:
            name: Identifier (string or AST node) to resolve.

        Returns:
            The VarBinding that should be written to, or None if no binding exists yet.
        """

        name = self._coerce_name(name)
        in_fn = bool(getattr(self, "in_function", False))
        func_globals = getattr(self, "_func_globals", set())
        for scope in reversed(self._scope_stack):
            b = scope.get(name)
            if b is None:
                continue
            if in_fn and getattr(b, "kind", None) == "global":
                # Only allow writing to *unqualified* globals explicitly declared via `global x`.
                # Qualified names (contain a dot) are explicit and may always be written.
                if "." not in name:
                    if not (isinstance(func_globals, set) and name in func_globals):
                        continue
            return b
        return None

    def _add_binding_to_current_scope(self, b: VarBinding) -> None:
        """
        Register a binding in the current (innermost) scope.

        Also tracks the binding for later cleanup (unless it is a parameter).
        """

        self._scope_stack[-1][b.name] = b
        self._scope_declared[-1].append(b)

        if b.kind == "global":
            # track for GC scanning
            if b.label:
                self._global_slots.append(b.label)
            if self.scope_depth == 0:
                self._globals[b.name] = b

        if b.kind == "local" and bool(getattr(self, "in_function", False)):
            if b.id not in self._function_local_ids:
                self._function_local_ids.add(b.id)
                self._function_locals.append(b)

    # --------- reserved identifiers ---------

    def _check_reserved_ident(self, name_s: str, node: Any = None) -> None:
        """
        Validate that an identifier is not reserved.

        Args:
            name: Normalized identifier.
            node: Optional AST node for better error locations.

        Raises:
            CompileError: If the name is reserved (e.g. internal runtime identifiers).
        """

        reserved = getattr(self, 'reserved_identifiers', set())
        if isinstance(reserved, set) and name_s in reserved:
            raise self.error(f"Identifier '{name_s}' is reserved", node)

    def declare_global_binding(self, name: object, *, node: Any = None) -> VarBinding:
        """
        Declare a new global binding in the current scope.

        Allocates a .data slot and registers the resulting VarBinding.

        Args:
            name: Identifier to declare.
            node: Optional AST node for diagnostics.

        Returns:
            The created VarBinding.
        """

        name_s = self._coerce_name(name)
        self._check_reserved_ident(name_s, node)
        bid = self._next_binding_id()
        label = f"g_{_sanitize_ident(name_s)}_{bid}"
        # host provides self.data.add_u64
        self.data.add_u64(label, enc_void())
        b = VarBinding(id=bid, name=name_s, kind="global", label=label, offset=None, depth=self.scope_depth, decl_node=node)
        self._add_binding_to_current_scope(b)
        return b

    def declare_global_binding_root(self, name: object, *, node: Any = None) -> VarBinding:
        """Declare (or reuse) a global binding in the *root/global* scope (depth 0).

        This is used for features like `global x` inside functions, where we want to
        ensure a global slot exists even if we're currently in function mode (where
        scope depth is > 0 due to the function-local root scope).

        If a root binding with the same name already exists, it is returned.
        """

        name_s = self._coerce_name(name)
        self._check_reserved_ident(name_s, node)

        # Reuse existing root/global binding if present.
        try:
            b0 = self._scope_stack[0].get(name_s)
        except Exception:
            b0 = None
        if b0 is not None and getattr(b0, 'kind', None) == 'global' and getattr(b0, 'depth', 0) == 0:
            return b0

        bid = self._next_binding_id()
        label = f"g_{_sanitize_ident(name_s)}_{bid}"
        # host provides self.data.add_u64
        self.data.add_u64(label, enc_void())

        b = VarBinding(id=bid, name=name_s, kind="global", label=label, offset=None, depth=0, decl_node=node)

        # Register in root scope + tracking (mirror _add_binding_to_current_scope for depth 0).
        if not hasattr(self, "_scope_stack") or not self._scope_stack:
            raise self.error("Internal error: scope stack not initialized", node)
        self._scope_stack[0][name_s] = b
        if hasattr(self, "_scope_declared") and self._scope_declared:
            self._scope_declared[0].append(b)

        if b.label:
            self._global_slots.append(b.label)
        self._globals[name_s] = b

        return b

    def declare_local_binding(self, name: object, *, node: Any = None, offset: Optional[int] = None) -> VarBinding:
        """
        Declare a new local binding in the current scope.

        Args:
            name: Identifier to declare.
            node: Optional AST node for diagnostics.
            offset: Optional stack offset (if already allocated).

        Returns:
            The created VarBinding.
        """

        name_s = self._coerce_name(name)
        self._check_reserved_ident(name_s, node)
        bid = self._next_binding_id()
        b = VarBinding(id=bid, name=name_s, kind="local", label=None, offset=offset, depth=self.scope_depth, decl_node=node)
        self._add_binding_to_current_scope(b)
        return b

    def declare_fresh_binding(self, name: object, *, node: Any) -> VarBinding:
        """Declare a fresh binding in current scope, even if an outer binding exists."""
        name_s = self._coerce_name(name)
        self._check_reserved_ident(name_s, node)
        key = self._decl_key(node, name_s)
        pre = self._decl_site_bindings.get(key)
        if pre is not None:
            self._add_binding_to_current_scope(pre)
            return pre
        if bool(getattr(self, "in_function", False)):
            return self.declare_local_binding(name_s, node=node, offset=None)
        return self.declare_global_binding(name_s, node=node)

    def bind_param(self, name: object, offset: int, *, node: Any = None) -> VarBinding:
        """
        Bind a function parameter to a stack offset.

        Parameters are visible within the function scope but are not included in cleanup.

        Args:
            name: Parameter name.
            offset: Stack offset where the parameter is stored.
            node: Optional AST node for diagnostics.

        Returns:
            The created VarBinding.
        """

        name_s = self._coerce_name(name)
        self._check_reserved_ident(name_s, node)
        bid = self._next_binding_id()
        b = VarBinding(id=bid, name=name_s, kind="param", label=None, offset=offset, depth=self.scope_depth, decl_node=node)
        # Parameters are visible but not cleaned up.
        self._scope_stack[-1][name_s] = b
        return b

    def register_decl_site_binding(self, node: Any, name: object, binding: VarBinding) -> None:
        """
        Cache the VarBinding for a declaration site.

        Some frontend nodes refer back to their declaration site; this mapping allows stable
        resolution even in the presence of shadowing.
        """

        self._decl_site_bindings[self._decl_key(node, name)] = binding

    def ensure_binding_for_write(self, name: object, *, node: Any) -> VarBinding:
        """
        Ensure a binding exists for a write operation.

        If a visible binding exists and is writable under the current rules, it is returned.
        Otherwise a new local/global binding is created according to the current context.

        Args:
            name: Identifier being assigned.
            node: AST node for diagnostics.

        Returns:
            A VarBinding suitable for storing into.
        """

        name_s = self._coerce_name(name)
        self._check_reserved_ident(name_s, node)

        # allow `global x` inside namespaced functions to map an unqualified
        # local name to a qualified global binding (e.g. std.fs.x).
        if bool(getattr(self, 'in_function', False)):
            gm = getattr(self, '_func_global_map', None)
            if isinstance(gm, dict) and name_s in gm:
                gname = gm.get(name_s)
                b = None
                try:
                    b = self._globals.get(gname)
                except Exception:
                    b = None
                if b is None:
                    try:
                        b = self._scope_stack[0].get(gname)
                    except Exception:
                        b = None
                if b is None or getattr(b, 'kind', None) != 'global' or getattr(b, 'depth', 0) != 0:
                    # Step 7.1b: `global x` can declare a package/file-global even
                    # if it wasn't written at top-level.
                    b = self.declare_global_binding_root(gname, node=node)
                return b

        existing = self.resolve_binding_for_write(name_s)
        if existing is not None:
            return existing

        key = self._decl_key(node, name_s)
        pre = self._decl_site_bindings.get(key)
        if pre is not None:
            self._add_binding_to_current_scope(pre)
            return pre

        if bool(getattr(self, "in_function", False)):
            return self.declare_local_binding(name_s, node=node, offset=None)
        return self.declare_global_binding(name_s, node=node)

    # --------- cleanup emission ---------

    def emit_cleanup_bindings(self, bindings: List[VarBinding]) -> None:
        """
        Emit runtime cleanup for a list of bindings.

        This writes TAG_VOID into the storage locations backing each binding (locals on stack,
        globals in .data), preventing the GC from retaining unreachable values.
        """

        a = self.asm
        voidv = enc_void()
        for b in bindings:
            if b.kind == "param":
                continue
            if b.kind == "local":
                if b.offset is None:
                    continue
                a.mov_membase_disp_imm32("rsp", b.offset, voidv, qword=True)
            elif b.kind == "global":
                if b.label is None:
                    continue
                a.mov_r64_imm64('r11', voidv)
                a.mov_rip_qword_r11(b.label)

    def emit_cleanup_to_depth(self, target_depth: int) -> None:
        """Emit cleanup for scopes deeper than target_depth WITHOUT mutating state."""
        if target_depth < 0:
            target_depth = 0
        cur = self.scope_depth
        if target_depth >= cur:
            return
        for d in range(cur, target_depth, -1):
            bindings = self._scope_declared[d]
            if bindings:
                self.emit_cleanup_bindings(bindings)

    # --------- scoped load/store ---------

    def _emit_module_init_dependency_error(self, *, target_name: str, target_file: str, target_state: int, node: Any = None) -> None:
        """Abort with a clean runtime diagnostic for illegal module-init global reads."""
        state_txt = 'initializing' if int(target_state) == 1 else 'not initialized'
        cur_file = getattr(self, '_module_init_active_file', None)
        cur_disp = str(cur_file) if isinstance(cur_file, str) and cur_file else '<entry>'
        tgt_disp = str(target_file) if isinstance(target_file, str) and target_file else '<unknown>'
        msg = (
            f"Cyclic/invalid module initialization dependency while reading '{target_name}': "
            f"module '{tgt_disp}' is {state_txt} (from '{cur_disp}')"
        )
        if hasattr(self, '_emit_make_error_const') and callable(getattr(self, '_emit_make_error_const')):
            self._emit_make_error_const(ERR_MODULE_INIT_CYCLE, msg)
            self.asm.mov_r64_r64('rcx', 'rax')
            self.asm.call('fn_unhandled_error_exit')
            return
        raise self.error(msg, node)

    def _maybe_emit_module_init_guard_for_global_read(self, binding: VarBinding, *, target_name: str, node: Any = None) -> None:
        """Guard cross-module global reads during top-level module initialization.

        Allowed:
        - reads outside module-init emission
        - reads of globals owned by the current module
        - reads of globals from modules whose init status is INITIALIZED (2)

        Illegal and diagnosed:
        - reads from a module still INITIALIZING (1)
        - reads from a module not yet INITIALIZED (0)
        """
        if not bool(getattr(self, '_module_init_active', False)):
            return
        owner_map = getattr(self, '_global_owner_file', None) or {}
        if not isinstance(owner_map, dict):
            return
        tgt_file = owner_map.get(str(target_name))
        if not (isinstance(tgt_file, str) and tgt_file):
            return
        cur_file = getattr(self, '_module_init_active_file', None)
        if isinstance(cur_file, str) and cur_file == tgt_file:
            return
        status_map = getattr(self, '_module_init_status_labels', None) or {}
        if not isinstance(status_map, dict):
            return
        status_lbl = status_map.get(tgt_file)
        if not (isinstance(status_lbl, str) and status_lbl):
            return

        a = self.asm
        ok_lbl = f"lbl_modinit_read_ok_{getattr(self, 'new_label_id')()}"
        a.mov_rax_rip_qword(status_lbl)
        a.cmp_rax_imm8(2)
        a.jcc('e', ok_lbl)
        # 0 = uninitialized, 1 = initializing. Both are illegal to read across modules
        # while top-level init is still running; 1 is the true cycle case, 0 is a forward
        # dependency into a module that has not run yet.
        state_txt_lbl = f"{status_lbl}"  # keep Python-side state for the message below
        # Determine the current state value conservatively for the diagnostic text.
        # The runtime branch only reaches here for 0 or 1. We do not need the exact value
        # in machine state afterwards because fn_unhandled_error_exit does not return.
        # Use a tiny split so the message is specific.
        st_init_lbl = f"lbl_modinit_read_initializing_{getattr(self, 'new_label_id')()}"
        st_after_lbl = f"lbl_modinit_read_state_after_{getattr(self, 'new_label_id')()}"
        a.cmp_rax_imm8(1)
        a.jcc('e', st_init_lbl)
        self._emit_module_init_dependency_error(target_name=str(target_name), target_file=tgt_file, target_state=0, node=node)
        a.jmp(st_after_lbl)
        a.mark(st_init_lbl)
        self._emit_module_init_dependency_error(target_name=str(target_name), target_file=tgt_file, target_state=1, node=node)
        a.mark(st_after_lbl)
        a.mark(ok_lbl)

    def emit_load_var_scoped(self, name: object, node: Any = None) -> None:
        """
        Emit code that loads a variable into the value register.

        Args:
            name: Identifier to load.
            node: Optional AST node for diagnostics.

        Raises:
            CompileError: If the identifier is undefined in all visible scopes.
        """

        name_s = self._coerce_name(name)
        a = self.asm

        # if `global x` inside the current function mapped x -> qualified global,
        # resolve reads of x to that global binding.
        if bool(getattr(self, 'in_function', False)):
            gm = getattr(self, '_func_global_map', None)
            if isinstance(gm, dict) and name_s in gm:
                mapped = gm.get(name_s)
                bb = self.resolve_binding(mapped)
                if bb is not None:
                    b = bb
                else:
                    b = None
            else:
                b = self.resolve_binding(name_s)
        else:
            b = self.resolve_binding(name_s)

        # Implicit qualification helpers (package + namespace/function prefix).
        #
        # Declarations in `package X` files are qualified as `X.<name>`.
        # Declarations inside `namespace Y` become `X.Y.<name>` (or `Y.<name>` without package).
        #
        # For ergonomics, allow unqualified references to resolve within:
        #   1) the current function's qualified prefix (package+namespace)
        #   2) the current file's package prefix
        #   3) if still not found: a unique symbol in the same package that ends with ".<name>"
        if b is None and '.' not in name_s:
            # (1) function/namespace prefix
            qpref = getattr(self, 'current_qname_prefix', '') or ''
            if isinstance(qpref, str) and qpref:
                if not qpref.endswith('.'):
                    qpref = qpref + '.'
                b = self.resolve_binding(qpref + name_s)

        if b is None and '.' not in name_s:
            # (2) file/package prefix
            fpref = getattr(self, 'current_file_prefix', '') or ''
            if isinstance(fpref, str) and fpref:
                if not fpref.endswith('.'):
                    fpref = fpref + '.'
                b = self.resolve_binding(fpref + name_s)


        if b is None:
            raise self.error(f"Undefined variable '{name_s}'", node)

        # inline compile-time constants (no memory load)
        if getattr(b, 'is_const', False):
            enc = getattr(b, 'const_value_encoded', None)
            if isinstance(enc, int):
                a.mov_rax_imm64(int(enc))
                return
            lbl = getattr(b, 'const_value_label', None)
            if isinstance(lbl, str) and lbl:
                a.lea_rax_rip(lbl)
                return

        # Closure capture (prep in 6.2b-1): captured vars are accessed via current env in r15.
        # Env layout is defined in 6.2b-2; here we assume:
        #   [env+8]  = parent env pointer (Value)
        #   [env+16] = first slot (Value), then qwords
        if getattr(b, 'kind', None) == 'capture' or getattr(b, 'capture_index', None) is not None:
            depth = int(getattr(b, 'capture_depth', 0) or 0)
            idx = getattr(b, 'capture_index', None)
            if idx is None:
                raise self.error(f"Internal error: capture missing index for '{name_s}'", node)
            a.mov_r64_r64('r11', 'r15')  # r11 = current env
            for _ in range(depth):
                a.mov_r64_membase_disp('r11', 'r11', 8)  # parent
            lid = self.new_label_id()
            l_cap_full = f"cap_load_full_{lid}"
            l_cap_done = f"cap_load_done_{lid}"
            a.mov_r32_membase_disp('r10d', 'r11', 0)
            a.cmp_r32_imm('r10d', OBJ_ENV_LOCAL)
            a.jcc('ne', l_cap_full)
            a.mov_r64_membase_disp('r11', 'r11', 8 + int(idx) * 8)  # cell ptr
            a.jmp(l_cap_done)
            a.mark(l_cap_full)
            a.mov_r64_membase_disp('r11', 'r11', 16 + int(idx) * 8)  # cell ptr
            a.mark(l_cap_done)
            a.mov_r64_membase_disp('rax', 'r11', 8)  # cell[0]
            return

        if b.kind in ("param", "local"):
            if b.offset is None:
                raise self.error(f"Internal error: unresolved stack slot for '{name_s}'", node)
            a.mov_rax_rsp_disp32(b.offset)
            # boxed local/param: slot contains cell pointer; load cell[0]
            if getattr(b, 'boxed', False):
                a.mov_r64_membase_disp('rax', 'rax', 8)
            return

        if b.kind == "global":
            if b.label is None:
                raise self.error(f"Internal error: missing global label for '{name_s}'", node)
            self._maybe_emit_module_init_guard_for_global_read(b, target_name=name_s, node=node)
            a.mov_rax_rip_qword(b.label)
            return

        raise self.error(f"Internal error: unknown binding kind for '{name_s}'", node)

    def emit_store_var_scoped(self, name: object, node: Any) -> None:
        """
        Emit code that stores the value register into a variable slot.

        Performs binding creation (if needed), const assignment checks, and writes to the correct
        storage location (stack or global slot).

        Args:
            name: Identifier to assign.
            node: AST node for diagnostics and const-decl detection.
        """

        name_s = self._coerce_name(name)
        a = self.asm
        b = self.ensure_binding_for_write(name_s, node=node)

        # Inline expansion support:
        # When emitting an inlined function body we cannot rely on the caller's
        # function-frame layout to provide stack slots for *new* bindings.
        # In that mode, allocate a persistent slot in the expression-temp arena
        # on first store.
        if b.kind in ("param", "local") and b.offset is None:
            if bool(getattr(self, "_inline_alloc_enabled", False)):
                # Captured/boxed variables require env/box setup that is handled
                # in the real function prologue. Keep this explicit for now.
                if bool(getattr(b, "boxed", False)) or getattr(b, "capture_index", None) is not None or getattr(b,
                                                                                                                  "kind",
                                                                                                                  None) == "capture":
                    raise self.error(
                        f"inline expansion: captured/boxed variable '{name_s}' is not supported", node)
                b.offset = self.alloc_expr_temps(8)
            else:
                raise self.error(f"Internal error: unresolved stack slot for '{name_s}'", node)

        # Const protection: allow a single initialization via `const name = expr`.
        if getattr(b, 'is_const', False):
            allow_init = (type(node).__name__ == 'ConstDecl') and (not getattr(b, 'const_initialized', False))
            if not allow_init:
                raise self.error(f"Cannot assign to const '{name_s}'", node)
            # Mark initialized now (safe because store cannot fail after this point).
            b.const_initialized = True


        # Closure capture (prep in 6.2b-1): store through current env in r15.
        if getattr(b, 'kind', None) == 'capture' or getattr(b, 'capture_index', None) is not None:
            depth = int(getattr(b, 'capture_depth', 0) or 0)
            idx = getattr(b, 'capture_index', None)
            if idx is None:
                raise self.error(f"Internal error: capture missing index for '{name_s}'", node)
            a.mov_r64_r64('r11', 'r15')  # r11 = current env
            for _ in range(depth):
                a.mov_r64_membase_disp('r11', 'r11', 8)  # parent
            lid = self.new_label_id()
            l_cap_full = f"cap_store_full_{lid}"
            l_cap_done = f"cap_store_done_{lid}"
            a.mov_r32_membase_disp('r10d', 'r11', 0)
            a.cmp_r32_imm('r10d', OBJ_ENV_LOCAL)
            a.jcc('ne', l_cap_full)
            a.mov_r64_membase_disp('r11', 'r11', 8 + int(idx) * 8)  # cell ptr
            a.jmp(l_cap_done)
            a.mark(l_cap_full)
            a.mov_r64_membase_disp('r11', 'r11', 16 + int(idx) * 8)  # cell ptr
            a.mark(l_cap_done)
            a.mov_membase_disp_r64('r11', 8, 'rax')  # cell[0] = value
            return
        if b.kind in ("param", "local"):
            if b.offset is None:
                raise self.error(f"Internal error: unresolved stack slot for '{name_s}'", node)
            # boxed local/param: slot holds cell pointer; write into cell[0]
            if getattr(b, 'boxed', False):
                a.mov_r64_membase_disp('r11', 'rsp', b.offset)
                a.mov_membase_disp_r64('r11', 8, 'rax')
                return
            a.mov_rsp_disp32_rax(b.offset)
            return

        if b.kind == "global":
            if b.label is None:
                raise self.error(f"Internal error: missing global label for '{name_s}'", node)
            a.mov_rip_qword_rax(b.label)
            return

        raise self.error(f"Internal error: unknown binding kind for '{name_s}'", node)


    def emit_store_existing_global(self, name: object, node: Any) -> None:
        """Store RAX into an already-declared global binding (no implicit creation).

        This is used for explicit qualified writes like `std.fs.x = ...` (parsed as SetMember)
        where we want to bypass the function-local write rules.
        """
        name_s = self._coerce_name(name)
        b = self.resolve_binding(name_s)
        if b is None or getattr(b, 'kind', None) != 'global':
            raise self.error(f"Undefined global variable '{name_s}'", node)
        if getattr(b, 'is_const', False):
            raise self.error(f"Cannot assign to const '{name_s}'", node)
        lbl = getattr(b, 'label', None)
        if not isinstance(lbl, str) or not lbl:
            raise self.error(f"Internal error: missing global label for '{name_s}'", node)
        self.asm.mov_rip_qword_rax(lbl)

    # --------- analysis helpers (required by codegen_stmt integration) ---------

    def analysis_reset_function(self) -> None:
        """Reset per-function analysis state."""
        self._decl_site_bindings = {}
        self._function_locals = []
        self._function_local_ids = set()
        self._func_globals = set()
        self._func_global_map = {}

    def analysis_layout_function_locals(self, base_offset: int) -> None:
        """Assign stack offsets to all function locals without offsets."""
        off = base_offset
        for b in self._function_locals:
            if b.kind != "local":
                continue
            if b.offset is None:
                b.offset = off
                off += 8

    def declare_function_global(self, name: object, *, node: Any = None) -> VarBinding:
        """Declare that `name` refers to an EXISTING global inside the current function.

        extension:
        - Inside namespaced/package-qualified functions, `global x` may refer to
          an existing qualified global like `std.fs.x` (searched in this order):
            1) current function/namespace prefix
            2) current file/package prefix
            3) root/global `x`
        - Qualified names passed to `global` are accepted as-is.

        Notes:
        - This is a compile-time directive only; it emits no runtime code.
        - If the referenced global does not exist yet, it is created in the root
          scope (default-initialized to VOID).
        """
        name_s = self._coerce_name(name)
        self._check_reserved_ident(name_s, node)
        if not bool(getattr(self, 'in_function', False)):
            raise self.error("'global' is only allowed inside functions", node)

        # Disallow global declaration if a local/param/capture with the same name is already visible.
        try:
            existing = self.resolve_binding(name_s)
        except Exception:
            existing = None
        if existing is not None:
            k = getattr(existing, 'kind', None)
            if k in ('local', 'param') or getattr(existing, 'capture_index', None) is not None or k == 'capture':
                raise self.error(f"global '{name_s}' conflicts with an existing local/param binding", node)

        candidates = []
        if '.' in name_s:
            candidates = [name_s]
        else:
            qpref = getattr(self, 'current_qname_prefix', '') or ''
            if isinstance(qpref, str) and qpref:
                if not qpref.endswith('.'):
                    qpref = qpref + '.'
                candidates.append(qpref + name_s)
            fpref = getattr(self, 'current_file_prefix', '') or ''
            if isinstance(fpref, str) and fpref:
                if not fpref.endswith('.'):
                    fpref = fpref + '.'
                candidates.append(fpref + name_s)
            candidates.append(name_s)

        chosen = None
        b = None
        for cand in candidates:
            try:
                b = self._globals.get(cand)
            except Exception:
                b = None
            if b is None:
                try:
                    b = self._scope_stack[0].get(cand)
                except Exception:
                    b = None
            if b is not None and getattr(b, 'kind', None) == 'global' and getattr(b, 'depth', 0) == 0:
                chosen = cand
                break
            b = None

        if b is None:
            # Step 7.1b: allow `global x` to *declare* a global variable for this
            # package/file even if there was no prior top-level write.
            #
            # Heuristic for creation target:
            #   - If the function prefix looks like a struct-method prefix (e.g. Point.),
            #     prefer the file/package prefix (if any).
            #   - Otherwise prefer the most specific prefix (function/namespace), then file/package,
            #     then root.
            create_name = None
            if '.' in name_s:
                create_name = name_s
            else:
                qpref0 = getattr(self, 'current_qname_prefix', '') or ''
                fpref0 = getattr(self, 'current_file_prefix', '') or ''

                # Detect struct-method prefixes (avoid creating Point.x by default).
                is_method_prefix = False
                try:
                    qn0 = qpref0[:-1] if isinstance(qpref0, str) and qpref0.endswith('.') else str(qpref0)
                    if isinstance(qn0, str) and qn0:
                        if '.__static__' in qn0:
                            is_method_prefix = True
                        else:
                            sf = getattr(self, 'struct_fields', {}) or {}
                            if isinstance(sf, dict) and qn0 in sf:
                                is_method_prefix = True
                except Exception:
                    is_method_prefix = False

                if (not is_method_prefix) and isinstance(qpref0, str) and qpref0:
                    if not qpref0.endswith('.'):
                        qpref0 = qpref0 + '.'
                    create_name = qpref0 + name_s
                elif isinstance(fpref0, str) and fpref0:
                    if not fpref0.endswith('.'):
                        fpref0 = fpref0 + '.'
                    create_name = fpref0 + name_s
                else:
                    create_name = name_s

            b = self.declare_global_binding_root(create_name, node=node)
            chosen = create_name

        # Mark as writable from this function.
        fg = getattr(self, '_func_globals', None)
        if not isinstance(fg, set):
            self._func_globals = set()
            fg = self._func_globals
        gm = getattr(self, '_func_global_map', None)
        if not isinstance(gm, dict):
            self._func_global_map = {}
            gm = self._func_global_map

        if chosen is not None and chosen != name_s:
            gm[name_s] = chosen
        else:
            fg.add(name_s)
        return b
