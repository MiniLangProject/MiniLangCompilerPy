"""MiniLang lexer/parser and AST definitions.

This module implements:

- A small regex-based tokenizer (`tokenize`)
- AST node dataclasses for expressions and statements
- A recursive-descent parser (`Parser`) producing a `List[Stmt]`

The compiler attaches source positions as absolute character offsets via a private `_pos`
attribute. For convenience, AST base classes expose a `.pos` property.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Tuple

from .tools import wrap_i61


# ============================================================
# Errors / Diagnostics
# ============================================================

class ParseError(Exception):
    """Raised on syntax/lexing errors.

    Attributes:
        pos: Absolute character offset in the source where the error occurred.

    """

    def __init__(self, message: str, pos: int):
        """Create a parse error.

        Args:
            message: Human-readable error message.
            pos: Absolute character offset.
        """
        super().__init__(message)
        self.pos = pos


def format_error(source: str, filename: str, pos: int, message: str, kind: str) -> str:
    """Format an error with a source excerpt and caret.

    Args:
        source: Full source code.
        filename: Source filename for diagnostics.
        pos: Absolute character offset.
        message: Error message.
        kind: Error kind prefix (e.g. \"ParseError\", \"CompileError\").

    Returns:
        A multi-line string suitable for console output.
    """
    if pos < 0:
        pos = 0
    if pos > len(source):
        pos = len(source)

    line_no = source.count("\n", 0, pos) + 1
    line_start = source.rfind("\n", 0, pos)
    line_start = 0 if line_start == -1 else line_start + 1
    line_end = source.find("\n", pos)
    if line_end == -1:
        line_end = len(source)

    col_no = pos - line_start + 1
    line_text = source[line_start:line_end]
    caret = " " * (max(col_no - 1, 0)) + "^"

    return (f"{kind}: {message}\n"
            f"  at {filename}:{line_no}:{col_no}\n"
            f"  {line_text}\n"
            f"  {caret}")


# ============================================================
# Tokenizer
# ============================================================

@dataclass
class Token:
    """A single token produced by the tokenizer.

    Attributes:
        kind: Token kind (e.g. IDENT, NUMBER, KW, OP, NL, ...).
        value: Raw token text.
        pos: Absolute character offset in the source.
    """
    kind: str
    value: str
    pos: int


KEYWORDS = {"print", "if", "then", "else", "end", "while", "loop", "true", "false", "and", "or", "not", "function",
            "return", "global", "const", "for", "to", "each", "in", "break", "continue", "switch", "case", "default",
            "struct", "enum", "are", "namespace", "import", "as", "package", "extern", "from", "returns", "symbol",
            "out", "static", "inline", "synchronized", "void", "is", "defer", "interface", "implements",
            "iterator", "yield", "async", "await", "operator",}

TOKEN_SPEC = [("COMMENTBLOCK", r"/\*[\s\S]*?\*/"), ("COMMENTDOC", r"///.*"), ("COMMENTLINE", r"//.*"),
              ("NUMBER", r"0[xX][0-9A-Fa-f]+|0[bB][01]+|\d+\.\d+|\d+"), ("STRING", r'"([^"\\]|\\.)*"'),
              ("IDENT", r"[A-Za-z_][A-Za-z0-9_]*"), ("ELLIPSIS", r"\.\.\."), ("SAFEDOT", r"\?\."),
              ("OP", r"<<=|>>=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|=>|\?\?|==|!=|>=|<=|<<|>>|[+\-*/%=<>&|^~>]"),
              ("QMARK", r"\?"), ("DOT", r"\."), ("LPAREN", r"\("), ("RPAREN", r"\)"),
              ("LBRACK", r"\["), ("RBRACK", r"\]"), ("COMMA", r","), ("SEMI", r";"),  # include % for modulo
              ("NEWLINE", r"\n"), ("SKIP", r"[ \t]+"), ]

TOKEN_RE = re.compile("|".join(f"(?P<{name}>{pattern})" for name, pattern in TOKEN_SPEC))


def tokenize(code: str) -> List[Token]:
    """Tokenize MiniLang source code.

    Args:
        code: Source code.

    Returns:
        List of tokens including a final EOF token.

    Raises:
        ParseError: If an unknown character sequence is encountered.
    """
    tokens: List[Token] = []
    i = 0

    while i < len(code):
        m = TOKEN_RE.match(code, i)
        if not m:
            raise ParseError(f"Unknown character: {repr(code[i:i + 10])}", i)

        kind = m.lastgroup
        text = m.group()

        # Declaration comments are deliberately not part of the executable AST.
        # MiniDoc reads them from the original source while compilation treats
        # them exactly like ordinary line comments.
        if kind in ("SKIP", "COMMENTDOC", "COMMENTLINE"):
            pass

        elif kind == "COMMENTBLOCK":
            # Ignore block comments, but keep newlines as NL tokens
            for j, ch in enumerate(text):
                if ch == "\n":
                    tokens.append(Token("NL", "\\n", i + j))

        elif kind == "IDENT" and text in KEYWORDS:
            tokens.append(Token("KW", text, i))

        elif kind == "NEWLINE":
            tokens.append(Token("NL", "\\n", i))

        else:
            tokens.append(Token(kind, text, i))

        i = m.end()

    tokens.append(Token("EOF", "", len(code)))
    return tokens


# ============================================================
# AST
# ============================================================

@dataclass
class Expr:
    """Base class for expressions.

    The parser attaches a private `_pos` field (absolute character offset).
    Some compiler stages expect a public `.pos` attribute.
    """

    @property
    def pos(self) -> Optional[int]:
        """Absolute character offset where this node starts (or None if unknown)."""
        return getattr(self, "_pos", None)


@dataclass
class Num(Expr):
    """Numeric literal preserving its integer or floating-point representation."""
    value: float | int


@dataclass
class Str(Expr):
    """UTF-8 string literal."""
    value: str


@dataclass
class Bool(Expr):
    """Boolean literal."""
    value: bool


@dataclass
class VoidLit(Expr):
    """The `void` literal."""
    pass


@dataclass
class Var(Expr):
    """Reference to a lexical, module-global, or qualified binding."""
    name: str


@dataclass
class ArrayLit(Expr):
    """Array literal and its optional non-escaping variadic-stack marker."""
    items: List[Expr]
    # Internal-only marker: a proven non-escaping variadic tail may use an
    # immutable stack view for the duration of its direct call.
    stack_variadic: bool = False


@dataclass
class Unary(Expr):
    """Unary operator application."""
    op: str
    right: Expr


@dataclass
class Bin(Expr):
    """Binary operator application with left-to-right operands."""
    left: Expr
    op: str
    right: Expr


@dataclass
class IsType(Expr):
    """Runtime type predicate produced by the ``is`` syntax."""
    expr: Expr
    type_name: str
    negated: bool = False


@dataclass
class TypeGuard(Expr):
    """Runtime guard introduced at an explicitly annotated type boundary."""
    expr: Expr
    type_name: str
    optional: bool = False


@dataclass
class Coalesce(Expr):
    """Return the left operand unless it is void; evaluate the right lazily."""
    left: Expr
    right: Expr


@dataclass
class Call(Expr):
    """Function or method call, including optional named arguments."""
    callee: Expr
    args: List[Expr]
    arg_names: List[Optional[str]] = field(default_factory=list)


@dataclass
class Index(Expr):
    """Indexed array, byte-buffer, or string access."""
    target: Expr
    index: Expr


@dataclass
class Member(Expr):
    """Member lookup on a value or qualified module path."""
    target: Expr
    name: str


@dataclass
class SafeMember(Expr):
    """Void-safe member access (`value?.member`)."""
    target: Expr
    name: str


@dataclass
class Lambda(Expr):
    """Parser-only anonymous function; lowered to an ordinary closure."""
    params: List[str]
    body: List["Stmt"]
    param_types: List[Optional[str]] = field(default_factory=list)
    param_optional: List[bool] = field(default_factory=list)
    param_defaults: List[Optional[Expr]] = field(default_factory=list)
    variadic_index: int = -1
    return_type: Optional[str] = None
    return_optional: bool = False


@dataclass
class DeferredCapture(Expr):
    """Compiler-internal expression that reloads a captured defer operand."""
    offset: int


# Statements
@dataclass
class Stmt:
    """Base class for statements.

    The parser attaches a private `_pos` field (absolute character offset).
    Some compiler stages expect a public `.pos` attribute.
    """

    @property
    def pos(self) -> Optional[int]:
        """Absolute character offset where this node starts (or None if unknown)."""
        return getattr(self, "_pos", None)


@dataclass
class Import(Stmt):
    """Source-file import with optional namespace metadata."""
    path: str
    alias: Optional[str] = None
    module: Optional[str] = None


@dataclass
class NamespaceDef(Stmt):
    """Lexically scoped namespace body."""
    name: str
    body: List[Stmt]


@dataclass
class NamespaceDecl(Stmt):
    """File-level namespace declaration."""
    name: str


@dataclass
class ImportStmt(Stmt):
    """Qualified module import and its local alias."""
    module: str
    alias: str


@dataclass
class Print(Stmt):
    """Statement that writes one formatted value followed by a newline."""
    expr: Expr


@dataclass
class Assign(Stmt):
    """Binding declaration or assignment with an optional type contract."""
    name: str
    expr: Expr
    declared_type: Optional[str] = None
    declared_optional: bool = False


@dataclass
class SynchronizedDecl(Assign):
    """Process-shared scalar protected by MiniLang's recursive monitor."""
    pass


@dataclass
class SynchronizedBlock(Stmt):
    """Critical block guarded by an explicitly supplied Lock-like object."""
    lock: Expr
    body: List[Stmt]
    cleanup: Any = None


@dataclass
class ConstDecl(Stmt):
    """Immutable binding declaration."""
    name: str
    expr: Expr


@dataclass
class SetMember(Stmt):
    """Assignment to a field on a struct value."""
    obj: Expr
    field: str
    expr: Expr


@dataclass
class SetIndex(Stmt):
    """Assignment to an indexed array or byte-buffer element."""
    target: Expr
    index: Expr
    expr: Expr


@dataclass
class ExprStmt(Stmt):
    """Expression evaluated only for its side effects."""
    expr: Expr


@dataclass
class If(Stmt):
    """Conditional statement with ordered elseif branches and an else body."""
    cond: Expr
    then_body: List[Stmt]
    elifs: List[Tuple[Expr, List[Stmt]]]
    else_body: List[Stmt]


@dataclass
class While(Stmt):
    """Pre-test loop."""
    cond: Expr
    body: List[Stmt]


@dataclass
class DoWhile(Stmt):
    """Post-test loop that executes its body at least once."""
    body: List[Stmt]
    cond: Expr


@dataclass
class For(Stmt):
    """Inclusive numeric range loop."""
    var: str
    start: Expr
    end: Expr
    body: List[Stmt]


@dataclass
class ForEach(Stmt):
    """Iteration over the values of an iterable expression."""
    var: str
    iterable: Expr
    body: List[Stmt]


@dataclass
class FunctionDef(Stmt):
    """Function declaration with calling, typing, and optimization metadata."""
    name: str
    params: List[str]
    body: List[Stmt]
    is_static: bool = False
    is_inline: bool = False
    is_synchronized: bool = False
    param_types: List[Optional[str]] = field(default_factory=list)
    param_optional: List[bool] = field(default_factory=list)
    param_defaults: List[Optional[Expr]] = field(default_factory=list)
    variadic_index: int = -1
    return_type: Optional[str] = None
    return_optional: bool = False
    is_async: bool = False
    is_iterator: bool = False


@dataclass
class Return(Stmt):
    """Return an optional value from the current function."""
    expr: Optional[Expr]


@dataclass
class Yield(Stmt):
    """Suspend an iterator and publish its optional next value."""
    expr: Optional[Expr]


@dataclass
class Defer(Stmt):
    """Register a call for execution when the current scope exits."""
    expr: Call
    site_id: int = -1
    offsets: List[int] = field(default_factory=list)
    capture_kind: str = ""


@dataclass
class Break(Stmt):
    """Leave one or more enclosing loops or switches."""
    count: int = 1


@dataclass
class Continue(Stmt):
    """Continue the nearest enclosing loop."""
    pass


@dataclass
class GlobalDecl(Stmt):
    """Declare module-global bindings visible inside a function."""
    names: List[str]


@dataclass
class SwitchCase:
    """One value-list or inclusive-range branch of a switch statement."""
    kind: str  # "values" | "range"
    values: List[Expr]
    range_start: Optional[Expr]
    range_end: Optional[Expr]
    body: List[Stmt]

    @property
    def pos(self) -> Optional[int]:
        """Absolute character offset where this node starts (or None if unknown)."""
        return getattr(self, "_pos", None)


@dataclass
class Switch(Stmt):
    """Multi-way value dispatch with an optional default body."""
    expr: Expr
    cases: List[SwitchCase]
    default_body: List[Stmt]


@dataclass
class StructDef(Stmt):
    """Struct declaration with fields, methods, and implemented interfaces."""
    name: str
    fields: List[str]
    methods: List["FunctionDef"] = field(default_factory=list)
    field_types: List[Optional[str]] = field(default_factory=list)
    field_optional: List[bool] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)


@dataclass
class InterfaceDef(Stmt):
    """Compile-time structural contract; it has no runtime representation."""
    name: str
    methods: List[FunctionDef] = field(default_factory=list)


@dataclass
class EnumDef(Stmt):
    """Enumeration declaration with optional explicit variant values."""
    name: str
    variants: List[str]
    values: List[Optional[Expr]] = field(default_factory=list)


@dataclass
class ExternParam:
    """Native ABI parameter, including optional trailing ``out`` semantics."""
    name: Optional[str]  # optional parameter name (for readability)
    ty: str  # ABI type name (e.g. int, bool, ptr, cstr, wstr, void)
    is_out: bool = False  # out-parameter (passed as pointer; may be omitted at call site)


@dataclass
class ExternFunctionDef(Stmt):
    """Foreign function declaration resolved from a native shared library."""
    name: str
    params: List[ExternParam]
    dll: str
    symbol: Optional[str]
    ret_ty: str


# ============================================================
# Parser
# ============================================================

PRECEDENCE = {"??": 0, "or": 1, "and": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6, "is": 6, ">": 7, "<": 7, ">=": 7, "<=": 7, "<<": 8,
              ">>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10, }

# Source operators are represented as reserved static struct methods after
# parsing.  The names are ordinary identifiers so every later compiler stage
# can reuse the existing function collection, type guards, calls and inliner.
OPERATOR_METHOD_NAMES = {
    ("+", 1): "__operator_pos",
    ("-", 1): "__operator_neg",
    ("not", 1): "__operator_not",
    ("~", 1): "__operator_bitnot",
    ("+", 2): "__operator_add",
    ("-", 2): "__operator_sub",
    ("*", 2): "__operator_mul",
    ("/", 2): "__operator_div",
    ("%", 2): "__operator_mod",
    ("==", 2): "__operator_eq",
    ("!=", 2): "__operator_ne",
    ("<", 2): "__operator_lt",
    ("<=", 2): "__operator_le",
    (">", 2): "__operator_gt",
    (">=", 2): "__operator_ge",
    ("&", 2): "__operator_bitand",
    ("|", 2): "__operator_bitor",
    ("^", 2): "__operator_bitxor",
    ("<<", 2): "__operator_shl",
    (">>", 2): "__operator_shr",
}

COMPOUND_ASSIGNMENT_OPERATORS = {
    "+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%",
    "&=": "&", "|=": "|", "^=": "^", "<<=": "<<", ">>=": ">>",
}


def operator_method_name(symbol: str, arity: int) -> Optional[str]:
    """Return the reserved method name for one supported operator signature."""
    return OPERATOR_METHOD_NAMES.get((str(symbol), int(arity)))


class Parser:
    """Recursive-descent parser for MiniLang.

    The parser consumes a token stream and produces a list of statement nodes.
    Most helper methods operate on `self.i` (the current token index).

"""

    def __init__(
        self,
        tokens: List[Token],
        source: str,
        filename: str,
        collect_errors: bool = False,
        max_errors: int = 50,
    ):
        self.tokens = tokens
        self.i = 0
        self.source = source
        self.filename = filename
        # Error recovery / collection
        self.collect_errors = bool(collect_errors)
        self.max_errors = int(max_errors) if max_errors is not None else 50
        self.errors: List[ParseError] = []
        # Deduplicate repeated diagnostics. With recovery enabled, the parser
        # may sync at boundary tokens (e.g. `else`, `end`) and otherwise
        # re-emit the same error at the same position on the next loop.
        self._error_keys: set[tuple[Optional[str], Optional[int], str]] = set()
        # Track whether we're currently parsing inside a function body
        self._func_depth = 0
        # Track whether we're inside a namespace block
        self._ns_depth = 0
        # file-level package directive tracking
        self._seen_package = False
        self._seen_nonpackage_toplevel_stmt = False
        self._lambda_counter = 0

    def peek(self) -> Token:
        return self.tokens[self.i]

    def peek2(self) -> Token:
        if self.i + 1 < len(self.tokens):
            return self.tokens[self.i + 1]
        return Token("EOF", "", self.tokens[-1].pos)

    def advance(self) -> Token:
        t = self.tokens[self.i]
        self.i += 1
        return t

    def match(self, kind: str, value: Optional[str] = None) -> bool:
        t = self.peek()
        if t.kind != kind:
            return False
        if value is not None and t.value != value:
            return False
        self.advance()
        return True

    def expect(self, kind: str, value: Optional[str] = None) -> Token:
        t = self.peek()
        if t.kind != kind or (value is not None and t.value != value):
            need = f"{kind}{' ' + value if value else ''}"
            got = f"{t.kind}:{t.value}"
            raise ParseError(f"Expected {need}, got {got}", t.pos)
        return self.advance()



    def _line_col(self, pos: int) -> tuple[int, int]:
        # Convert absolute source offset -> (line, col), 1-indexed.
        if pos is None:
            return (1, 1)
        try:
            pos_i = int(pos)
        except Exception:
            pos_i = 0
        if pos_i < 0:
            pos_i = 0
        src = self.source
        line_no = src.count("\n", 0, pos_i) + 1
        line_start = src.rfind("\n", 0, pos_i)
        line_start = 0 if line_start == -1 else line_start + 1
        col_no = pos_i - line_start + 1
        return (line_no, col_no)

    def _fmt_pos(self, pos: int) -> str:
        ln, cn = self._line_col(pos)
        return f"{self.filename}:{ln}:{cn}"

    def skip_newlines(self) -> None:
        while self.match("NL"):
            pass

    def peek_non_nl(self) -> Token:
        """Peek the next token, skipping any NL tokens, without consuming."""
        j = self.i
        while j < len(self.tokens) and self.tokens[j].kind == "NL":
            j += 1
        if j >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[j]

    def _is_case_value_continuation_start(self, tok: Token) -> bool:
        """Heuristic for multiline 'case X, Y, ...' header continuation.

        To avoid ambiguity with the case body (which often starts with IDENT/KW),
        we only treat a newline after a comma as continuing the value list when
        the next non-NL token looks like a literal/primary expression start.
        """
        if tok.kind in ("NUMBER", "STRING", "LPAREN", "LBRACK"):
            return True
        if tok.kind == "OP" and tok.value in ("-", "~"):
            return True
        if tok.kind == "KW" and tok.value in ("true", "false", "not"):
            return True
        return False

    def parse_delimited_list(self, end_kind: str, parse_item: Callable[[], Any]) -> List[Any]:
        """Parse a comma-separated list that ends with end_kind.

        - Newlines are allowed after the opening delimiter, after commas, and
          before the closing delimiter.
        - A trailing comma is allowed.
        - The opening delimiter token must already be consumed.
        - This function consumes the closing delimiter token.
        """
        items: List[Any] = []
        self.skip_newlines()
        if self.match(end_kind):
            return items

        while True:
            items.append(parse_item())
            self.skip_newlines()

            if self.match("COMMA"):
                self.skip_newlines()
                # trailing comma
                if self.match(end_kind):
                    break
                continue

            self.expect(end_kind)
            break

        return items

    def parse_type_ref(self) -> tuple[str, bool]:
        """Parse a qualified type name followed by an optional `?` marker."""
        tok = self.peek()
        if tok.kind not in ("IDENT", "KW"):
            raise ParseError("Expected type name", tok.pos)
        parts = [self.advance().value]
        while self.match("DOT"):
            parts.append(self.expect("IDENT").value)
        optional = self.match("QMARK")
        return ".".join(parts), optional

    def parse_parameter(self) -> tuple[str, Optional[str], bool, Optional[Expr], bool]:
        """Parse one user-function parameter and its gradual-type metadata."""
        name = self.expect("IDENT").value
        ty: Optional[str] = None
        optional = False
        if self.peek().kind == "KW" and self.peek().value == "as":
            self.advance()
            ty, optional = self.parse_type_ref()
        variadic = self.match("ELLIPSIS")
        default: Optional[Expr] = None
        if self.match("OP", "="):
            if variadic:
                raise ParseError("A variadic parameter cannot have a default value", self.peek().pos)
            default = self.parse_expr()
        return name, ty, optional, default, variadic

    def parse_parameters(self) -> tuple[List[str], List[Optional[str]], List[bool], List[Optional[Expr]], int]:
        raw = self.parse_delimited_list("RPAREN", self.parse_parameter)
        names: List[str] = []
        types: List[Optional[str]] = []
        optionals: List[bool] = []
        defaults: List[Optional[Expr]] = []
        variadic_index = -1
        saw_default = False
        for i, (name, ty, optional, default, variadic) in enumerate(raw):
            if variadic:
                if i != len(raw) - 1:
                    raise ParseError("The variadic parameter must be last", getattr(default, "pos", self.peek().pos))
                variadic_index = i
            elif default is None and saw_default:
                raise ParseError("Required parameters cannot follow default parameters", self.peek().pos)
            if default is not None:
                saw_default = True
            names.append(name)
            types.append(ty)
            optionals.append(optional)
            defaults.append(default)
        if len(set(names)) != len(names):
            raise ParseError("Duplicate function parameter", self.peek().pos)
        return names, types, optionals, defaults, variadic_index

    def parse_call_arguments(self) -> tuple[List[Expr], List[Optional[str]]]:
        """Parse positional and `name = value` call arguments."""
        args: List[Expr] = []
        names: List[Optional[str]] = []
        self.skip_newlines()
        if self.match("RPAREN"):
            return args, names
        named_seen = False
        while True:
            arg_name: Optional[str] = None
            if self.peek().kind == "IDENT" and self.peek2().kind == "OP" and self.peek2().value == "=":
                arg_name = self.advance().value
                self.advance()
                named_seen = True
            elif named_seen:
                raise ParseError("Positional arguments cannot follow named arguments", self.peek().pos)
            args.append(self.parse_expr())
            names.append(arg_name)
            self.skip_newlines()
            if self.match("COMMA"):
                self.skip_newlines()
                if self.match("RPAREN"):
                    break
                continue
            self.expect("RPAREN")
            break
        return args, names

    def _guard_expr(self, expr: Expr, ty: Optional[str], optional: bool, pos: int) -> Expr:
        if not ty:
            return expr
        return self._attach_pos(TypeGuard(expr, ty, optional), pos)

    def _guard_returns(self, body: List[Stmt], ty: Optional[str], optional: bool) -> None:
        """Apply a declared return contract without descending into nested functions."""
        if not ty:
            return
        for st in body:
            if isinstance(st, Return):
                value = st.expr if st.expr is not None else self._attach_pos(VoidLit(), getattr(st, "_pos", 0))
                st.expr = self._guard_expr(value, ty, optional, getattr(st, "_pos", 0))
            elif isinstance(st, If):
                self._guard_returns(st.then_body, ty, optional)
                for _, branch in st.elifs:
                    self._guard_returns(branch, ty, optional)
                self._guard_returns(st.else_body, ty, optional)
            elif isinstance(st, (While, DoWhile, For, ForEach, SynchronizedBlock)):
                self._guard_returns(st.body, ty, optional)
            elif isinstance(st, Switch):
                for case in st.cases:
                    self._guard_returns(case.body, ty, optional)
                self._guard_returns(st.default_body, ty, optional)

    def _apply_function_contracts(self, fn: FunctionDef) -> FunctionDef:
        guards: List[Stmt] = []
        for i, name in enumerate(fn.params):
            ty = fn.param_types[i] if i < len(fn.param_types) else None
            optional = fn.param_optional[i] if i < len(fn.param_optional) else False
            if ty:
                var = self._attach_pos(Var(name), getattr(fn, "_pos", 0))
                guarded = self._guard_expr(var, ty, optional, getattr(fn, "_pos", 0))
                guards.append(self._attach_pos(Assign(name, guarded, ty, optional), getattr(fn, "_pos", 0)))
        if guards:
            fn.body = guards + fn.body
        self._guard_returns(fn.body, fn.return_type, fn.return_optional)
        return fn

    def skip_stmt_seps(self) -> None:
        # Statement separators: newline(s) and semicolons.
        while True:
            if self.match("NL"):
                continue
            if self.match("SEMI"):
                continue
            break

    def _record_error(self, e: ParseError) -> None:
        if not self.collect_errors:
            raise e
        if len(self.errors) >= self.max_errors:
            return
        try:
            # Attach filename for nicer multi-file output.
            setattr(e, "filename", getattr(self, "filename", None))
        except Exception:
            pass
        key = (getattr(self, "filename", None), getattr(e, "pos", None), str(e))
        if key in self._error_keys:
            return
        self._error_keys.add(key)
        self.errors.append(e)

    def _sync_stmt(
        self,
        *,
        stop_keywords: Optional[set[str]] = None,
        end_type: Optional[str] = None,
    ) -> None:
        """Best-effort statement recovery.

        Advance until we reach a likely statement boundary:
          - newline or ';'
          - block boundary keywords (end/else/case/default)
          - explicit stop_keywords (used by parse_block_until)

        We intentionally do not consume block-boundary keywords so the caller
        can observe them.
        """
        if stop_keywords is None:
            stop_keywords = set()

        start_i = self.i
        while True:
            t = self.peek()
            if t.kind == "EOF":
                return

            # Statement separators: consume them and stop.
            if t.kind in ("NL", "SEMI"):
                self.skip_stmt_seps()
                return

            if t.kind == "KW":
                if t.value in stop_keywords:
                    return
                if t.value in ("end", "else", "case", "default"):
                    return
                if end_type is not None and self.is_end_of(end_type):
                    return

            self.advance()

            # Ensure progress even on pathological inputs.
            if self.i == start_i:
                self.advance()

    def _parse_stmt_recover(
        self,
        *,
        stop_keywords: Optional[set[str]] = None,
        end_type: Optional[str] = None,
    ) -> Optional[Stmt]:
        """Parse a statement, recording errors and synchronizing on failure."""
        start_i = self.i
        try:
            return self.parse_stmt()
        except ParseError as e:
            self._record_error(e)
            self._sync_stmt(stop_keywords=stop_keywords, end_type=end_type)
            # Ensure progress. At the top-level, boundary keywords like `else`
            # or `end` are not consumed by _sync_stmt (by design), which can
            # otherwise cause the same error to be emitted repeatedly.
            if self.i == start_i:
                if self.peek().kind != "EOF":
                    self.advance()
                self.skip_stmt_seps()
            return None

    def expect_block_nl(self) -> None:
        """Consume an optional block separator.

        Historically MiniLang required a physical newline after many block headers
        (e.g. after `function ... )`, `struct ...`, `enum ...`, `while ...`, ...).

        To support newline-free / inline formatting, a separator is now optional:
        - If a newline or ';' is present, we consume it (and any following separators).
        - Otherwise we accept an inline block body immediately following the header.

        This keeps existing code working while enabling one-liners like:
            function main(args) if true then print "ok" end if end function
        """
        if self.match("NL") or self.match("SEMI"):
            self.skip_stmt_seps()
            return
        # Inline block body (no separator) is valid.
        return

    def is_end_of(self, what: str) -> bool:
        return (
                self.peek().kind == "KW" and self.peek().value == "end"
                and self.peek2().kind in ("KW", "IDENT") and self.peek2().value == what)

    def expect_end_of(self, what: str) -> None:
        self.expect("KW", "end")
        token = self.peek()
        if token.kind not in ("KW", "IDENT") or token.value != what:
            raise ParseError(f"Expected '{what}'", token.pos)
        self.advance()

    def parse_dotted_name(self) -> str:
        first = self.expect("IDENT").value
        parts = [first]
        while self.match("DOT"):
            parts.append(self.expect("IDENT").value)
        return ".".join(parts)

    def parse_extern_param(self) -> ExternParam:
        """Parse an extern parameter.

        Forms:
          - <type>
          - <name> as <type>
          - out <type>
          - out <name> as <type>

        `out` marks an out-parameter (passed by pointer; may be omitted at the call site).
        """
        is_out = False
        t = self.peek()
        if t.kind == "KW" and t.value == "out":
            is_out = True
            self.advance()
            t = self.peek()

        if t.kind not in ("IDENT", "KW"):
            raise ParseError("external parameter expects a type or '<name> as <type>'", t.pos)

        first = self.advance().value

        if self.peek().kind == "KW" and self.peek().value == "as":
            self.advance()
            ty_tok = self.peek()
            if ty_tok.kind not in ("IDENT", "KW"):
                raise ParseError("external parameter expects a type name after 'as'", ty_tok.pos)
            ty = self.advance().value
            return ExternParam(first, ty, is_out=is_out)

        # no explicit name -> treat as type-only param
        return ExternParam(None, first, is_out=is_out)

    def _decode_string_raw(self, raw: str, pos: int) -> str:
        # Decode backslash escapes, but keep UTF-8 characters as-is.
        out: List[str] = []
        i = 0
        n = len(raw)

        while i < n:
            ch = raw[i]
            if ch != '\\':
                out.append(ch)
                i += 1
                continue

            # escape
            if i + 1 >= n:
                raise ParseError("Invalid escape at the end of the string", pos + i)

            esc = raw[i + 1]

            if esc == 'n':
                out.append('\n')
                i += 2
                continue
            if esc == 'r':
                out.append('\r')
                i += 2
                continue
            if esc == 't':
                out.append('\t')
                i += 2
                continue
            if esc == '0':
                out.append('\x00')
                i += 2
                continue
            if esc == '\\':
                out.append('\\')
                i += 2
                continue
            if esc == '"':
                out.append('"')
                i += 2
                continue

            if esc == 'x':
                if i + 3 >= n:
                    raise ParseError(r"Invalid \\x escape (expected 2 hex characters)", pos + i)
                hx = raw[i + 2:i + 4]
                if not re.fullmatch(r"[0-9A-Fa-f]{2}", hx):
                    raise ParseError(r"Invalid \\x escape (expected 2 hex characters)", pos + i)
                out.append(chr(int(hx, 16)))
                i += 4
                continue

            if esc == 'u':
                if i + 5 >= n:
                    raise ParseError(r"Invalid \\u escape (expected 4 hex characters)", pos + i)
                hx = raw[i + 2:i + 6]
                if not re.fullmatch(r"[0-9A-Fa-f]{4}", hx):
                    raise ParseError(r"Invalid \\u escape (expected 4 hex characters)", pos + i)
                out.append(chr(int(hx, 16)))
                i += 6
                continue

            if esc == 'U':
                if i + 9 >= n:
                    raise ParseError(r"Invalid \\U escape (expected 8 hex characters)", pos + i)
                hx = raw[i + 2:i + 10]
                if not re.fullmatch(r"[0-9A-Fa-f]{8}", hx):
                    raise ParseError(r"Invalid \\U escape (expected 8 hex characters)", pos + i)
                out.append(chr(int(hx, 16)))
                i += 10
                continue

            # Fallback: interpret "\\<char>" as "<char>" (robust path/regex strings, etc.)
            out.append(esc)
            i += 2

        return ''.join(out)

    def _decode_string_token(self, tok: Token) -> str:
        if tok.kind != "STRING":
            raise ParseError("Expect STRING literal", tok.pos)
        raw = tok.value[1:-1]
        return self._decode_string_raw(raw, tok.pos)

    def _flatten_member_chain_as_qualname(self, e: Expr) -> Optional[str]:
        # Convert Member(Member(Var("a"),"b"),"c") -> "a.b.c"
        parts: List[str] = []
        cur = e
        while isinstance(cur, Member):
            parts.append(cur.name)
            cur = cur.target
        if isinstance(cur, Var):
            base = cur.name
            if parts:
                return base + "." + ".".join(reversed(parts))
            return base
        return None

    def parse_namespace_def(self) -> NamespaceDef:
        start_pos = self.peek().pos
        self.expect("KW", "namespace")

        if self._func_depth > 0:
            raise ParseError("'namespace' is only permitted at the top level", start_pos)

        # allow dotted namespace names (namespace a.b) and nested namespaces.
        ns_name = self.parse_dotted_name()

        self.expect_block_nl()

        self._ns_depth += 1
        body: List[Stmt] = []
        try:
            self.skip_stmt_seps()
            while not self.is_end_of("namespace"):
                if self.peek().kind == "EOF":
                    raise ParseError("namespace ends unexpectedly (missing ‘end namespace’?)", self.peek().pos)

                try:
                    t = self.peek()

                    # Imports are still forbidden inside namespaces.
                    if t.kind == "KW" and t.value == "import":
                        raise ParseError("'import' is not allowed inside a namespace", t.pos)

                    # Allowed at namespace top-level: declarations + const + simple global assignments.
                    if t.kind == "KW" and t.value in ("function", "struct", "interface", "enum", "namespace", "extern", "const"):
                        st2 = self.parse_stmt() if not self.collect_errors else self._parse_stmt_recover(end_type="namespace")
                        if st2 is not None:
                            body.append(st2)
                        self.skip_stmt_seps()
                        continue

                    if t.kind == "IDENT":
                        st = self.parse_stmt() if not self.collect_errors else self._parse_stmt_recover(end_type="namespace")
                        if st is None:
                            self.skip_stmt_seps()
                            continue
                        if isinstance(st, Assign):
                            body.append(st)
                            self.skip_stmt_seps()
                            continue
                        pos = getattr(st, 'pos', None) or t.pos
                        raise ParseError("Inside a namespace, only declarations/globals are allowed (e.g. 'x = ...')", pos)

                    raise ParseError(
                        "Inside a namespace, only declarations are allowed (function/struct/interface/enum/namespace/extern/const)",
                        t.pos)
                except ParseError as e:
                    if not self.collect_errors:
                        raise
                    self._record_error(e)
                    self._sync_stmt(end_type="namespace")
                    if len(self.errors) >= self.max_errors:
                        break
        finally:
            self._ns_depth -= 1

        self.expect_end_of("namespace")
        return self._attach_pos(NamespaceDef(ns_name, body), start_pos)

    def parse_program(self) -> List[Stmt]:
        stmts: List[Stmt] = []
        self.skip_stmt_seps()
        while self.peek().kind != "EOF":
            if self.collect_errors:
                st = self._parse_stmt_recover()
                if st is None:
                    if len(self.errors) >= self.max_errors:
                        break
                    continue
            else:
                st = self.parse_stmt()

            stmts.append(st)
            # `package` must be the first statement in the file (before imports/decls).
            if self._func_depth == 0 and self._ns_depth == 0:
                if not isinstance(st, NamespaceDecl):
                    self._seen_nonpackage_toplevel_stmt = True
            self.skip_stmt_seps()
        return stmts

    def _attach_pos(self, node: Any, pos: int) -> Any:
        try:
            setattr(node, "_pos", pos)
            # Remember originating file for better diagnostics (multi-file / imports).
            setattr(node, "_filename", getattr(self, "filename", None))
        except Exception:
            pass
        return node

    def parse_stmt(self) -> Stmt:
        start_pos = self.peek().pos
        t = self.peek()

        # package <Name>   (top-level only)
        if t.kind == "KW" and t.value == "package":
            if self._func_depth > 0 or self._ns_depth > 0:
                raise ParseError("'package' is only allowed at the top level", t.pos)
            if self._seen_package:
                raise ParseError("'package' may only appear once per file", t.pos)
            if self._seen_nonpackage_toplevel_stmt:
                raise ParseError("'package' must be the first statement in the file", t.pos)
            self._seen_package = True
            self.advance()
            # allow dotted package names: package foo.bar
            pkg_name = self.parse_dotted_name()
            return self._attach_pos(NamespaceDecl(pkg_name), start_pos)

        # namespace <Name> ... end namespace   (top-level only; may nest within namespaces)
        if t.kind == "KW" and t.value == "namespace":
            return self.parse_namespace_def()

        # import "relative/path.ml"   (top-level only)
        # import foo.bar              (syntactic sugar for import "foo/bar.ml")
        if t.kind == "KW" and t.value == "import":
            if self._func_depth > 0 or self._ns_depth > 0:
                raise ParseError("'import' is only allowed at the top level", t.pos)
            self.advance()

            # Two forms:
            #   import "path/to/file.ml"
            #   import foo.bar        (module-style; resolves to foo/bar.ml)
            if self.peek().kind == "STRING":
                path_tok = self.advance()
                p = self._decode_string_token(path_tok)
                module_name = None
            else:
                module_name = self.parse_dotted_name()
                p = module_name.replace(".", "/") + ".ml"

            alias = None
            if self.peek().kind == "KW" and self.peek().value == "as":
                self.advance()
                alias = self.expect("IDENT").value

            return self._attach_pos(Import(p, alias, module_name), start_pos)

        # const name = expr
        if t.kind == "KW" and t.value == "const":
            self.advance()
            name_tok = self.expect("IDENT")
            self.expect("OP", "=")
            expr = self.parse_expr()
            return self._attach_pos(ConstDecl(name_tok.value, expr), start_pos)

        # synchronized(lock) ... end synchronized (fine-grained block)
        # synchronized name = expr                    (process-shared scalar)
        if t.kind == "KW" and t.value == "synchronized":
            self.advance()
            if self.match("LPAREN"):
                lock_expr = self.parse_expr()
                self.expect("RPAREN")
                self.expect_block_nl()
                body = self.parse_block_until_end("synchronized", start_pos)
                self.expect_end_of("synchronized")
                return self._attach_pos(SynchronizedBlock(lock_expr, body), start_pos)
            name_tok = self.expect("IDENT")
            self.expect("OP", "=")
            expr = self.parse_expr()
            return self._attach_pos(SynchronizedDecl(name_tok.value, expr), start_pos)

        # print expr
        if t.kind == "KW" and t.value == "print":
            self.advance()
            return self._attach_pos(Print(self.parse_expr()), start_pos)

        # break [n]
        if t.kind == "KW" and t.value == "break":
            self.advance()
            if self.peek().kind == "NUMBER" and "." not in self.peek().value:
                raw_n = self.advance().value
                # allow decimal, hex (0x..), binary (0b..)
                if re.match(r"-?0[xX]", raw_n) or re.match(r"-?0[bB]", raw_n):
                    n = int(raw_n, 0)
                else:
                    n = int(raw_n)
                return self._attach_pos(Break(max(1, n)), start_pos)
            return self._attach_pos(Break(1), start_pos)

        # continue
        if t.kind == "KW" and t.value == "continue":
            self.advance()
            return self._attach_pos(Continue(), start_pos)

        # global x, y, z (function scope declaration)
        if t.kind == "KW" and t.value == "global":
            if self._func_depth <= 0:
                raise ParseError("'global' is only allowed inside functions", t.pos)
            self.advance()
            names: List[str] = [self.expect("IDENT").value]
            while self.match("COMMA"):
                # Trailing comma allowed in global lists.
                if self.peek().kind in ("NL", "SEMI", "EOF"):
                    break
                names.append(self.expect("IDENT").value)
            return self._attach_pos(GlobalDecl(names), start_pos)

        # return [expr]
        if t.kind == "KW" and t.value == "return":
            self.advance()
            # Allow bare `return` when the statement ends immediately.
            # This is important for inline control-flow forms like:
            #   if cond then return end if
            #   if cond then return else return end if
            # where the next token is a block boundary keyword rather than a newline.
            nxt = self.peek()
            if nxt.kind in ("NL", "SEMI", "EOF"):
                return self._attach_pos(Return(None), start_pos)
            if nxt.kind == "KW" and nxt.value in ("end", "else", "case", "default"):
                return self._attach_pos(Return(None), start_pos)
            return self._attach_pos(Return(self.parse_expr()), start_pos)

        # yield [expr] (only valid in iterator functions; validated during lowering)
        if t.kind == "KW" and t.value == "yield":
            if self._func_depth <= 0:
                raise ParseError("'yield' is only allowed inside iterator functions", t.pos)
            self.advance()
            nxt = self.peek()
            if nxt.kind in ("NL", "SEMI", "EOF") or (nxt.kind == "KW" and nxt.value in ("end", "else", "case", "default")):
                return self._attach_pos(Yield(None), start_pos)
            return self._attach_pos(Yield(self.parse_expr()), start_pos)

        # defer call(...)
        #
        # The call operands are evaluated when this statement is reached; the
        # call itself runs in LIFO order when the surrounding function exits.
        if t.kind == "KW" and t.value == "defer":
            if self._func_depth <= 0:
                raise ParseError("'defer' is only allowed inside functions", t.pos)
            self.advance()
            expr = self.parse_expr()
            if not isinstance(expr, Call):
                raise ParseError("'defer' expects a function or method call", start_pos)
            return self._attach_pos(Defer(expr), start_pos)

        # extern function / extern struct (native compiler)
        if t.kind == "KW" and t.value == "extern":
            if self._func_depth > 0:
                raise ParseError("'extern' is only allowed at the top level / inside a namespace", t.pos)

            self.advance()

            # extern struct Name ... end struct
            if self.peek().kind == "KW" and self.peek().value == "struct":
                self.advance()
                name = self.expect("IDENT").value
                self.expect_block_nl()

                fields: List[str] = []
                field_tys: List[str] = []

                while not self.is_end_of("struct"):
                    # allow blank lines / semicolons inside the block
                    self.skip_stmt_seps()
                    if self.is_end_of("struct"):
                        break
                    if self.peek().kind == "EOF":
                        raise ParseError(f"extern struct ended unexpectedly (missing 'end struct'?) (block started at {self._fmt_pos(start_pos)})", self.peek().pos)

                    fname = self.expect("IDENT").value
                    self.expect("KW", "as")
                    ty_tok = self.peek()
                    if ty_tok.kind not in ("IDENT", "KW"):
                        raise ParseError("extern struct field erwartet einen Typnamen nach 'as'", ty_tok.pos)
                    fty = self.advance().value

                    fields.append(fname)
                    field_tys.append(fty)
                    self.expect_block_nl()

                self.expect_end_of("struct")
                node = StructDef(name, fields, methods=[])
                # attach ABI layout info for the native compiler
                setattr(node, "_extern_field_types", field_tys)
                return self._attach_pos(node, start_pos)

            # extern function Name(params) from "dll" [symbol "Sym"] [returns Type]
            self.expect("KW", "function")

            name_tok = self.expect("IDENT")
            self.expect("LPAREN")
            params: List[ExternParam] = self.parse_delimited_list("RPAREN", self.parse_extern_param)

            if not (self.peek().kind == "KW" and self.peek().value == "from"):
                raise ParseError("extern function erwartet 'from \"...\"'", self.peek().pos)
            self.advance()
            dll_tok = self.expect("STRING")
            dll = self._decode_string_token(dll_tok)

            symbol: Optional[str] = None
            if self.peek().kind == "KW" and self.peek().value == "symbol":
                self.advance()
                sym_tok = self.expect("STRING")
                symbol = self._decode_string_token(sym_tok)

            ret_ty = "int"
            if self.peek().kind == "KW" and self.peek().value == "returns":
                self.advance()
                rt = self.peek()
                if rt.kind not in ("IDENT", "KW"):
                    raise ParseError("returns erwartet einen Typnamen", rt.pos)
                ret_ty = self.advance().value

            return self._attach_pos(ExternFunctionDef(name_tok.value, params, dll, symbol, ret_ty), start_pos)

        # [async|iterator] function ... or contextual `lazy iterator function ...`.
        # `lazy` intentionally remains an identifier outside this exact header.
        is_lazy_iterator = (t.kind == "IDENT" and t.value == "lazy"
                            and self.peek2().kind == "KW" and self.peek2().value == "iterator"
                            and self.i + 2 < len(self.tokens)
                            and self.tokens[self.i + 2].kind == "KW"
                            and self.tokens[self.i + 2].value == "function")
        if ((t.kind == "KW" and t.value in ("function", "async", "iterator"))
                or is_lazy_iterator):
            is_async = t.value == "async"
            is_iterator = 2 if is_lazy_iterator else (t.value == "iterator")
            self.advance()
            if is_lazy_iterator:
                self.expect("KW", "iterator")
                self.expect("KW", "function")
            elif is_async or is_iterator:
                self.expect("KW", "function")
            is_inline = False
            is_synchronized = False
            while self.peek().kind == "KW" and self.peek().value in ("inline", "synchronized"):
                modifier = self.advance().value
                if modifier == "inline":
                    if is_inline:
                        raise ParseError("duplicate function modifier 'inline'", self.peek().pos)
                    is_inline = True
                else:
                    if is_synchronized:
                        raise ParseError("duplicate function modifier 'synchronized'", self.peek().pos)
                    is_synchronized = True
            name_tok = self.expect("IDENT")
            self.expect("LPAREN")
            params, param_types, param_optional, param_defaults, variadic_index = self.parse_parameters()

            return_type: Optional[str] = None
            return_optional = False
            if self.peek().kind == "KW" and self.peek().value == "returns":
                self.advance()
                return_type, return_optional = self.parse_type_ref()

            self.expect_block_nl()
            self._func_depth += 1
            try:
                body = self.parse_block_until_end("function", start_pos)
            finally:
                self._func_depth -= 1
            self.expect_end_of("function")
            fn = self._attach_pos(FunctionDef(name_tok.value, params, body, is_inline=is_inline,
                                               is_synchronized=is_synchronized, param_types=param_types,
                                               param_optional=param_optional, param_defaults=param_defaults,
                                               variadic_index=variadic_index, return_type=return_type,
                                               return_optional=return_optional, is_async=is_async,
                                               is_iterator=is_iterator), start_pos)
            return self._apply_function_contracts(fn)

        # interface Name ... end interface
        if t.kind == "KW" and t.value == "interface":
            if self._func_depth > 0:
                raise ParseError("'interface' is only allowed at declaration scope", t.pos)
            self.advance()
            name = self.expect("IDENT").value
            self.expect_block_nl()
            methods: List[FunctionDef] = []
            while not self.is_end_of("interface"):
                self.skip_stmt_seps()
                if self.is_end_of("interface"):
                    break
                self.expect("KW", "function")
                mpos = self.peek().pos
                mname = self.expect("IDENT").value
                self.expect("LPAREN")
                params, ptypes, poptional, pdefaults, variadic = self.parse_parameters()
                if any(x is not None for x in pdefaults):
                    raise ParseError("Interface methods cannot declare default values", mpos)
                rty: Optional[str] = None
                ropt = False
                if self.peek().kind == "KW" and self.peek().value == "returns":
                    self.advance()
                    rty, ropt = self.parse_type_ref()
                methods.append(self._attach_pos(FunctionDef(mname, params, [], param_types=ptypes,
                                                             param_optional=poptional, variadic_index=variadic,
                                                             return_type=rty, return_optional=ropt), mpos))
                self.expect_block_nl()
            self.expect_end_of("interface")
            return self._attach_pos(InterfaceDef(name, methods), start_pos)

        # struct
        if t.kind == "KW" and t.value == "struct":
            self.advance()
            name = self.expect("IDENT").value
            interfaces: List[str] = []
            if self.peek().kind == "KW" and self.peek().value == "implements":
                self.advance()
                while True:
                    iface, opt = self.parse_type_ref()
                    if opt:
                        raise ParseError("An implemented interface cannot be optional", self.peek().pos)
                    interfaces.append(iface)
                    if not self.match("COMMA"):
                        break
            # `are` is optional (legacy)
            if self.peek().kind == "KW" and self.peek().value == "are":
                self.advance()
            self.expect_block_nl()

            fields: List[str] = []
            field_types: List[Optional[str]] = []
            field_optional: List[bool] = []
            methods: List[FunctionDef] = []

            while not self.is_end_of("struct"):
                # allow blank lines / semicolons inside the block
                self.skip_stmt_seps()
                if self.is_end_of("struct"):
                    break
                if self.peek().kind == "EOF":
                    raise ParseError(f"struct ended unexpectedly (missing 'end struct'?) (block started at {self._fmt_pos(start_pos)})", self.peek().pos)

                # Statically dispatched operator overload.  The owning value is
                # always the first explicit operand; no implicit `this` exists.
                if self.peek().kind == "KW" and self.peek().value == "operator":
                    op_start = self.advance().pos
                    op_inline = False
                    if self.peek().kind == "KW" and self.peek().value == "inline":
                        self.advance()
                        op_inline = True

                    op_tok = self.peek()
                    if op_tok.kind == "OP" or (op_tok.kind == "KW" and op_tok.value == "not"):
                        op_symbol = self.advance().value
                    else:
                        raise ParseError("Expected a supported operator after 'operator'", op_tok.pos)

                    self.expect("LPAREN")
                    op_params, op_types, op_optional, op_defaults, op_variadic = self.parse_parameters()
                    op_name_base = operator_method_name(op_symbol, len(op_params))
                    if op_name_base is None:
                        raise ParseError(f"Operator '{op_symbol}' does not support {len(op_params)} operand(s)", op_tok.pos)
                    if op_variadic >= 0 or any(default is not None for default in op_defaults):
                        raise ParseError("Operator parameters cannot be variadic or have default values", op_start)
                    if any(ty is None for ty in op_types) or any(op_optional):
                        raise ParseError("Every operator operand requires a non-optional type", op_start)
                    first_type = str(op_types[0])
                    if first_type.rsplit(".", 1)[-1] != name:
                        raise ParseError(f"The first operator operand must have the owning struct type '{name}'", op_start)

                    if not (self.peek().kind == "KW" and self.peek().value == "returns"):
                        raise ParseError("Operator declarations require an explicit return type", self.peek().pos)
                    self.advance()
                    op_return_type, op_return_optional = self.parse_type_ref()
                    if op_return_optional:
                        raise ParseError("Operator return types cannot be optional", op_start)
                    if op_return_type.lower() == "void":
                        raise ParseError("Operator return types cannot be void", op_start)
                    if op_symbol in ("==", "!=", "<", "<=", ">", ">=", "not") and op_return_type.lower() not in ("bool", "boolean"):
                        raise ParseError(f"Operator '{op_symbol}' must return bool", op_start)

                    same_operator = [method for method in methods
                                     if str(getattr(method, 'name', '')).startswith(op_name_base + "__overload_")]
                    if any(list(getattr(method, 'param_types', []) or []) == list(op_types)
                           for method in same_operator):
                        raise ParseError(f"Duplicate operator '{op_symbol}' signature", op_start)
                    op_name = op_name_base + "__overload_" + str(len(same_operator))

                    self.expect_block_nl()
                    self._func_depth += 1
                    try:
                        op_body = self.parse_block_until_end("operator", op_start)
                    finally:
                        self._func_depth -= 1
                    self.expect_end_of("operator")
                    operator_fn = self._attach_pos(FunctionDef(
                        op_name, op_params, op_body, is_static=True, is_inline=op_inline,
                        param_types=op_types, param_optional=op_optional,
                        param_defaults=op_defaults, variadic_index=-1,
                        return_type=op_return_type, return_optional=False), op_start)
                    methods.append(self._apply_function_contracts(operator_fn))
                    continue

                # method inside struct (instance or static)
                if self.peek().kind == "KW" and self.peek().value in ("function", "static"):
                    m_start = self.peek().pos
                    is_static = False
                    if self.peek().value == "static":
                        is_static = True
                        self.advance()
                        self.skip_newlines()
                        self.expect("KW", "function")
                    else:
                        self.advance()

                    is_inline = False
                    is_synchronized = False
                    while self.peek().kind == "KW" and self.peek().value in ("inline", "synchronized"):
                        modifier = self.advance().value
                        if modifier == "inline":
                            if is_inline:
                                raise ParseError("duplicate function modifier 'inline'", self.peek().pos)
                            is_inline = True
                        else:
                            if is_synchronized:
                                raise ParseError("duplicate function modifier 'synchronized'", self.peek().pos)
                            is_synchronized = True

                    m_name_tok = self.expect("IDENT")
                    if m_name_tok.value.startswith("__operator_"):
                        raise ParseError("Method names beginning with '__operator_' are reserved", m_name_tok.pos)
                    self.expect("LPAREN")
                    m_params, m_types, m_optional, m_defaults, m_variadic = self.parse_parameters()
                    m_return_type: Optional[str] = None
                    m_return_optional = False
                    if self.peek().kind == "KW" and self.peek().value == "returns":
                        self.advance()
                        m_return_type, m_return_optional = self.parse_type_ref()

                    self.expect_block_nl()
                    self._func_depth += 1
                    try:
                        m_body = self.parse_block_until_end("function", m_start)
                    finally:
                        self._func_depth -= 1
                    self.expect_end_of("function")

                    method = self._attach_pos(FunctionDef(m_name_tok.value, m_params, m_body, is_static=is_static,
                                                           is_inline=is_inline, is_synchronized=is_synchronized,
                                                           param_types=m_types, param_optional=m_optional,
                                                           param_defaults=m_defaults, variadic_index=m_variadic,
                                                           return_type=m_return_type,
                                                           return_optional=m_return_optional), m_start)
                    methods.append(self._apply_function_contracts(method))
                    continue

                # field (allow comma-separated lists + trailing commas)
                fields.append(self.expect("IDENT").value)
                fty: Optional[str] = None
                fopt = False
                if self.peek().kind == "KW" and self.peek().value == "as":
                    self.advance()
                    fty, fopt = self.parse_type_ref()
                field_types.append(fty)
                field_optional.append(fopt)
                while self.match("COMMA"):
                    # If we see a newline after a comma, continue the field list only if the
                    # next non-newline token is an identifier; otherwise treat it as a trailing comma.
                    if self.peek().kind == "NL":
                        nxt = self.peek_non_nl()
                        if nxt.kind != "IDENT":
                            break
                        self.skip_newlines()
                    if self.peek().kind != "IDENT":
                        break
                    fields.append(self.expect("IDENT").value)
                    fty = None
                    fopt = False
                    if self.peek().kind == "KW" and self.peek().value == "as":
                        self.advance()
                        fty, fopt = self.parse_type_ref()
                    field_types.append(fty)
                    field_optional.append(fopt)
                self.expect_block_nl()

            self.expect_end_of("struct")
            return self._attach_pos(StructDef(name, fields, methods, field_types, field_optional, interfaces), start_pos)

        # enum
        if t.kind == "KW" and t.value == "enum":
            self.advance()
            name = self.expect("IDENT").value
            # `are` is optional (legacy)
            if self.peek().kind == "KW" and self.peek().value == "are":
                self.advance()
            self.expect_block_nl()

            variants: List[str] = []
            values: List[Optional[Expr]] = []
            while not self.is_end_of("enum"):
                # allow blank lines / semicolons inside the block
                self.skip_stmt_seps()
                if self.is_end_of("enum"):
                    break
                if self.peek().kind == "EOF":
                    raise ParseError(f"enum ended unexpectedly (missing 'end enum'?) (block started at {self._fmt_pos(start_pos)})", self.peek().pos)

                # Variants may optionally have explicit values:
                #   X
                #   X = 123
                #   X = 0x01
                #   X = "hello"
                # Comma-separated lists and trailing commas are supported.
                vname = self.expect("IDENT").value
                vexpr: Optional[Expr] = None
                if self.match("OP", "="):
                    vexpr = self.parse_expr()
                variants.append(vname)
                values.append(vexpr)

                while self.match("COMMA"):
                    if self.peek().kind == "NL":
                        nxt = self.peek_non_nl()
                        if nxt.kind != "IDENT":
                            break
                        self.skip_newlines()
                    if self.peek().kind != "IDENT":
                        break
                    vname = self.expect("IDENT").value
                    vexpr = None
                    if self.match("OP", "="):
                        vexpr = self.parse_expr()
                    variants.append(vname)
                    values.append(vexpr)

                self.expect_block_nl()

            self.expect_end_of("enum")
            return self._attach_pos(EnumDef(name, variants, values), start_pos)

        # loop ... while <cond> end loop  (do-while)
        # (legacy syntax still accepted: end loop while <cond>)
        if t.kind == "KW" and t.value == "loop":
            self.advance()
            self.expect_block_nl()

            body: List[Stmt] = []
            self.skip_stmt_seps()

            while True:
                # New syntax footer: while <cond> end loop
                # To avoid ambiguity with a normal `while` statement, we only treat this as the
                # loop footer if `end loop` follows immediately after the condition.
                if self.peek().kind == "KW" and self.peek().value == "while":
                    save_i = self.i
                    self.advance()  # 'while'
                    cond = self.parse_expr()

                    self.skip_stmt_seps()
                    if self.is_end_of("loop"):
                        self.expect_end_of("loop")
                        return self._attach_pos(DoWhile(body, cond), start_pos)

                    # Not a footer => it's a normal `while` statement in the body.
                    self.i = save_i

                # Legacy syntax: end loop while <cond>
                if self.is_end_of("loop"):
                    self.expect_end_of("loop")
                    self.expect("KW", "while")
                    cond = self.parse_expr()
                    return self._attach_pos(DoWhile(body, cond), start_pos)

                if self.peek().kind == "EOF":
                    raise ParseError(f"loop ended unexpectedly (missing 'end loop'?) (block started at {self._fmt_pos(start_pos)})", self.peek().pos)

                body.append(self.parse_stmt())
                self.skip_stmt_seps()

        # switch/match expr. `match` is the pattern-oriented spelling and shares
        # value/range semantics with switch. Destructuring and guarded patterns
        # are deliberately left for a future extension.
        if ((t.kind == "KW" and t.value == "switch")
                or (t.kind in ("IDENT", "KW") and t.value == "match"
                    and self.peek2().kind not in ("OP", "DOT"))):
            block_kind = t.value
            self.advance()
            expr = self.parse_expr()
            self.expect_block_nl()

            cases: List[SwitchCase] = []
            default_body: List[Stmt] = []

            while True:
                if self.peek().kind == "KW" and self.peek().value == "case":
                    case_pos = self.peek().pos
                    self.advance()

                    # case default
                    if self.peek().kind == "KW" and self.peek().value == "default":
                        self.advance()
                        self.expect_block_nl()
                        default_body = self.parse_block_until_end("case", case_pos)
                        self.expect_end_of("case")
                        self.skip_stmt_seps()
                        continue

                    # parse first expr
                    first = self.parse_expr()

                    # range case: case A to B
                    if self.peek().kind == "KW" and self.peek().value == "to":
                        self.advance()
                        end_expr = self.parse_expr()
                        self.expect_block_nl()
                        body = self.parse_block_until_end("case", case_pos)
                        self.expect_end_of("case")
                        cases.append(SwitchCase("range", [], first, end_expr, body))
                        self.skip_stmt_seps()
                        continue

                    # multi-value case: case X, Y, Z
                    values = [first]
                    while self.match("COMMA"):
                        # Allow trailing commas and multiline case value lists.
                        # A newline after ',' continues the header only for "safe" starts
                        # (literals/primaries), otherwise it is treated as a trailing comma
                        # before the case body.
                        if self.peek().kind == "NL":
                            nxt = self.peek_non_nl()
                            if not self._is_case_value_continuation_start(nxt):
                                break  # trailing comma
                            self.skip_newlines()
                        values.append(self.parse_expr())

                    self.expect_block_nl()
                    body = self.parse_block_until_end("case", case_pos)
                    self.expect_end_of("case")
                    cases.append(SwitchCase("values", values, None, None, body))
                    self.skip_stmt_seps()
                    continue

                break

            self.expect_end_of(block_kind)
            return self._attach_pos(Switch(expr, cases, default_body), start_pos)

        # if cond then ... [else if ...] [else ...] end if
        if t.kind == "KW" and t.value == "if":
            self.advance()
            cond = self.parse_expr()
            self.expect("KW", "then")
            # NEWLINE after 'then' is optional (supports inline if)

            then_body = self.parse_block_until({"else"}, end_type="if", start_pos=start_pos)

            elifs: List[Tuple[Expr, List[Stmt]]] = []
            else_body: List[Stmt] = []

            while self.peek().kind == "KW" and self.peek().value == "else":
                self.advance()

                # else if ... then
                if self.peek().kind == "KW" and self.peek().value == "if":
                    self.advance()
                    econd = self.parse_expr()
                    self.expect("KW", "then")
                    # NEWLINE after 'then' is optional (supports inline if)
                    ebody = self.parse_block_until({"else"}, end_type="if", start_pos=start_pos)
                    elifs.append((econd, ebody))
                    continue

                # else
                # NEWLINE after 'else' is optional (supports inline if)
                else_body = self.parse_block_until(set(), end_type="if", start_pos=start_pos)
                break

            self.expect_end_of("if")
            return self._attach_pos(If(cond, then_body, elifs, else_body), start_pos)

        # while cond ... end while
        if t.kind == "KW" and t.value == "while":
            self.advance()
            cond = self.parse_expr()
            self.expect_block_nl()
            body = self.parse_block_until_end("while", start_pos)
            self.expect_end_of("while")
            return self._attach_pos(While(cond, body), start_pos)

        # for ... / for each ...
        if t.kind == "KW" and t.value == "for":
            self.advance()

            if self.peek().kind == "KW" and self.peek().value == "each":
                self.advance()
                varname = self.expect("IDENT").value
                self.expect("KW", "in")
                iterable = self.parse_expr()
                self.expect_block_nl()
                body = self.parse_block_until_end("for", start_pos)
                self.expect_end_of("for")
                return self._attach_pos(ForEach(varname, iterable, body), start_pos)

            varname = self.expect("IDENT").value
            self.expect("OP", "=")
            start = self.parse_expr()
            self.expect("KW", "to")
            end = self.parse_expr()
            self.expect_block_nl()
            body = self.parse_block_until_end("for", start_pos)
            self.expect_end_of("for")
            return self._attach_pos(For(varname, start, end, body), start_pos)

        # Assignment or call statement.
        if t.kind == "IDENT":
            expr = self.parse_postfix()

            declared_type: Optional[str] = None
            declared_optional = False
            if isinstance(expr, Var) and self.peek().kind == "KW" and self.peek().value == "as":
                self.advance()
                declared_type, declared_optional = self.parse_type_ref()

            assignment_op: Optional[str] = None
            if self.peek().kind == "OP" and self.peek().value in ({"="} | set(COMPOUND_ASSIGNMENT_OPERATORS)):
                assignment_op = self.advance().value

            if assignment_op is not None:
                rhs = self.parse_expr()

                if assignment_op != "=":
                    if declared_type is not None:
                        raise ParseError("A compound assignment cannot redeclare a variable type", start_pos)
                    if not isinstance(expr, Var):
                        raise ParseError("Compound assignment currently requires a variable target", start_pos)
                    rhs = self._attach_pos(Bin(expr, COMPOUND_ASSIGNMENT_OPERATORS[assignment_op], rhs), start_pos)

                if isinstance(expr, Var):
                    rhs = self._guard_expr(rhs, declared_type, declared_optional, start_pos)
                    return self._attach_pos(Assign(expr.name, rhs, declared_type, declared_optional), start_pos)
                if isinstance(expr, Member):
                    return self._attach_pos(SetMember(expr.target, expr.name, rhs), start_pos)
                if isinstance(expr, Index):
                    return self._attach_pos(SetIndex(expr.target, expr.index, rhs), start_pos)

                raise ParseError("Invalid assignment target (lvalue)", start_pos)

            if declared_type is not None:
                raise ParseError("A typed variable declaration requires '='", start_pos)

            if isinstance(expr, Call):
                return self._attach_pos(ExprStmt(expr), start_pos)

            raise ParseError("Only assignments or function calls are allowed as a statement", start_pos)

        raise ParseError(f"Unknown statement: {t.kind}:{t.value}", t.pos)

    def parse_block_until_end(self, end_type: str, start_pos: int | None = None) -> List[Stmt]:
        stmts: List[Stmt] = []
        self.skip_stmt_seps()
        while True:
            if self.is_end_of(end_type):
                break
            if self.peek().kind == "EOF":
                loc = f" (block started at {self._fmt_pos(start_pos)})" if start_pos is not None else ""
                raise ParseError(f"Block ended unexpectedly (missing 'end {end_type}'?){loc}", self.peek().pos)
            if self.collect_errors:
                st = self._parse_stmt_recover(end_type=end_type)
                if st is not None:
                    stmts.append(st)
                else:
                    if len(self.errors) >= self.max_errors:
                        break
            else:
                stmts.append(self.parse_stmt())
            self.skip_stmt_seps()
        return stmts

    def parse_block_until(self, stop_keywords: set[str], end_type: Optional[str] = None, start_pos: int | None = None) -> List[Stmt]:
        stmts: List[Stmt] = []
        self.skip_stmt_seps()
        while True:
            t = self.peek()

            if t.kind == "KW" and t.value in stop_keywords:
                break

            if end_type is not None and self.is_end_of(end_type):
                break

            if t.kind == "EOF":
                wanted = f"end {end_type}" if end_type else "end <...>"
                loc = f" (block started at {self._fmt_pos(start_pos)})" if start_pos is not None else ""
                raise ParseError(f"Block ended unexpectedly (missing '{wanted}'?){loc}", t.pos)

            if self.collect_errors:
                st = self._parse_stmt_recover(stop_keywords=set(stop_keywords), end_type=end_type)
                if st is not None:
                    stmts.append(st)
                else:
                    if len(self.errors) >= self.max_errors:
                        break
            else:
                stmts.append(self.parse_stmt())
            self.skip_stmt_seps()
        return stmts

    # ----------------------------
    # Expressions
    # ----------------------------

    def parse_expr(self, min_prec: int = 0) -> Expr:
        """Parse an expression using precedence climbing.

        Positions:
            Every expression node created here is annotated with a private `_pos` (absolute character offset).
            This enables precise error reporting in later compiler stages (e.g. undefined variables inside expressions).
        """
        left = self.parse_unary()

        while True:
            tok = self.peek()
            op: Optional[str] = None

            if tok.kind == "OP":
                op = tok.value
            elif tok.kind == "KW" and tok.value in ("and", "or", "is"):
                op = tok.value

            if op is None or op not in PRECEDENCE:
                break

            prec = PRECEDENCE[op]
            if prec < min_prec:
                break

            self.advance()
            # Allow expression continuation across newlines after an operator.
            # Example:
            #   x = 1 +\n    2
            self.skip_newlines()

            # `is` operator:
            # - For primitive categories: sugar to `typeof(x) == "..."` (optionally negated)
            # - For named struct/enum types: keep as IsType(expr, "Name") and resolve later in codegen
            if op == "is":
                is_start = tok.pos
                is_not = False
                if self.peek().kind == "KW" and self.peek().value == "not":
                    is_not = True
                    self.advance()
                    self.skip_newlines()

                # Parse a type name token sequence (IDENT/KW with optional dotted segments)
                ty_tok = self.peek()
                if ty_tok.kind not in ("IDENT", "KW"):
                    raise ParseError("Expected type name after 'is'", ty_tok.pos)
                parts = [str(ty_tok.value)]
                self.advance()
                # allow dotted qualified names: Foo.Bar.Baz
                while self.peek().kind == "OP" and self.peek().value == ".":
                    dot = self.peek()
                    self.advance()
                    seg = self.peek()
                    if seg.kind != "IDENT":
                        raise ParseError("Expected identifier after '.' in type name", seg.pos)
                    parts.append(str(seg.value))
                    self.advance()

                ty_raw = ".".join(parts)
                ty_l = ty_raw.lower()
                _aliases = {"integer": "int", "boolean": "bool", "str": "string"}
                # Only apply aliases / canonicalization for non-qualified primitive names
                ty_canon = _aliases.get(ty_l, ty_l) if "." not in ty_raw else ty_raw

                _allowed = {"int", "float", "bool", "string", "array", "bytes", "function", "struct", "enum", "error", "thread", "void", "unknown"}

                start_pos = getattr(left, "_pos", None)
                if start_pos is None:
                    start_pos = is_start

                if isinstance(ty_canon, str) and ty_canon in _allowed:
                    # typeof(left)
                    typeof_call = self._attach_pos(Call(self._attach_pos(Var("typeof"), is_start), [left]), start_pos)
                    rhs = self._attach_pos(Str(ty_canon), ty_tok.pos)
                    cmp_expr = self._attach_pos(Bin(typeof_call, "==", rhs), start_pos)
                    if is_not:
                        left = self._attach_pos(Unary("not", cmp_expr), start_pos)
                    else:
                        left = cmp_expr
                else:
                    # Named type check (struct/enum): resolved by codegen
                    left = self._attach_pos(IsType(left, ty_raw, is_not), start_pos)
                continue
            right = self.parse_expr(prec + 1)

            start_pos = getattr(left, "_pos", None)
            if start_pos is None:
                start_pos = tok.pos
            if op == "??":
                left = self._attach_pos(Coalesce(left, right), start_pos)
            else:
                left = self._attach_pos(Bin(left, op, right), start_pos)

        return left

    def parse_unary(self) -> Expr:
        """Parse unary expressions (prefix operators) or fall back to postfix parsing."""
        t = self.peek()

        if t.kind == "OP" and t.value == "+":
            start_pos = t.pos
            self.advance()
            self.skip_newlines()
            return self._attach_pos(Unary("+", self.parse_unary()), start_pos)

        if t.kind == "OP" and t.value == "-":
            start_pos = t.pos
            self.advance()
            # Allow newline after unary operator.
            self.skip_newlines()
            return self._attach_pos(Unary("-", self.parse_unary()), start_pos)

        if t.kind == "OP" and t.value == "~":
            start_pos = t.pos
            self.advance()
            self.skip_newlines()
            return self._attach_pos(Unary("~", self.parse_unary()), start_pos)

        if t.kind == "KW" and t.value == "not":
            start_pos = t.pos
            self.advance()
            self.skip_newlines()
            return self._attach_pos(Unary("not", self.parse_unary()), start_pos)

        if t.kind == "KW" and t.value == "await":
            start_pos = t.pos
            self.advance()
            self.skip_newlines()
            callee = self._attach_pos(Var("__ml_await"), start_pos)
            return self._attach_pos(Call(callee, [self.parse_unary()]), start_pos)

        return self.parse_postfix()
    def parse_postfix(self) -> Expr:
        """Parse postfix operators: calls, indexing, and member access."""
        expr = self.parse_primary()

        while True:
            # Call
            if self.peek().kind == "LPAREN":
                call_start = getattr(expr, "_pos", None)
                if call_start is None:
                    call_start = self.peek().pos

                self.advance()

                # typeof(...) arguments are parsed as normal expressions.
                # Qualified-name handling (e.g. typeof(ns.Struct) / typeof(ns.Enum.Variant)) is
                # resolved later during codegen. This avoids incorrectly treating runtime member
                # access like typeof(t.value) as a qualified symbol "t.value".
                args, arg_names = self.parse_call_arguments()

                expr = self._attach_pos(Call(expr, args, arg_names), call_start)
                continue

            # Indexing
            if self.peek().kind == "LBRACK":
                idx_start = getattr(expr, "_pos", None)
                if idx_start is None:
                    idx_start = self.peek().pos

                self.advance()
                self.skip_newlines()
                idx = self.parse_expr()
                self.skip_newlines()
                self.expect("RBRACK")
                expr = self._attach_pos(Index(expr, idx), idx_start)
                continue

            # Member access
            if self.peek().kind == "DOT":
                mem_start = getattr(expr, "_pos", None)
                if mem_start is None:
                    mem_start = self.peek().pos

                self.advance()
                name_tok = self.expect("IDENT")
                expr = self._attach_pos(Member(expr, name_tok.value), mem_start)
                continue

            # Optional chaining. Calls following this member are handled by the
            # normal call parser and remain void-safe because the callee is void.
            if self.peek().kind == "SAFEDOT":
                mem_start = getattr(expr, "_pos", None)
                if mem_start is None:
                    mem_start = self.peek().pos
                self.advance()
                name_tok = self.expect("IDENT")
                expr = self._attach_pos(SafeMember(expr, name_tok.value), mem_start)
                continue

            break

        return expr
    def parse_primary(self) -> Expr:
        """Parse primary expressions: literals, identifiers, parenthesized expressions, arrays."""
        t = self.peek()

        if t.kind == "LPAREN":
            start_pos = t.pos
            self.advance()
            expr = self.parse_expr()
            self.expect("RPAREN")
            # Keep the inner expression's position if present, otherwise fall back to '('.
            if getattr(expr, "_pos", None) is None:
                self._attach_pos(expr, start_pos)
            return expr

        if t.kind == "LBRACK":
            start_pos = t.pos
            self.advance()
            items = self.parse_delimited_list("RBRACK", self.parse_expr)
            return self._attach_pos(ArrayLit(items), start_pos)

        # Expression-bodied anonymous function. It is lowered to a regular
        # nested function so it automatically inherits the closure machinery.
        # Example: `mapper = function(x as int) => x + 1`.
        if t.kind == "KW" and t.value == "function":
            start_pos = t.pos
            self.advance()
            self.expect("LPAREN")
            params, ptypes, poptional, pdefaults, variadic = self.parse_parameters()
            if variadic >= 0 or any(default is not None for default in pdefaults):
                raise ParseError("Lambda parameters do not support default or variadic arguments", start_pos)
            return_type: Optional[str] = None
            return_optional = False
            if self.peek().kind == "KW" and self.peek().value == "returns":
                self.advance()
                return_type, return_optional = self.parse_type_ref()
            self.expect("OP", "=>")
            value = self.parse_expr()
            value = self._guard_expr(value, return_type, return_optional, start_pos)
            body: List[Stmt] = [self._attach_pos(Return(value), start_pos)]
            return self._attach_pos(Lambda(params, body, ptypes, poptional, pdefaults, variadic,
                                           return_type, return_optional), start_pos)

        # `select(a, b, ...)` waits until one async handle completes and returns
        # its zero-based index. The helper is injected only when used.
        if (t.kind in ("IDENT", "KW") and t.value == "select"
                and self.peek2().kind == "LPAREN"):
            start_pos = t.pos
            self.advance()
            self.expect("LPAREN")
            args, names = self.parse_call_arguments()
            if any(name is not None for name in names):
                raise ParseError("select does not accept named arguments", start_pos)
            return self._attach_pos(Call(self._attach_pos(Var("__ml_select"), start_pos),
                                         [self._attach_pos(ArrayLit(args), start_pos)]), start_pos)

        if t.kind == "NUMBER":
            start_pos = t.pos
            self.advance()
            if "." in t.value:
                return self._attach_pos(Num(float(t.value)), start_pos)
            # allow hex (0x..), binary (0b..); keep plain int() for decimal with leading zeros
            if re.match(r"0[xX]", t.value) or re.match(r"0[bB]", t.value):
                return self._attach_pos(Num(wrap_i61(int(t.value, 0))), start_pos)
            return self._attach_pos(Num(wrap_i61(int(t.value))), start_pos)

        if t.kind == "STRING":
            start_pos = t.pos
            self.advance()
            raw = t.value[1:-1]
            val = self._decode_string_raw(raw, t.pos)
            return self._attach_pos(Str(val), start_pos)

        if t.kind == "KW" and t.value in ("true", "false"):
            start_pos = t.pos
            self.advance()
            return self._attach_pos(Bool(t.value == "true"), start_pos)

        

        if t.kind == "KW" and t.value == "void":
            start_pos = t.pos
            self.advance()
            return self._attach_pos(VoidLit(), start_pos)

        if t.kind == "IDENT":
            start_pos = t.pos
            self.advance()
            return self._attach_pos(Var(t.value), start_pos)

        raise ParseError(f"Unexpected expression: {t.kind}:{t.value}", t.pos)


# ============================================================
# Backward-compatible lowering for high-level language features
# ============================================================

def _copy_source_pos(dst: Any, src: Any) -> Any:
    for attr in ("_pos", "_filename"):
        if hasattr(src, attr):
            setattr(dst, attr, getattr(src, attr))
    return dst


class _LanguageLowerer:
    """Lower closures, generators and async sugar to the stable core AST."""

    def __init__(self) -> None:
        self.serial = 0
        self.needs_await = False
        self.needs_select = False
        self.await_source: Optional[Expr] = None
        self.select_source: Optional[Expr] = None
        self.needs_async_pool = False
        self.async_pool_name = "__ml_async_pool_global"

    def fresh(self, stem: str) -> str:
        self.serial += 1
        return f"__ml_{stem}_{self.serial}"

    def lower_expr(self, expr: Optional[Expr], prelude: List[Stmt]) -> Optional[Expr]:
        if expr is None:
            return None
        if isinstance(expr, Lambda):
            name = self.fresh("lambda")
            body = self.lower_block(expr.body, function_depth=1)
            guards: List[Stmt] = []
            for i, param in enumerate(expr.params):
                ty = expr.param_types[i] if i < len(expr.param_types) else None
                if ty:
                    optional = expr.param_optional[i] if i < len(expr.param_optional) else False
                    guards.append(_copy_source_pos(Assign(param, TypeGuard(Var(param), ty, optional), ty, optional), expr))
            fn = FunctionDef(name, list(expr.params), guards + body,
                             param_types=list(expr.param_types), param_optional=list(expr.param_optional),
                             param_defaults=list(expr.param_defaults), variadic_index=expr.variadic_index,
                             return_type=expr.return_type, return_optional=expr.return_optional)
            prelude.append(_copy_source_pos(fn, expr))
            return _copy_source_pos(Var(name), expr)
        if isinstance(expr, Call):
            expr.callee = self.lower_expr(expr.callee, prelude)
            expr.args = [self.lower_expr(x, prelude) for x in expr.args]
            if isinstance(expr.callee, Var) and expr.callee.name == "__ml_await":
                self.needs_await = True
                if self.await_source is None:
                    self.await_source = expr
            if isinstance(expr.callee, Var) and expr.callee.name == "__ml_select":
                self.needs_select = True
                if self.select_source is None:
                    self.select_source = expr
            return expr
        if isinstance(expr, (Member, SafeMember)):
            expr.target = self.lower_expr(expr.target, prelude)
            return expr
        if isinstance(expr, Index):
            expr.target = self.lower_expr(expr.target, prelude)
            expr.index = self.lower_expr(expr.index, prelude)
            return expr
        if isinstance(expr, ArrayLit):
            expr.items = [self.lower_expr(x, prelude) for x in expr.items]
            return expr
        if isinstance(expr, Unary):
            expr.right = self.lower_expr(expr.right, prelude)
            return expr
        if isinstance(expr, Bin):
            expr.left = self.lower_expr(expr.left, prelude)
            expr.right = self.lower_expr(expr.right, prelude)
            return expr
        if isinstance(expr, Coalesce):
            expr.left = self.lower_expr(expr.left, prelude)
            expr.right = self.lower_expr(expr.right, prelude)
            return expr
        if isinstance(expr, (IsType, TypeGuard)):
            expr.expr = self.lower_expr(expr.expr, prelude)
            return expr
        return expr

    def lower_stmt(self, st: Stmt, function_depth: int) -> List[Stmt]:
        prelude: List[Stmt] = []
        if isinstance(st, NamespaceDef):
            st.body = self.lower_block(st.body, function_depth=function_depth)
        elif isinstance(st, FunctionDef):
            for i, default in enumerate(st.param_defaults):
                if default is not None:
                    st.param_defaults[i] = self.lower_expr(default, prelude)
            st.body = self.lower_block(st.body, function_depth=function_depth + 1)
            if st.is_iterator:
                if int(st.is_iterator) == 2:
                    self.lower_lazy_iterator(st)
                else:
                    self.lower_iterator(st)
            if st.is_async:
                if function_depth > 0:
                    raise ParseError("async functions must be declared at module or namespace scope", getattr(st, "_pos", 0))
                return prelude + self.lower_async(st)
        elif isinstance(st, StructDef):
            for method in st.methods:
                for i, default in enumerate(method.param_defaults):
                    if default is not None:
                        method.param_defaults[i] = self.lower_expr(default, prelude)
                method.body = self.lower_block(method.body, function_depth=function_depth + 1)
                if method.is_iterator:
                    if int(method.is_iterator) == 2:
                        self.lower_lazy_iterator(method)
                    else:
                        self.lower_iterator(method)
                if method.is_async:
                    raise ParseError("async struct methods are not supported; use a module-level async function", getattr(method, "_pos", 0))
        elif isinstance(st, If):
            st.cond = self.lower_expr(st.cond, prelude)
            st.then_body = self.lower_block(st.then_body, function_depth)
            st.elifs = [(self.lower_expr(c, prelude), self.lower_block(b, function_depth)) for c, b in st.elifs]
            st.else_body = self.lower_block(st.else_body, function_depth)
        elif isinstance(st, (While, DoWhile)):
            st.cond = self.lower_expr(st.cond, prelude)
            st.body = self.lower_block(st.body, function_depth)
        elif isinstance(st, For):
            st.start = self.lower_expr(st.start, prelude)
            st.end = self.lower_expr(st.end, prelude)
            st.body = self.lower_block(st.body, function_depth)
        elif isinstance(st, ForEach):
            st.iterable = self.lower_expr(st.iterable, prelude)
            st.body = self.lower_block(st.body, function_depth)
        elif isinstance(st, SynchronizedBlock):
            st.lock = self.lower_expr(st.lock, prelude)
            st.body = self.lower_block(st.body, function_depth)
        elif isinstance(st, Switch):
            st.expr = self.lower_expr(st.expr, prelude)
            for case in st.cases:
                case.values = [self.lower_expr(x, prelude) for x in case.values]
                case.range_start = self.lower_expr(case.range_start, prelude)
                case.range_end = self.lower_expr(case.range_end, prelude)
                case.body = self.lower_block(case.body, function_depth)
            st.default_body = self.lower_block(st.default_body, function_depth)
        else:
            for attr in ("expr", "cond", "target", "index", "start", "end"):
                if hasattr(st, attr):
                    setattr(st, attr, self.lower_expr(getattr(st, attr), prelude))
            if isinstance(st, SetMember):
                st.obj = self.lower_expr(st.obj, prelude)
        return prelude + [st]

    def lower_block(self, body: List[Stmt], function_depth: int = 0) -> List[Stmt]:
        out: List[Stmt] = []
        for st in body:
            out.extend(self.lower_stmt(st, function_depth))
        return out

    def lower_iterator(self, fn: FunctionDef) -> None:
        """Implement `yield` as an allocation-efficient eager sequence builder.

        Arrays are MiniLang's native iterable protocol today. The lowering grows
        a private capacity buffer geometrically, avoiding quadratic array
        concatenation, and returns a tightly sized array to callers.
        """
        if fn.is_async:
            raise ParseError("A function cannot be both async and iterator", getattr(fn, "_pos", 0))
        suffix = self.fresh("iter")
        buf = suffix + "_buf"
        count = suffix + "_count"
        grown = suffix + "_grown"
        copy_i = suffix + "_copy_i"
        result = suffix + "_result"

        def v(name: str) -> Var:
            return _copy_source_pos(Var(name), fn)

        def n(value: int) -> Num:
            return _copy_source_pos(Num(value), fn)

        def call(name: str, args: List[Expr]) -> Call:
            return _copy_source_pos(Call(_copy_source_pos(Var(name), fn), args), fn)

        def append_yield(y: Yield) -> List[Stmt]:
            value: Expr = y.expr if y.expr is not None else _copy_source_pos(VoidLit(), y)
            if fn.return_type:
                value = _copy_source_pos(TypeGuard(value, fn.return_type, fn.return_optional), y)
            grow_body: List[Stmt] = [
                _copy_source_pos(Assign(grown, call("array", [Bin(call("len", [v(buf)]), "*", n(2)), VoidLit()])), y),
                _copy_source_pos(For(copy_i, n(0), Bin(v(count), "-", n(1)), [
                    _copy_source_pos(SetIndex(v(grown), v(copy_i), Index(v(buf), v(copy_i))), y)
                ]), y),
                _copy_source_pos(Assign(buf, v(grown)), y),
            ]
            return [
                _copy_source_pos(If(Bin(v(count), "==", call("len", [v(buf)])), grow_body, [], []), y),
                _copy_source_pos(SetIndex(v(buf), v(count), value), y),
                _copy_source_pos(Assign(count, Bin(v(count), "+", n(1))), y),
            ]

        def rewrite(body: List[Stmt]) -> List[Stmt]:
            out: List[Stmt] = []
            for st in body:
                if isinstance(st, Yield):
                    out.extend(append_yield(st))
                elif isinstance(st, Return):
                    raise ParseError("iterator functions use yield and cannot return a value", getattr(st, "_pos", 0))
                elif isinstance(st, If):
                    st.then_body = rewrite(st.then_body)
                    st.elifs = [(c, rewrite(b)) for c, b in st.elifs]
                    st.else_body = rewrite(st.else_body)
                    out.append(st)
                elif isinstance(st, (While, DoWhile, For, ForEach, SynchronizedBlock)):
                    st.body = rewrite(st.body)
                    out.append(st)
                elif isinstance(st, Switch):
                    for case in st.cases:
                        case.body = rewrite(case.body)
                    st.default_body = rewrite(st.default_body)
                    out.append(st)
                elif isinstance(st, FunctionDef):
                    out.append(st)
                else:
                    out.append(st)
            return out

        original = rewrite(fn.body)
        init = [
            _copy_source_pos(Assign(buf, call("array", [n(8), VoidLit()])), fn),
            _copy_source_pos(Assign(count, n(0)), fn),
        ]
        finish = [
            _copy_source_pos(Assign(result, call("array", [v(count), VoidLit()])), fn),
            _copy_source_pos(For(copy_i, n(0), Bin(v(count), "-", n(1)), [
                _copy_source_pos(SetIndex(v(result), v(copy_i), Index(v(buf), v(copy_i))), fn)
            ]), fn),
            _copy_source_pos(Return(v(result)), fn),
        ]
        fn.body = init + original + finish
        fn.is_iterator = False

    def lower_lazy_iterator(self, fn: FunctionDef) -> None:
        """Lower a pull iterator to a zero-argument closure state machine.

        The returned closure computes one `yield` per call and returns `void`
        after exhaustion. `for each` recognizes this callable pull protocol,
        so values are never materialized into an intermediate array.
        """
        if fn.is_async:
            raise ParseError("A function cannot be both async and iterator", getattr(fn, "_pos", 0))

        state_name = self.fresh("lazy_state")
        next_name = self.fresh("lazy_next")
        blocks: List[List[Stmt]] = []
        persistent: set[str] = {state_name}
        globals_declared: set[str] = set()

        def tagged(node: Any, src: Any = fn) -> Any:
            return _copy_source_pos(node, src)

        def reserve() -> int:
            blocks.append([])
            return len(blocks) - 1

        def jump(target: int, src: Any = fn) -> List[Stmt]:
            return [tagged(Assign(state_name, tagged(Num(target), src)), src), tagged(Continue(), src)]

        def contains_yield(st: Stmt) -> bool:
            if isinstance(st, Yield):
                return True
            if isinstance(st, FunctionDef):
                return False
            if isinstance(st, If):
                return (any(contains_yield(x) for x in st.then_body)
                        or any(contains_yield(x) for _, body in st.elifs for x in body)
                        or any(contains_yield(x) for x in st.else_body))
            if isinstance(st, Switch):
                return (any(contains_yield(x) for case in st.cases for x in case.body)
                        or any(contains_yield(x) for x in st.default_body))
            return any(contains_yield(x) for x in list(getattr(st, "body", []) or []))

        def collect_names(body: List[Stmt]) -> None:
            for st in body:
                if isinstance(st, GlobalDecl):
                    globals_declared.update(st.names)
                    continue
                if isinstance(st, (Assign, ConstDecl, SynchronizedDecl)):
                    persistent.add(str(st.name))
                elif isinstance(st, (For, ForEach)):
                    persistent.add(str(st.var))
                elif isinstance(st, FunctionDef):
                    persistent.add(str(st.name))
                    continue
                if isinstance(st, If):
                    collect_names(st.then_body)
                    for _, branch in st.elifs:
                        collect_names(branch)
                    collect_names(st.else_body)
                elif isinstance(st, Switch):
                    for case in st.cases:
                        collect_names(case.body)
                    collect_names(st.default_body)
                else:
                    collect_names(list(getattr(st, "body", []) or []))

        collect_names(fn.body)

        def compile_seq(body: List[Stmt], cont: int,
                        break_target: Optional[int] = None,
                        continue_target: Optional[int] = None) -> int:
            """Lower a statement sequence backwards into lazy iterator states."""
            current = cont
            for st in reversed(body):
                src = st
                if isinstance(st, Yield):
                    block = reserve()
                    value: Expr = st.expr if st.expr is not None else tagged(VoidLit(), st)
                    if fn.return_type:
                        value = tagged(TypeGuard(value, fn.return_type, fn.return_optional), st)
                    blocks[block] = [tagged(Assign(state_name, tagged(Num(current), st)), st),
                                     tagged(Return(value), st)]
                    current = block
                    continue
                if isinstance(st, Return):
                    raise ParseError("iterator functions use yield and cannot return a value", getattr(st, "_pos", 0))
                if isinstance(st, Break):
                    if int(getattr(st, "count", 1) or 1) != 1 or break_target is None:
                        raise ParseError("lazy iterators only support break for the innermost loop", getattr(st, "_pos", 0))
                    block = reserve()
                    blocks[block] = jump(break_target, src)
                    current = block
                    continue
                if isinstance(st, Continue):
                    if continue_target is None:
                        raise ParseError("continue outside a lazy-iterator loop", getattr(st, "_pos", 0))
                    block = reserve()
                    blocks[block] = jump(continue_target, src)
                    current = block
                    continue
                if isinstance(st, If):
                    then_entry = compile_seq(st.then_body, current, break_target, continue_target)
                    else_entry = compile_seq(st.else_body, current, break_target, continue_target)
                    elif_entries = [(cond, compile_seq(branch, current, break_target, continue_target))
                                    for cond, branch in st.elifs]
                    branch = reserve()
                    branch_elifs = [(cond, jump(entry, st)) for cond, entry in elif_entries]
                    blocks[branch] = [tagged(If(st.cond, jump(then_entry, st), branch_elifs,
                                                       jump(else_entry, st)), st)]
                    current = branch
                    continue
                if isinstance(st, While):
                    cond_block = reserve()
                    body_entry = compile_seq(st.body, cond_block, current, cond_block)
                    blocks[cond_block] = [tagged(If(st.cond, jump(body_entry, st), [], jump(current, st)), st)]
                    current = cond_block
                    continue
                if isinstance(st, DoWhile):
                    cond_block = reserve()
                    body_entry = compile_seq(st.body, cond_block, current, cond_block)
                    blocks[cond_block] = [tagged(If(st.cond, jump(body_entry, st), [], jump(current, st)), st)]
                    current = body_entry
                    continue
                if isinstance(st, For):
                    end_name = self.fresh("lazy_for_end")
                    step_name = self.fresh("lazy_for_step")
                    persistent.update((st.var, end_name, step_name))
                    cond_block = reserve()
                    inc_block = reserve()
                    body_entry = compile_seq(st.body, inc_block, current, inc_block)
                    positive = tagged(Bin(Var(step_name), ">", Num(0)), st)
                    within_up = tagged(Bin(Var(st.var), "<=", Var(end_name)), st)
                    within_down = tagged(Bin(Var(st.var), ">=", Var(end_name)), st)
                    condition = tagged(Bin(tagged(Bin(positive, "and", within_up), st), "or",
                                           tagged(Bin(tagged(Unary("not", positive), st), "and", within_down), st)), st)
                    blocks[cond_block] = [tagged(If(condition, jump(body_entry, st), [], jump(current, st)), st)]
                    blocks[inc_block] = [tagged(Assign(st.var, tagged(Bin(Var(st.var), "+", Var(step_name)), st)), st)] + jump(cond_block, st)
                    init_block = reserve()
                    blocks[init_block] = [
                        tagged(Assign(st.var, st.start), st),
                        tagged(Assign(end_name, st.end), st),
                        tagged(If(tagged(Bin(Var(st.var), "<=", Var(end_name)), st),
                                  [tagged(Assign(step_name, tagged(Num(1), st)), st)], [],
                                  [tagged(Assign(step_name, tagged(Num(-1), st)), st)]), st),
                    ] + jump(cond_block, st)
                    current = init_block
                    continue
                if isinstance(st, ForEach):
                    seq_name = self.fresh("lazy_each_seq")
                    index_name = self.fresh("lazy_each_index")
                    persistent.update((st.var, seq_name, index_name))
                    cond_block = reserve()
                    inc_block = reserve()
                    body_entry = compile_seq(st.body, inc_block, current, inc_block)
                    load_block = reserve()
                    blocks[load_block] = [tagged(Assign(st.var, tagged(Index(Var(seq_name), Var(index_name)), st)), st)] + jump(body_entry, st)
                    cond = tagged(Bin(Var(index_name), "<", tagged(Call(Var("len"), [Var(seq_name)]), st)), st)
                    blocks[cond_block] = [tagged(If(cond, jump(load_block, st), [], jump(current, st)), st)]
                    blocks[inc_block] = [tagged(Assign(index_name, tagged(Bin(Var(index_name), "+", Num(1)), st)), st)] + jump(cond_block, st)
                    init_block = reserve()
                    blocks[init_block] = [tagged(Assign(seq_name, st.iterable), st),
                                          tagged(Assign(index_name, tagged(Num(0), st)), st)] + jump(cond_block, st)
                    current = init_block
                    continue
                if isinstance(st, (Switch, SynchronizedBlock)) and contains_yield(st):
                    raise ParseError("yield inside match/switch or synchronized is not supported by lazy iterators",
                                     getattr(st, "_pos", 0))
                if isinstance(st, Defer):
                    raise ParseError("defer is not supported inside a lazy iterator", getattr(st, "_pos", 0))

                simple: Stmt = st
                if isinstance(st, ConstDecl):
                    simple = tagged(Assign(st.name, st.expr), st)
                block = reserve()
                blocks[block] = [simple] + jump(current, src)
                current = block
            return current

        done = reserve()
        blocks[done] = [tagged(Return(tagged(VoidLit(), fn)), fn)]
        entry = compile_seq(fn.body, done)

        cases: List[SwitchCase] = []
        for index, body in enumerate(blocks):
            case = tagged(SwitchCase("values", [tagged(Num(index), fn)], None, None, body), fn)
            cases.append(case)
        dispatch = tagged(Switch(tagged(Var(state_name), fn), cases,
                                 [tagged(Return(tagged(VoidLit(), fn)), fn)]), fn)
        next_fn = tagged(FunctionDef(next_name, [], [tagged(While(tagged(Bool(True), fn), [dispatch]), fn)]), fn)

        initializers: List[Stmt] = []
        for name in sorted(persistent - set(fn.params) - globals_declared - {state_name}):
            initializers.append(tagged(Assign(name, tagged(VoidLit(), fn)), fn))
        initializers.append(tagged(Assign(state_name, tagged(Num(entry), fn)), fn))
        fn.body = initializers + [next_fn, tagged(Return(tagged(Var(next_name), fn)), fn)]
        # The declared return type describes yielded elements, not the closure.
        fn.return_type = None
        fn.return_optional = False
        fn.is_iterator = False

    def lower_async(self, fn: FunctionDef) -> List[Stmt]:
        impl_name = self.fresh("async_impl")
        entry_name = self.fresh("async_entry")
        arg_name = self.fresh("async_args")
        self.needs_async_pool = True

        # The public wrapper has already packed the variadic tail into its last
        # parameter.  The internal implementation therefore receives ordinary
        # fixed arguments and must not pack that array a second time.
        impl = _copy_source_pos(FunctionDef(impl_name, list(fn.params), fn.body,
                                            param_types=list(fn.param_types), param_optional=list(fn.param_optional),
                                            variadic_index=-1, return_type=fn.return_type,
                                            return_optional=fn.return_optional), fn)
        forwarded = [_copy_source_pos(Index(Var(arg_name), Num(i)), fn) for i in range(len(fn.params))]
        entry_call = _copy_source_pos(Call(Var(impl_name), forwarded), fn)
        entry = _copy_source_pos(FunctionDef(entry_name, [arg_name], [Return(entry_call)]), fn)

        packed = _copy_source_pos(ArrayLit([Var(name) for name in fn.params]), fn)
        submit = _copy_source_pos(Call(Member(Var(self.async_pool_name), "Submit"),
                                       [Var(entry_name), packed]), fn)
        wrapper_body: List[Stmt] = [_copy_source_pos(Return(submit), fn)]
        wrapper = _copy_source_pos(FunctionDef(fn.name, list(fn.params), wrapper_body,
                                               is_static=fn.is_static,
                                               param_types=list(fn.param_types), param_optional=list(fn.param_optional),
                                               param_defaults=list(fn.param_defaults), variadic_index=fn.variadic_index,
                                               return_type=None, return_optional=False), fn)
        return [impl, entry, wrapper]

    def await_helper(self) -> FunctionDef:
        value = Var("value")
        is_thread = Bin(Call(Var("typeof"), [value]), "==", Str("thread"))
        is_job = IsType(value, "std.concurrent.thread_pool.ThreadPoolJob", False)
        body: List[Stmt] = [
            If(is_thread, [ExprStmt(Call(Member(value, "Join"), [])), Return(Call(Member(value, "Result"), []))], [], []),
            If(is_job, [ExprStmt(Call(Member(value, "Wait"), [])), Return(Call(Member(value, "GetResult"), []))], [], []),
            Return(value),
        ]
        return FunctionDef("__ml_await", ["value"], body)

    def select_helper(self) -> FunctionDef:
        handles = Var("handles")
        idx = Var("__ml_select_i")
        handle = Var("__ml_select_handle")
        valid = Bin(Call(Var("typeof"), [handles]), "==", Str("array"))
        nonempty = Bin(Call(Var("len"), [handles]), ">", Num(0))
        is_thread = Bin(Call(Var("typeof"), [handle]), "==", Str("thread"))
        is_job = IsType(handle, "std.concurrent.thread_pool.ThreadPoolJob", False)
        completed_thread = Bin(is_thread, "and", Unary("not", Call(Member(handle, "IsAlive"), [])))
        completed_job = Bin(is_job, "and", Call(Member(handle, "IsDone"), []))
        completed = Bin(completed_thread, "or", completed_job)
        loop = While(Bool(True), [
            For("__ml_select_i", Num(0), Bin(Call(Var("len"), [handles]), "-", Num(1)), [
                Assign("__ml_select_handle", Index(handles, idx)),
                If(Unary("not", Bin(is_thread, "or", is_job)), [Return(idx)], [], []),
                If(completed, [Return(idx)], [], []),
            ]),
            ExprStmt(Call(Var("threadSleep"), [Num(1)])),
        ])
        return FunctionDef("__ml_select", ["handles"], [
            If(Unary("not", Bin(valid, "and", nonempty)), [Return(Num(-1))], [], []),
            loop,
            Return(Num(-1)),
        ])


def _validate_interfaces(program: List[Stmt]) -> None:
    interfaces: dict[str, InterfaceDef] = {}
    structs: List[tuple[str, StructDef]] = []

    def collect(body: List[Stmt], prefix: str = "") -> None:
        for st in body:
            if isinstance(st, NamespaceDef):
                collect(st.body, prefix + st.name + ".")
            elif isinstance(st, InterfaceDef):
                interfaces[prefix + st.name] = st
            elif isinstance(st, StructDef):
                structs.append((prefix + st.name, st))

    collect(program)

    def signature_matches(requirement: FunctionDef, actual: FunctionDef) -> bool:
        """Compare the callable contract exposed by an interface method."""
        if actual.is_static:
            return False
        if len(actual.params) != len(requirement.params) or actual.variadic_index != requirement.variadic_index:
            return False
        required_types = list(requirement.param_types or []) + [None] * len(requirement.params)
        actual_types = list(actual.param_types or []) + [None] * len(actual.params)
        required_optional = list(requirement.param_optional or []) + [False] * len(requirement.params)
        actual_optional = list(actual.param_optional or []) + [False] * len(actual.params)
        for i in range(len(requirement.params)):
            if required_types[i] != actual_types[i] or bool(required_optional[i]) != bool(actual_optional[i]):
                return False
        return (requirement.return_type == actual.return_type
                and bool(requirement.return_optional) == bool(actual.return_optional))

    simple: dict[str, List[str]] = {}
    for qname in interfaces:
        simple.setdefault(qname.rsplit(".", 1)[-1], []).append(qname)
    for struct_qname, struct in structs:
        prefix = struct_qname.rsplit(".", 1)[0] + "." if "." in struct_qname else ""
        methods = {m.name: m for m in struct.methods}
        for raw_name in struct.interfaces:
            candidates = [prefix + raw_name, raw_name]
            candidates.extend(simple.get(raw_name, []))
            iface_name = next((x for x in candidates if x in interfaces), None)
            if iface_name is None:
                raise ParseError(f"Unknown interface '{raw_name}' implemented by {struct_qname}", getattr(struct, "_pos", 0))
            for requirement in interfaces[iface_name].methods:
                actual = methods.get(requirement.name)
                if actual is None:
                    raise ParseError(f"Struct {struct_qname} does not implement {raw_name}.{requirement.name}", getattr(struct, "_pos", 0))
                if not signature_matches(requirement, actual):
                    raise ParseError(f"Method {struct_qname}.{actual.name} has an incompatible interface signature", getattr(actual, "_pos", 0))


def prepare_language_features(program: List[Stmt]) -> List[Stmt]:
    """Validate contracts and lower new syntax before semantic analysis/codegen."""
    _validate_interfaces(program)
    lowerer = _LanguageLowerer()
    lowered = lowerer.lower_block(program)

    def remove_interfaces(body: List[Stmt]) -> List[Stmt]:
        out: List[Stmt] = []
        for st in body:
            if isinstance(st, InterfaceDef):
                continue
            if isinstance(st, NamespaceDef):
                st.body = remove_interfaces(st.body)
            out.append(st)
        return out

    lowered = remove_interfaces(lowered)
    helpers: List[Stmt] = []
    if lowerer.needs_await:
        helper = lowerer.await_helper()
        helpers.append(_copy_source_pos(helper, lowerer.await_source) if lowerer.await_source is not None else helper)
    if lowerer.needs_select:
        helper = lowerer.select_helper()
        helpers.append(_copy_source_pos(helper, lowerer.select_source) if lowerer.select_source is not None else helper)
    if lowerer.needs_async_pool:
        pool_type: Expr = Member(Member(Member(Var("std"), "concurrent"), "thread_pool"), "ThreadPool")
        pool_init = Assign(lowerer.async_pool_name,
                           Call(Member(pool_type, "new"), [Num(4)]))
        # This initializer is compiler-generated infrastructure, not user code.
        # Keeping its neutral source position also keeps both frontends' debug
        # line tables deterministic.
        helpers.insert(0, pool_init)
    return helpers + lowered


# ============================================================
# Typed conditional-compilation directives
# ============================================================

_COMPILE_PREDEFINED = {
    "TARGET_OS": "windows",
    "TARGET_ARCH": "x64",
    "TARGET_ABI": "win64",
    "TARGET_FORMAT": "pe",
    "POINTER_SIZE": 8,
    "MINILANG_VERSION": "1.2.6",
}
_compile_external_defines: dict[str, bool | int | str] = {}


def set_compile_target(target: str) -> None:
    """Select the immutable target values used by subsequent source parses."""
    normalized = str(target or "windows-x64").strip().lower().replace("_", "-")
    aliases = {
        "windows": "windows-x64",
        "win64": "windows-x64",
        "win-x64": "windows-x64",
        "linux": "linux-x64",
        "linux64": "linux-x64",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized == "windows-x64":
        values = {"TARGET_OS": "windows", "TARGET_ARCH": "x64", "TARGET_ABI": "win64", "TARGET_FORMAT": "pe"}
    elif normalized == "linux-x64":
        values = {"TARGET_OS": "linux", "TARGET_ARCH": "x64", "TARGET_ABI": "sysv", "TARGET_FORMAT": "elf"}
    else:
        raise ValueError(f"unsupported target: {target!r}")
    _COMPILE_PREDEFINED.update(values)


def _compile_value_type(value: Any) -> Optional[str]:
    """Return the source-level type of one supported compile-time value."""
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, str):
        return "string"
    return None


def _compile_valid_name(name: str) -> bool:
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name or "") is not None


def _parse_cli_compile_value(text: str) -> bool | int | str:
    raw = str(text).strip()
    if raw == "true":
        return True
    if raw == "false":
        return False
    if re.fullmatch(r"-?(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|[0-9]+)", raw):
        sign = -1 if raw.startswith("-") else 1
        digits = raw[1:] if sign < 0 else raw
        base = 0 if digits.lower().startswith(("0x", "0b")) else 10
        return wrap_i61(sign * int(digits, base))
    if raw[0].isdigit() or (raw.startswith("-") and len(raw) > 1 and raw[1].isdigit()):
        parsed_number = _parse_compile_expression(raw, "<command-line>", 0)
        value = _eval_compile_expression(parsed_number, {}, "<command-line>", 0)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("invalid numeric compile definition")
        return value
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        parsed = _parse_compile_expression(raw, "<command-line>", 0)
        if not isinstance(parsed, Str):
            raise ValueError("quoted compile definition must be a string")
        return parsed.value
    if not raw:
        raise ValueError("compile definition value must not be empty")
    return raw


def parse_compile_define_specs(specs: Any) -> dict[str, bool | int | str]:
    """Parse repeated ``-DNAME=value`` arguments into typed values."""
    result: dict[str, bool | int | str] = {}
    for item in list(specs or []):
        raw = str(item)
        if "=" in raw:
            name, value_text = raw.split("=", 1)
            value = _parse_cli_compile_value(value_text)
        else:
            name, value = raw, True
        name = name.strip()
        if not _compile_valid_name(name):
            raise ValueError(f"invalid compile definition name: {name!r}")
        if name in _COMPILE_PREDEFINED:
            raise ValueError(f"predefined compile value {name} cannot be overridden")
        result[name] = value
    return result


def set_compile_defines(values: Any) -> None:
    """Install external compile definitions for subsequent file parses."""
    global _compile_external_defines
    normalized: dict[str, bool | int | str] = {}
    for name, value in dict(values or {}).items():
        if not _compile_valid_name(str(name)):
            raise ValueError(f"invalid compile definition name: {name!r}")
        if str(name) in _COMPILE_PREDEFINED:
            raise ValueError(f"predefined compile value {name} cannot be overridden")
        if _compile_value_type(value) is None:
            raise ValueError(f"compile definition {name} must be bool, int, or string")
        normalized[str(name)] = value
    _compile_external_defines = normalized


def _parse_compile_expression(text: str, filename: str, base_pos: int) -> Expr:
    try:
        parser = Parser(tokenize(text), text, filename)
        expr = parser.parse_expr()
        parser.skip_stmt_seps()
        if parser.peek().kind != "EOF":
            raise ParseError("Trailing tokens after compile-time expression", parser.peek().pos)
        return expr
    except ParseError as exc:
        exc.pos = base_pos + int(getattr(exc, "pos", 0) or 0)
        exc.filename = filename
        raise


def _eval_compile_expression(expr: Expr, env: dict[str, bool | int | str], filename: str,
                             base_pos: int) -> bool | int | str:
    pos = base_pos + int(getattr(expr, "_pos", 0) or 0)

    if isinstance(expr, Bool):
        return expr.value
    if isinstance(expr, Num):
        if isinstance(expr.value, int) and not isinstance(expr.value, bool):
            return expr.value
        raise ParseError("compile-time values do not support floats", pos)
    if isinstance(expr, Str):
        return expr.value
    if isinstance(expr, Var):
        if expr.name not in env:
            raise ParseError(f"unknown compile-time value: {expr.name}", pos)
        return env[expr.name]
    if isinstance(expr, Call) and isinstance(expr.callee, Var) and expr.callee.name == "defined":
        if len(expr.args) != 1 or not isinstance(expr.args[0], (Var, Str)):
            raise ParseError("defined(...) expects one name or string", pos)
        name = expr.args[0].name if isinstance(expr.args[0], Var) else expr.args[0].value
        return name in env
    if isinstance(expr, Unary):
        value = _eval_compile_expression(expr.right, env, filename, base_pos)
        if expr.op == "not" and isinstance(value, bool):
            return not value
        if expr.op == "-" and isinstance(value, int) and not isinstance(value, bool):
            return wrap_i61(-value)
        if expr.op == "~" and isinstance(value, int) and not isinstance(value, bool):
            return wrap_i61(~value)
        raise ParseError(f"invalid compile-time unary operation: {expr.op}", pos)
    if isinstance(expr, Bin):
        left = _eval_compile_expression(expr.left, env, filename, base_pos)
        if expr.op == "and":
            if not isinstance(left, bool):
                raise ParseError("compile-time 'and' expects booleans", pos)
            if not left:
                return False
            right = _eval_compile_expression(expr.right, env, filename, base_pos)
            if not isinstance(right, bool):
                raise ParseError("compile-time 'and' expects booleans", pos)
            return right
        if expr.op == "or":
            if not isinstance(left, bool):
                raise ParseError("compile-time 'or' expects booleans", pos)
            if left:
                return True
            right = _eval_compile_expression(expr.right, env, filename, base_pos)
            if not isinstance(right, bool):
                raise ParseError("compile-time 'or' expects booleans", pos)
            return right

        right = _eval_compile_expression(expr.right, env, filename, base_pos)
        if expr.op in ("==", "!="):
            equal = type(left) is type(right) and left == right
            return equal if expr.op == "==" else not equal
        if expr.op in ("<", "<=", ">", ">="):
            if type(left) is not type(right) or isinstance(left, bool) or not isinstance(left, (int, str)):
                raise ParseError(f"compile-time '{expr.op}' expects matching int or string operands", pos)
            return {"<": left < right, "<=": left <= right,
                    ">": left > right, ">=": left >= right}[expr.op]
        if expr.op == "+" and isinstance(left, str) and isinstance(right, str):
            return left + right
        if (not isinstance(left, int) or isinstance(left, bool) or
                not isinstance(right, int) or isinstance(right, bool)):
            raise ParseError(f"compile-time '{expr.op}' expects integer operands", pos)
        if expr.op == "+":
            return wrap_i61(left + right)
        if expr.op == "-":
            return wrap_i61(left - right)
        if expr.op == "*":
            return wrap_i61(left * right)
        if expr.op == "%":
            if right == 0:
                raise ParseError("compile-time modulo by zero", pos)
            return wrap_i61(left % right)
        if expr.op in ("&", "|", "^"):
            return wrap_i61({"&": left & right, "|": left | right, "^": left ^ right}[expr.op])
        if expr.op in ("<<", ">>"):
            if right < 0:
                raise ParseError("negative compile-time shift count", pos)
            return wrap_i61(left << (right & 63) if expr.op == "<<" else left >> (right & 63))
        raise ParseError(f"unsupported compile-time operation: {expr.op}", pos)

    raise ParseError("unsupported compile-time expression", pos)


def _compile_eval(text: str, env: dict[str, bool | int | str], filename: str,
                  base_pos: int) -> bool | int | str:
    expr = _parse_compile_expression(text, filename, base_pos)
    return _eval_compile_expression(expr, env, filename, base_pos)


def _scan_compile_block_comment(line: str, in_block: bool) -> bool:
    """Track active-code block comments so commented directives stay inert."""
    i = 0
    in_string = False
    escaped = False
    while i < len(line):
        if in_block:
            end = line.find("*/", i)
            if end < 0:
                return True
            in_block = False
            i = end + 2
            continue
        ch = line[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if line.startswith("//", i):
            return False
        if line.startswith("/*", i):
            in_block = True
            i += 2
            continue
        i += 1
    return in_block


def preprocess_compile_directives(code: str, filename: str = "<source>") -> str:
    """Evaluate typed line directives and preserve every original source offset."""
    # Most source files do not use conditional compilation. Avoid allocating a
    # second full-size source string on that overwhelmingly common path.
    if re.search(r"(?m)^[ \t]*#", code) is None:
        return code
    env: dict[str, bool | int | str] = dict(_COMPILE_PREDEFINED)
    env.update(_compile_external_defines)
    external_names = set(_compile_external_defines)
    option_types: dict[str, str] = {}
    frames: list[dict[str, Any]] = []
    output: list[str] = []
    line_start = 0
    in_block_comment = False

    def active() -> bool:
        return bool(frames[-1]["active"]) if frames else True

    for physical in code.splitlines(keepends=True):
        ending = "\n" if physical.endswith("\n") else ""
        line = physical[:-1] if ending else physical
        stripped = line.lstrip(" \t")
        hash_column = len(line) - len(stripped)
        is_directive = stripped.startswith("#") and (not active() or not in_block_comment)
        blank = " " * len(line) + ending

        if not is_directive:
            if active():
                output.append(physical)
                in_block_comment = _scan_compile_block_comment(line, in_block_comment)
            else:
                output.append(blank)
            line_start += len(physical)
            continue

        output.append(blank)
        body = stripped[1:].strip()
        parts = body.split(None, 1)
        command = (parts[0] if parts else "").lower()
        argument = parts[1].strip() if len(parts) == 2 else ""
        directive_pos = line_start + hash_column
        argument_pos = line_start + max(line.find(argument), hash_column + 1) if argument else directive_pos

        if command == "if":
            parent_active = active()
            condition = False
            if parent_active:
                value = _compile_eval(argument, env, filename, argument_pos)
                if not isinstance(value, bool):
                    raise ParseError("#if expression must produce bool", argument_pos)
                condition = value
            frames.append({"parent": parent_active, "active": parent_active and condition,
                           "taken": parent_active and condition, "else": False, "pos": directive_pos})
        elif command == "elif":
            if not frames:
                raise ParseError("#elif without matching #if", directive_pos)
            frame = frames[-1]
            if frame["else"]:
                raise ParseError("#elif is not allowed after #else", directive_pos)
            condition = False
            if frame["parent"] and not frame["taken"]:
                value = _compile_eval(argument, env, filename, argument_pos)
                if not isinstance(value, bool):
                    raise ParseError("#elif expression must produce bool", argument_pos)
                condition = value
            frame["active"] = frame["parent"] and not frame["taken"] and condition
            frame["taken"] = frame["taken"] or frame["active"]
        elif command == "else":
            if argument:
                raise ParseError("#else does not accept an expression", argument_pos)
            if not frames:
                raise ParseError("#else without matching #if", directive_pos)
            frame = frames[-1]
            if frame["else"]:
                raise ParseError("duplicate #else", directive_pos)
            frame["else"] = True
            frame["active"] = frame["parent"] and not frame["taken"]
            frame["taken"] = frame["taken"] or frame["active"]
        elif command == "endif":
            if argument:
                raise ParseError("#endif does not accept an expression", argument_pos)
            if not frames:
                raise ParseError("#endif without matching #if", directive_pos)
            frames.pop()
        elif command in ("option", "const", "error"):
            if active():
                if command == "option":
                    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(bool|int|string)\s*=\s*(.+)", argument)
                    if match is None:
                        raise ParseError("#option expects NAME: bool|int|string = expression", argument_pos)
                    name, declared_type, default_text = match.groups()
                    if name in _COMPILE_PREDEFINED:
                        raise ParseError(f"predefined compile value {name} cannot be declared as an option", argument_pos)
                    if name in option_types:
                        raise ParseError(f"duplicate compile option: {name}", argument_pos)
                    default_pos = line_start + line.find(default_text)
                    default_value = _compile_eval(default_text, env, filename, default_pos)
                    option_types[name] = declared_type
                    value = env[name] if name in external_names else default_value
                    if _compile_value_type(value) != declared_type:
                        raise ParseError(f"compile option {name} expects {declared_type}, got {_compile_value_type(value) or 'unsupported'}", argument_pos)
                    env[name] = value
                elif command == "const":
                    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)", argument)
                    if match is None:
                        raise ParseError("#const expects NAME = expression", argument_pos)
                    name, value_text = match.groups()
                    if name in env:
                        raise ParseError(f"compile-time value already defined: {name}", argument_pos)
                    value_pos = line_start + line.find(value_text)
                    env[name] = _compile_eval(value_text, env, filename, value_pos)
                else:
                    value = _compile_eval(argument, env, filename, argument_pos)
                    if not isinstance(value, str):
                        raise ParseError("#error expects a string expression", argument_pos)
                    raise ParseError(value, directive_pos)
        else:
            raise ParseError(f"unknown compile directive: #{command or '<empty>'}", directive_pos)

        line_start += len(physical)

    if frames:
        raise ParseError("unterminated #if (missing #endif)", int(frames[-1]["pos"]))
    return "".join(output)
