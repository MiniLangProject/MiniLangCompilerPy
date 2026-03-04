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
            "out", "static", "inline", "void", "is",}

TOKEN_SPEC = [("COMMENTBLOCK", r"/\*[\s\S]*?\*/"), ("COMMENTLINE", r"//.*"),
              ("NUMBER", r"0[xX][0-9A-Fa-f]+|0[bB][01]+|\d+\.\d+|\d+"), ("STRING", r'"([^"\\]|\\.)*"'),
              ("IDENT", r"[A-Za-z_][A-Za-z0-9_]*"), ("DOT", r"\."), ("LPAREN", r"\("), ("RPAREN", r"\)"),
              ("LBRACK", r"\["), ("RBRACK", r"\]"), ("COMMA", r","), ("SEMI", r";"),  # include % for modulo
              ("OP", r"==|!=|>=|<=|<<|>>|[+\-*/%=<>&|^~>]"), ("NEWLINE", r"\n"), ("SKIP", r"[ \t]+"), ]

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

        if kind in ("SKIP", "COMMENTLINE"):
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
    value: float | int


@dataclass
class Str(Expr):
    value: str


@dataclass
class Bool(Expr):
    value: bool


@dataclass
class VoidLit(Expr):
    """The `void` literal."""
    pass


@dataclass
class Var(Expr):
    name: str


@dataclass
class ArrayLit(Expr):
    items: List[Expr]


@dataclass
class Unary(Expr):
    op: str
    right: Expr


@dataclass
class Bin(Expr):
    left: Expr
    op: str
    right: Expr


@dataclass
class Call(Expr):
    callee: Expr
    args: List[Expr]


@dataclass
class Index(Expr):
    target: Expr
    index: Expr


@dataclass
class Member(Expr):
    target: Expr
    name: str


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
    path: str
    alias: Optional[str] = None
    module: Optional[str] = None


@dataclass
class NamespaceDef(Stmt):
    name: str
    body: List[Stmt]


@dataclass
class NamespaceDecl(Stmt):
    name: str


@dataclass
class ImportStmt(Stmt):
    module: str
    alias: str


@dataclass
class Print(Stmt):
    expr: Expr


@dataclass
class Assign(Stmt):
    name: str
    expr: Expr


@dataclass
class ConstDecl(Stmt):
    name: str
    expr: Expr


@dataclass
class SetMember(Stmt):
    obj: Expr
    field: str
    expr: Expr


@dataclass
class SetIndex(Stmt):
    target: Expr
    index: Expr
    expr: Expr


@dataclass
class ExprStmt(Stmt):
    expr: Expr


@dataclass
class If(Stmt):
    cond: Expr
    then_body: List[Stmt]
    elifs: List[Tuple[Expr, List[Stmt]]]
    else_body: List[Stmt]


@dataclass
class While(Stmt):
    cond: Expr
    body: List[Stmt]


@dataclass
class DoWhile(Stmt):
    body: List[Stmt]
    cond: Expr


@dataclass
class For(Stmt):
    var: str
    start: Expr
    end: Expr
    body: List[Stmt]


@dataclass
class ForEach(Stmt):
    var: str
    iterable: Expr
    body: List[Stmt]


@dataclass
class FunctionDef(Stmt):
    name: str
    params: List[str]
    body: List[Stmt]
    is_static: bool = False
    is_inline: bool = False


@dataclass
class Return(Stmt):
    expr: Optional[Expr]


@dataclass
class Break(Stmt):
    count: int = 1


@dataclass
class Continue(Stmt):
    pass


@dataclass
class GlobalDecl(Stmt):
    names: List[str]


@dataclass
class SwitchCase:
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
    expr: Expr
    cases: List[SwitchCase]
    default_body: List[Stmt]


@dataclass
class StructDef(Stmt):
    name: str
    fields: List[str]
    methods: List["FunctionDef"] = field(default_factory=list)


@dataclass
class EnumDef(Stmt):
    name: str
    variants: List[str]
    values: List[Optional[Expr]] = field(default_factory=list)


@dataclass
class ExternParam:
    name: Optional[str]  # optional parameter name (for readability)
    ty: str  # ABI type name (e.g. int, bool, ptr, cstr, wstr, void)
    is_out: bool = False  # out-parameter (passed as pointer; may be omitted at call site)


@dataclass
class ExternFunctionDef(Stmt):
    name: str
    params: List[ExternParam]
    dll: str
    symbol: Optional[str]
    ret_ty: str


# ============================================================
# Parser
# ============================================================

PRECEDENCE = {"or": 1, "and": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6, "is": 6, ">": 7, "<": 7, ">=": 7, "<=": 7, "<<": 8,
              ">>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10, }


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
        # Historically this required a physical newline after block headers.
        # Be a bit more liberal and also accept ';' as a block separator.
        if self.match("NL"):
            self.skip_newlines()
            return
        if self.match("SEMI"):
            self.skip_stmt_seps()
            return
        t = self.peek()
        raise ParseError("Expected NEWLINE or ';'", t.pos)

    def is_end_of(self, what: str) -> bool:
        return (
                self.peek().kind == "KW" and self.peek().value == "end" and self.peek2().kind == "KW" and self.peek2().value == what)

    def expect_end_of(self, what: str) -> None:
        self.expect("KW", "end")
        self.expect("KW", what)

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
                    if t.kind == "KW" and t.value in ("function", "struct", "enum", "namespace", "extern", "const"):
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
                        "Inside a namespace, only declarations are allowed (function/struct/enum/namespace/extern/const)",
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
                        raise ParseError("extern struct ended unexpectedly (missing 'end struct'?)", self.peek().pos)

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

        # function [inline] name(params)
        if t.kind == "KW" and t.value == "function":
            self.advance()
            is_inline = False
            if self.peek().kind == "KW" and self.peek().value == "inline":
                is_inline = True
                self.advance()
            name_tok = self.expect("IDENT")
            self.expect("LPAREN")
            # Allow multiline parameter lists and a trailing comma.
            params: List[str] = self.parse_delimited_list("RPAREN", lambda: self.expect("IDENT").value)

            self.expect_block_nl()
            self._func_depth += 1
            try:
                body = self.parse_block_until_end("function")
            finally:
                self._func_depth -= 1
            self.expect_end_of("function")
            return self._attach_pos(FunctionDef(name_tok.value, params, body, is_inline=is_inline), start_pos)

        # struct
        if t.kind == "KW" and t.value == "struct":
            self.advance()
            name = self.expect("IDENT").value
            # `are` is optional (legacy)
            if self.peek().kind == "KW" and self.peek().value == "are":
                self.advance()
            self.expect_block_nl()

            fields: List[str] = []
            methods: List[FunctionDef] = []

            while not self.is_end_of("struct"):
                # allow blank lines / semicolons inside the block
                self.skip_stmt_seps()
                if self.is_end_of("struct"):
                    break
                if self.peek().kind == "EOF":
                    raise ParseError("struct ended unexpectedly (missing 'end struct'?)", self.peek().pos)

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
                    if self.peek().kind == "KW" and self.peek().value == "inline":
                        is_inline = True
                        self.advance()

                    m_name_tok = self.expect("IDENT")
                    self.expect("LPAREN")
                    # Allow multiline parameter lists and a trailing comma.
                    m_params: List[str] = self.parse_delimited_list("RPAREN", lambda: self.expect("IDENT").value)

                    self.expect_block_nl()
                    self._func_depth += 1
                    try:
                        m_body = self.parse_block_until_end("function")
                    finally:
                        self._func_depth -= 1
                    self.expect_end_of("function")

                    methods.append(
                        self._attach_pos(FunctionDef(m_name_tok.value, m_params, m_body, is_static=is_static, is_inline=is_inline), m_start))
                    continue

                # field (allow comma-separated lists + trailing commas)
                fields.append(self.expect("IDENT").value)
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
                self.expect_block_nl()

            self.expect_end_of("struct")
            return self._attach_pos(StructDef(name, fields, methods), start_pos)

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
                    raise ParseError("enum ended unexpectedly (missing 'end enum'?)", self.peek().pos)

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
                    raise ParseError("loop ended unexpectedly (missing 'end loop'?)", self.peek().pos)

                body.append(self.parse_stmt())
                self.skip_stmt_seps()

        # switch expr
        if t.kind == "KW" and t.value == "switch":
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
                        default_body = self.parse_block_until_end("case")
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
                        body = self.parse_block_until_end("case")
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
                    body = self.parse_block_until_end("case")
                    self.expect_end_of("case")
                    cases.append(SwitchCase("values", values, None, None, body))
                    self.skip_stmt_seps()
                    continue

                break

            self.expect_end_of("switch")
            return self._attach_pos(Switch(expr, cases, default_body), start_pos)

        # if cond then ... [else if ...] [else ...] end if
        if t.kind == "KW" and t.value == "if":
            self.advance()
            cond = self.parse_expr()
            self.expect("KW", "then")
            # NEWLINE after 'then' is optional (supports inline if)

            then_body = self.parse_block_until({"else"}, end_type="if")

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
                    ebody = self.parse_block_until({"else"}, end_type="if")
                    elifs.append((econd, ebody))
                    continue

                # else
                # NEWLINE after 'else' is optional (supports inline if)
                else_body = self.parse_block_until(set(), end_type="if")
                break

            self.expect_end_of("if")
            return self._attach_pos(If(cond, then_body, elifs, else_body), start_pos)

        # while cond ... end while
        if t.kind == "KW" and t.value == "while":
            self.advance()
            cond = self.parse_expr()
            self.expect_block_nl()
            body = self.parse_block_until_end("while")
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
                body = self.parse_block_until_end("for")
                self.expect_end_of("for")
                return self._attach_pos(ForEach(varname, iterable, body), start_pos)

            varname = self.expect("IDENT").value
            self.expect("OP", "=")
            start = self.parse_expr()
            self.expect("KW", "to")
            end = self.parse_expr()
            self.expect_block_nl()
            body = self.parse_block_until_end("for")
            self.expect_end_of("for")
            return self._attach_pos(For(varname, start, end, body), start_pos)

        # Assignment oder Call-Statement
        if t.kind == "IDENT":
            expr = self.parse_postfix()

            if self.match("OP", "="):
                rhs = self.parse_expr()

                if isinstance(expr, Var):
                    return self._attach_pos(Assign(expr.name, rhs), start_pos)
                if isinstance(expr, Member):
                    return self._attach_pos(SetMember(expr.target, expr.name, rhs), start_pos)
                if isinstance(expr, Index):
                    return self._attach_pos(SetIndex(expr.target, expr.index, rhs), start_pos)

                raise ParseError("Invalid assignment target (lvalue)", start_pos)

            if isinstance(expr, Call):
                return self._attach_pos(ExprStmt(expr), start_pos)

            raise ParseError("Only assignments or function calls are allowed as a statement", start_pos)

        raise ParseError(f"Unknown statement: {t.kind}:{t.value}", t.pos)

    def parse_block_until_end(self, end_type: str) -> List[Stmt]:
        stmts: List[Stmt] = []
        self.skip_stmt_seps()
        while True:
            if self.is_end_of(end_type):
                break
            if self.peek().kind == "EOF":
                raise ParseError(f"Block ended unexpectedly (missing 'end {end_type}'?)", self.peek().pos)
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

    def parse_block_until(self, stop_keywords: set[str], end_type: Optional[str] = None) -> List[Stmt]:
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
                raise ParseError(f"Block ended unexpectedly (missing '{wanted}'?)", t.pos)

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

            # Syntactic sugar: `x is <type>` / `x is not <type>` -> `typeof(x) == "<type>"` (optionally negated)
            if op == "is":
                is_start = tok.pos
                is_not = False
                if self.peek().kind == "KW" and self.peek().value == "not":
                    is_not = True
                    self.advance()
                    self.skip_newlines()
                ty_tok = self.peek()
                if ty_tok.kind not in ("IDENT", "KW"):
                    raise ParseError("Expected type name after 'is'", ty_tok.pos)
                self.advance()
                ty = str(ty_tok.value)
                ty_l = ty.lower()
                _aliases = {"integer": "int", "boolean": "bool", "str": "string"}
                ty_canon = _aliases.get(ty_l, ty_l)
                _allowed = {"int", "float", "bool", "string", "array", "bytes", "function", "struct", "enum", "error", "void", "unknown"}
                if ty_canon not in _allowed:
                    raise ParseError(f"Unknown type '{ty}' in 'is' expression", ty_tok.pos)

                start_pos = getattr(left, "_pos", None)
                if start_pos is None:
                    start_pos = is_start

                # typeof(left)
                typeof_call = self._attach_pos(Call(self._attach_pos(Var("typeof"), is_start), [left]), start_pos)
                rhs = self._attach_pos(Str(ty_canon), ty_tok.pos)
                cmp_expr = self._attach_pos(Bin(typeof_call, "==", rhs), start_pos)
                if is_not:
                    left = self._attach_pos(Unary("not", cmp_expr), start_pos)
                else:
                    left = cmp_expr
                continue

            right = self.parse_expr(prec + 1)

            start_pos = getattr(left, "_pos", None)
            if start_pos is None:
                start_pos = tok.pos
            left = self._attach_pos(Bin(left, op, right), start_pos)

        return left
    def parse_unary(self) -> Expr:
        """Parse unary expressions (prefix operators) or fall back to postfix parsing."""
        t = self.peek()

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
                args = self.parse_delimited_list("RPAREN", self.parse_expr)

                expr = self._attach_pos(Call(expr, args), call_start)
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

        if t.kind == "NUMBER":
            start_pos = t.pos
            self.advance()
            if "." in t.value:
                return self._attach_pos(Num(float(t.value)), start_pos)
            # allow hex (0x..), binary (0b..); keep plain int() for decimal with leading zeros
            if re.match(r"0[xX]", t.value) or re.match(r"0[bB]", t.value):
                return self._attach_pos(Num(int(t.value, 0)), start_pos)
            return self._attach_pos(Num(int(t.value)), start_pos)

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
