"""Compiler-specific exception types.

The compiler uses a small custom exception type (:class:`CompileError`) to
associate diagnostics with an optional source location.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


class CompileError(Exception):
    """A compilation error with optional source location.

    Attributes:
        pos: Optional character offset (or token position) in the source file.
        filename: Optional path of the source file.
    """

    def __init__(self, message: str, pos: Optional[int] = None, filename: Optional[str] = None):
        """Create a :class:`CompileError`.

        Args:
            message: Human-readable error message.
            pos: Optional character offset (or token position) in the file.
            filename: Optional filename for improved diagnostics.
        """

        super().__init__(message)
        self.pos: Optional[int] = pos
        self.filename: Optional[str] = filename


@dataclass(frozen=True)
class Diagnostic:
    """A single compiler diagnostic (syntax or compilation)."""

    kind: str
    message: str
    filename: Optional[str] = None
    pos: Optional[int] = None
    source: Optional[str] = None


class MultiCompileError(Exception):
    """A collection of multiple diagnostics.

    Raised when the compiler runs in "keep going" mode and wants to report
    *all* found errors at once.
    """

    def __init__(self, diags: List[Diagnostic]):
        super().__init__(f"{len(diags)} error(s)")
        self.diags: List[Diagnostic] = list(diags)
