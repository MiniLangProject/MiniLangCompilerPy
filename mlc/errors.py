"""Compiler-specific exception types.

The compiler uses a small custom exception type (:class:`CompileError`) to
associate diagnostics with an optional source location.
"""

from __future__ import annotations

from typing import Optional


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
