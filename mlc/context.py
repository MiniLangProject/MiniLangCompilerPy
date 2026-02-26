"""Small context dataclasses used during code generation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional


@dataclass
class LoopCtx:
    """Context for emitting code inside a loop.

    Attributes:
        break_label: Target label for a ``break``.
        continue_label: Target label for a ``continue``.
    """

    break_label: str
    continue_label: str


@dataclass
class BreakableCtx:
    """Context for a breakable construct (loop or switch).

    The compiler tracks additional information to support lexical-scope cleanup
    when breaking out of nested constructs.

    Attributes:
        kind: Either ``"loop"`` or ``"switch"``.
        break_label: Target label for ``break``.
        continue_label: Target label for ``continue`` (only for loops).
        break_depth: Number of lexical scopes to unwind on ``break``.
        continue_depth: Number of lexical scopes to unwind on ``continue``.
    """

    kind: Literal["loop", "switch"]
    break_label: str
    continue_label: Optional[str] = None
    # Lexical-scope cleanup targets for 'break' / 'continue'
    break_depth: int = 0
    continue_depth: int = 0
