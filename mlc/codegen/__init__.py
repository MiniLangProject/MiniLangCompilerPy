"""Codegen package.

This package exposes the `Codegen` facade, which is implemented as a composition of
multiple mixins (core, scope, memory/GC, runtime helpers, expression/statement
lowering, etc.). See `codegen.py` for the actual class definition.
"""

from __future__ import annotations

from .codegen import Codegen

__all__ = ["Codegen"]
