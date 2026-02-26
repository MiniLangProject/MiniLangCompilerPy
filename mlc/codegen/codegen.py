"""Codegen facade.

The actual implementation lives in mixins:
- CodegenCore:   state + small helpers
- CodegenScope:  lexical scoping helpers (block scopes, bindings, cleanup)
- CodegenMemory: heap/GC helpers (allocator + GC core)
- CodegenBuiltinsAlloc: allocation-using language builtins (input, string/array concat, value_to_string, box_float)
- CodegenRuntime: other internal runtime/builtins assembly emitters
- CodegenExpr:   expression lowering
- CodegenStmt:   statement/program lowering
"""

from __future__ import annotations

from .codegen_builtins_alloc import CodegenBuiltinsAlloc
from .codegen_core import CodegenCore
from .codegen_expr import CodegenExpr
from .codegen_memory import CodegenMemory
from .codegen_runtime import CodegenRuntime
from .codegen_scope import CodegenScope
from .codegen_stmt import CodegenStmt


class Codegen(CodegenCore, CodegenScope, CodegenMemory, CodegenBuiltinsAlloc, CodegenRuntime, CodegenExpr,
              CodegenStmt, ):
    """Facade class that combines all codegen mixins into one implementation."""


__all__ = ["Codegen"]
