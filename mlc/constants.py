"""Constants shared across the Windows x64 native codegen.

This module is imported from multiple compiler stages (codegen, PE builder,
runtime helpers). Keep it side-effect free.
"""

from __future__ import annotations

# ============================================================
# Tagged values (64-bit)
# ============================================================

TAG_PTR = 0
TAG_INT = 1
TAG_BOOL = 2
TAG_VOID = 3
TAG_ENUM = 4

# ============================================================
# Heap object type ids (for TAG_PTR objects)
# ============================================================
# 0 is reserved for "free blocks" managed by the allocator.

OBJ_FREE = 0
OBJ_STRING = 1
OBJ_ARRAY = 2
OBJ_FUNCTION = 3
OBJ_FLOAT = 4
OBJ_STRUCT = 5

OBJ_STRUCTTYPE = 6

# Builtin function value (first-class builtins like len/toNumber/typeof/heap_* etc.)
OBJ_BUILTIN = 7

# Closures / nested functions
OBJ_ENV = 8
OBJ_BOX = 9
OBJ_BYTES = 10
# ============================================================
# Heap GC header (Mark/Sweep + Free-List)
# ============================================================
#
# Heap objects keep their existing layout starting at the object pointer:
#   [u32 type][u32 len/pad][payload...]
#
# Additionally, every *heap-allocated* object gets a GC header placed
# immediately *before* the object pointer:
#   [ptr-24] u64 block_size   (total bytes incl. GC header, 8-byte aligned)
#   [ptr-16] u64 mark         (0 or 1; used by the tracing GC)
#   [ptr-8 ] u64 next_free    (singly-linked free list when block is free)
#
# IMPORTANT:
# - The MiniLang value for pointers (TAG_PTR) is the pointer to the *object*
#   start (type/len/payload). The GC header is at negative offsets.
# - For compatibility, GC_OFF_REFCOUNT is kept as an alias for GC_OFF_MARK.

GC_HEADER_SIZE = 24
GC_OFF_BLOCK_SIZE = -24
GC_OFF_MARK = -16
GC_OFF_REFCOUNT = GC_OFF_MARK  # backward-compatible alias
GC_OFF_NEXT_FREE = -8

# ============================================================
# Runtime buffer sizes
# ============================================================

# Buffer for the print function. Must be a multiple of 2 bytes (UTF-16).
WIDEBUF_SIZE = 8096

# Input buffer size for reading from stdin.
INBUF_SIZE = 4096

# ============================================================
# Built-in struct ids
# ============================================================
# Reserved struct id for the built-in `error` type.
ERROR_STRUCT_ID = 0xE0000001

# Reserved struct id for the call-profiling record type (`callStat`).
CALLSTAT_STRUCT_ID = 0xE0000002

# ============================================================
# Runtime error codes (for built-in `error(code, message)` values)
# ============================================================
# Use these for runtime failures that previously returned void.

ERR_EXTERN_CONVERSION = 1001
ERR_EXTERN_RET_WSTR_CONVERSION = 1002

# Calling / method dispatch errors
ERR_CALL_NOT_CALLABLE = 1100
ERR_METHOD_NOT_FOUND = 1101

# Strict void handling
ERR_VOID_OP = 1200

# Indexing / bounds errors
ERR_INDEX_OOB = 1300
ERR_INDEX_TYPE = 1301
ERR_INDEX_TARGET_TYPE = 1302

# Stringification / printing of unsupported values
ERR_STRINGIFY_UNSUPPORTED = 1303
ERR_PRINT_UNSUPPORTED = 1304

# Struct member access errors
ERR_MEMBER_TARGET_TYPE = 1305
ERR_MEMBER_NOT_FOUND = 1306

# Module initialization dependency / cycle
ERR_MODULE_INIT_CYCLE = 1400
