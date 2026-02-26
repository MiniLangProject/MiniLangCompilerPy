"""Small helper utilities used by the native compiler codegen.

This module is intentionally dependency-light and only contains:

- Alignment helpers
- Little-endian integer packers
- Immediate/tagged value encoders
"""

from __future__ import annotations

import struct

from .constants import TAG_INT, TAG_BOOL, TAG_VOID, TAG_ENUM


def align_up(n: int, a: int) -> int:
    """Round ``n`` up to the next multiple of ``a``.

    Note:
        This implementation uses a bit trick that works correctly when ``a`` is
        a power of two.

    Args:
        n: Value to align.
        a: Alignment (typically a power of two).

    Returns:
        The smallest value ``m >= n`` such that ``m`` is aligned to ``a``.
    """

    return (n + (a - 1)) & ~(a - 1)


def align_to_mod(n: int, mod: int, target: int) -> int:
    """Align ``n`` so that the result matches a desired modulo.

    Args:
        n: Starting value.
        mod: Modulus.
        target: Desired remainder (``0 <= target < mod``).

    Returns:
        The smallest ``m >= n`` such that ``m % mod == target``.
    """

    r = n % mod
    pad = (target - r) % mod
    return n + pad


def u16(x: int) -> bytes:
    """Pack an unsigned 16-bit integer (little-endian)."""

    return struct.pack("<H", x & 0xFFFF)


def u32(x: int) -> bytes:
    """Pack an unsigned 32-bit integer (little-endian)."""

    return struct.pack("<I", x & 0xFFFFFFFF)


def u64(x: int) -> bytes:
    """Pack an unsigned 64-bit integer (little-endian)."""

    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


# ============================================================
# Tagged value encoders
# ============================================================

def enc_int(x: int) -> int:
    """Encode a tagged immediate integer value."""

    return ((x << 3) & 0xFFFFFFFFFFFFFFFF) | TAG_INT


def enc_bool(b: bool) -> int:
    """Encode a tagged immediate boolean value."""

    return (((1 if b else 0) << 3) & 0xFFFFFFFFFFFFFFFF) | TAG_BOOL


def enc_void() -> int:
    """Encode the ``void`` value (tag only)."""

    return TAG_VOID


def enc_enum(enum_id: int, variant_id: int) -> int:
    """Encode an enum immediate value.

    Layout: (variant_id << 8) | enum_id, tagged with TAG_ENUM.
    """

    payload = ((variant_id & 0xFF) << 8) | (enum_id & 0xFF)
    return (payload << 3) | TAG_ENUM
