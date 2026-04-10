"""Helpers for building ``.data`` / ``.rdata`` blobs and labels.

The PE builder (see :mod:`mlc.pe`) needs deterministic byte blobs for the
sections it emits. These builders help:

- append raw bytes
- remember label offsets
- keep everything aligned
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Tuple

from .constants import OBJ_FLOAT, OBJ_STRING
from .tools import u32, u64


@dataclass
class DataLabel:
    """A named offset into a section blob."""

    name: str
    offset: int


class DataBuilder:
    """Builder for the writable ``.data`` section."""

    def __init__(self) -> None:
        """Create an empty ``.data`` builder."""

        self.data: bytearray = bytearray()
        self.labels: Dict[str, int] = {}

    def add_u32(self, name: str, value: int) -> None:
        """Append a 32-bit little-endian integer and record its label."""

        self.labels[name] = len(self.data)
        self.data += u32(value)

    def add_u64(self, name: str, value: int) -> None:
        """Append a 64-bit little-endian integer and record its label."""

        self.labels[name] = len(self.data)
        self.data += u64(value)

    def pad_align(self, align: int = 8) -> None:
        """Pad with NUL bytes to reach ``align``-byte alignment."""

        pad = (-len(self.data)) % align
        if pad:
            self.data += b"\x00" * pad

    def add_bytes(self, name: str, b: bytes) -> None:
        """Append raw bytes and record their start offset as label."""

        self.labels[name] = len(self.data)
        self.data += b


class BssBuilder:
    """Builder for uninitialized (zero-filled) data.

    Windows PE supports sections where ``VirtualSize`` is larger than
    ``SizeOfRawData`` (or even 0). The loader maps the section into memory and
    zero-initializes the bytes that are not present in the file.

    We use this for large scratch buffers (e.g. GC mark stack) to keep produced
    executables small.
    """

    def __init__(self) -> None:
        self.size: int = 0
        self.labels: Dict[str, int] = {}

    def pad_align(self, align: int = 8) -> None:
        pad = (-self.size) % align
        if pad:
            self.size += pad

    def reserve(self, name: str, size: int, *, align: int = 8) -> None:
        """Reserve ``size`` bytes of zero-initialized memory and record ``name``."""

        if name in self.labels:
            return
        self.pad_align(align)
        self.labels[name] = self.size
        self.size += int(size)


class RDataBuilder:
    """Builder for the read-only ``.rdata`` section."""

    def __init__(self) -> None:
        """Create an empty ``.rdata`` builder."""

        self.data: bytearray = bytearray()
        # name -> (offset, length)
        self.labels: Dict[str, Tuple[int, int]] = {}

        # --- constant pooling ---
        # Deduplicate identical constants so they land only once in the executable.
        # This is intentionally conservative:
        # - raw byte blobs (add_bytes/add_str) can always be pooled
        # - boxed objects must remain 8-byte aligned, so they use separate pools
        self._pool_raw: Dict[bytes, Tuple[int, int]] = {}
        self._pool_obj_string: Dict[bytes, Tuple[int, int]] = {}  # utf-8 payload -> (off, len)
        self._pool_obj_float: Dict[bytes, Tuple[int, int]] = {}   # packed f64 -> (off, len)

    def _intern_raw(self, name: str, b: bytes) -> None:
        """Intern a raw byte blob (deduplicate identical sequences)."""

        hit = self._pool_raw.get(b)
        if hit is not None:
            self.labels[name] = hit
            return

        off = len(self.data)
        self.data += b
        rec = (off, len(b))
        self.labels[name] = rec
        self._pool_raw[b] = rec

    def add_str(self, name: str, s: str, add_newline: bool = True) -> None:
        """Append a UTF-8 string (optionally with trailing newline) and label it."""

        if add_newline:
            s = s + "\n"
        b = s.encode("utf-8")

        # Pool identical string blobs.
        self._intern_raw(name, b)

    def add_bytes(self, name: str, b: bytes) -> None:
        """Append raw bytes and record (offset, length) under ``name``."""

        # Pool identical raw blobs.
        self._intern_raw(name, b)

    def pad_align(self, align: int = 8) -> None:
        """Pad with NUL bytes to reach ``align``-byte alignment."""

        pad = (-len(self.data)) % align
        if pad:
            self.data += b"\x00" * pad

    def add_obj_string(self, name: str, s: str) -> None:
        """Add a boxed string object into .rdata.

        Layout (8-byte aligned):
          u32 type = OBJ_STRING
          u32 len  = byte length (utf-8)
          bytes...
          u8 0 (NUL, not counted in len)
        Value representation: TAG_PTR pointer to start of header.
        """
        b = s.encode("utf-8")

        # Pool boxed strings by payload bytes (requires 8-byte aligned header).
        hit = self._pool_obj_string.get(b)
        if hit is not None:
            self.labels[name] = hit
            return

        self.pad_align(8)
        off = len(self.data)
        self.data += struct.pack("<II", OBJ_STRING, len(b))
        self.data += b + b"\x00"
        rec = (off, len(self.data) - off)
        self.labels[name] = rec
        self._pool_obj_string[b] = rec

    def add_obj_float(self, name: str, value: float) -> None:
        """Add a boxed float object into .rdata.

        Layout (8-byte aligned):
          u32 type = OBJ_FLOAT
          u32 pad  = 0
          f64 value
        """
        f64 = struct.pack("<d", float(value))

        # Pool boxed floats by their exact IEEE-754 bit-pattern.
        hit = self._pool_obj_float.get(f64)
        if hit is not None:
            self.labels[name] = hit
            return

        self.pad_align(8)
        off = len(self.data)
        self.data += struct.pack("<II", OBJ_FLOAT, 0)
        self.data += f64
        rec = (off, len(self.data) - off)
        self.labels[name] = rec
        self._pool_obj_float[f64] = rec
