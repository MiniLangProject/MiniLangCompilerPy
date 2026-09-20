#!/usr/bin/env python3
"""Optional LZ4 block interoperability check against upstream liblz4.

Usage: python3 tests/compression_interop.py build/compression_interop_linux
Requires liblz4 at runtime; the main MiniLang suite does not depend on it.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import random
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("program", type=Path, help="Compiled compression_interop.ml")
    args = parser.parse_args()
    program = args.program.resolve()
    library = ctypes.util.find_library("lz4")
    if not library:
        raise SystemExit("liblz4 is unavailable; install it for this optional check")
    lz4 = ctypes.CDLL(library)
    lz4.LZ4_compress_default.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int
    ]
    lz4.LZ4_compress_default.restype = ctypes.c_int
    lz4.LZ4_decompress_safe.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int
    ]
    lz4.LZ4_decompress_safe.restype = ctypes.c_int

    rng = random.Random(0x4C5A34)
    samples = {
        "short": b"ABCD",
        "overlap": b"A" * 1048576,
        "patterned": bytes((i // 7 + i * 13) & 255 for i in range(1048576)),
        "random": rng.randbytes(1048576),
    }
    with tempfile.TemporaryDirectory(prefix="minilang-lz4-") as temp:
        root = Path(temp)
        for label, raw in samples.items():
            raw_file = root / f"{label}.raw"
            mini_file = root / f"{label}.mini.lz4"
            native_file = root / f"{label}.native.lz4"
            raw_file.write_bytes(raw)
            result = subprocess.run(
                [str(program), "encode", str(raw_file), str(mini_file)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode:
                raise AssertionError(f"{label}: MiniLang encoder failed: {result.stdout} {result.stderr}")
            mini_block = mini_file.read_bytes()
            native_output = ctypes.create_string_buffer(len(raw))
            count = lz4.LZ4_decompress_safe(
                ctypes.c_char_p(mini_block), native_output,
                len(mini_block), len(raw)
            )
            if count != len(raw) or native_output.raw[:count] != raw:
                raise AssertionError(f"{label}: liblz4 rejected MiniLang output")
            capacity = len(raw) + len(raw) // 255 + 16
            native_block = ctypes.create_string_buffer(capacity)
            count = lz4.LZ4_compress_default(
                ctypes.c_char_p(raw), native_block, len(raw), capacity
            )
            if count <= 0:
                raise AssertionError(f"{label}: liblz4 compression failed")
            native_file.write_bytes(native_block.raw[:count])
            result = subprocess.run(
                [str(program), "decode", str(raw_file), str(native_file)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode:
                raise AssertionError(f"{label}: MiniLang rejected liblz4 block: {result.stdout} {result.stderr}")
            print(f"[OK] {label}: MiniLang <-> liblz4 ({len(raw)} -> {len(mini_block)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
