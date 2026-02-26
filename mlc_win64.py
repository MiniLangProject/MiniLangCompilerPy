#!/usr/bin/env python3
"""MiniLang native compiler (Windows x64) — CLI entrypoint.

This file is intentionally tiny: it forwards the command line to
``mlc.compiler.main``.

Usage:
    python mlc_win64.py <input.ml> <output.exe> [options]
"""

from __future__ import annotations

import sys
from typing import List, Optional

from mlc.compiler import main


def run(argv: Optional[List[str]] = None) -> int:
    """Run the compiler CLI.

    Args:
        argv: Argument vector including program name. If ``None`` (default),
            :data:`sys.argv` is used.

    Returns:
        Process exit code (0 on success, non-zero on failure).
    """

    return main(sys.argv if argv is None else argv)


if __name__ == "__main__":
    raise SystemExit(run())
