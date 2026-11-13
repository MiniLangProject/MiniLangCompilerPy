#!/usr/bin/env python3
"""Compare conditional-index loops using the common alternating runtime runner.

The fixture mirrors loop bodies from tests/codegen_optimizations.ml and checks
the expected checksum before reporting a timing result.
"""
import compare_runtime_codegen as comparison

comparison.CASES = ("array-elif", "bytes-elif", "case-value", "case-range", "single-control")

if __name__ == "__main__":
    comparison.main()
