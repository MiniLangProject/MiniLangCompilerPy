#!/usr/bin/env python3
"""Compare OOP dispatch loops in alternating before/after runs on one CPU."""
import compare_typeof_checks as comparison

comparison.CASES = ("mono", "typed", "poly", "control")

if __name__ == "__main__":
    comparison.main()
