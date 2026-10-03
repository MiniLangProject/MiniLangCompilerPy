"""Alternate memory-runtime A/B processes with the common timing/RSS harness.

The output 'bytes' field is the final committed managed heap, not allocation
volume. Mark-only cases include forty explicit collections. This benchmark
contains no Thread reference, so it also covers the single-thread allocator.
"""
import compare_runtime_codegen as harness

harness.CASES = ("small-churn", "large-live", "leaf-mark", "graph-mark", "fragmented", "control")

if __name__ == "__main__":
    harness.main()
