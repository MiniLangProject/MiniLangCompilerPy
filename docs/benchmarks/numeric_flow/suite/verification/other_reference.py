"""Independent correctness oracles for numeric, text and native-bulk kernels.

This module performs no compilation, subprocess execution or timing. Import
``expected_checksum`` and call it with the same case/n/seed as one bench call.
Use small inputs for verification: the Python implementations intentionally
prioritize transparency and algorithmic independence over speed.

The string oracle uses Python formatting and join, the ASCII oracle sums the
generated integers without reproducing the parser, the tree oracle visits
levels instead of recursing, and the bulk oracles derive the final buffer or
marker position without performing the repeated copy/search operations.

Numeric floating-point references use Python binary64 operations in the same
specified evaluation order. Their integer results verify the benchmark's
published checksum, not every floating-point intermediate bit pattern.
"""

from __future__ import annotations

from collections.abc import Iterator


MASK = (1 << 31) - 1
CASES = (
    "int_mix",
    "branch_mix",
    "float_recurrence",
    "mandelbrot",
    "recursive_tree",
    "ascii_parse",
    "string_concat",
    "string_builder",
    "byte_copy",
    "byte_search",
)


def _check_input(case: str, n: int, seed: int) -> None:
    if case not in CASES:
        raise ValueError(f"unknown numeric/text/bulk kernel: {case}")
    if type(n) is not int or n < 1:
        raise ValueError("n must be a positive integer, as in the timing driver")
    if type(seed) is not int or not 0 <= seed <= MASK:
        raise ValueError("seed must be an integer in 0..2147483647")
    if case == "byte_search" and n < 32:
        raise ValueError("byte_search requires n >= 32")
    if case == "mandelbrot" and n > 4096:
        raise ValueError("mandelbrot's documented input domain is n <= 4096")
    if case == "float_recurrence" and n > 100_000_000:
        raise ValueError("float_recurrence's documented domain is n <= 100000000")
    if case in ("ascii_parse", "string_concat", "string_builder") and n > 10_000_000:
        raise ValueError("the documented text-kernel domain is n <= 10000000")


def _next_state(value: int) -> int:
    return (value * 1_664_525 + 1_013_904_223) & MASK


def _states(n: int, seed: int) -> Iterator[int]:
    state = seed
    for _ in range(n):
        state = _next_state(state)
        yield state


def _int_mix(n: int, seed: int) -> int:
    x, y = seed, seed ^ 1_103_515_245
    total = 0
    for _ in range(n):
        x = _next_state(x)
        y = ((y ^ (x >> 7)) * 48_271 + 17) & MASK
        total += (x ^ y) & 65_535
    # Modular accumulation can be deferred because Python integers do not
    # overflow and only these low 31 accumulator bits are returned.
    return ((total & MASK) ^ x ^ y) & MASK


def _branch_mix(n: int, seed: int) -> int:
    accumulator = (seed ^ 123_456_789) & MASK
    state = seed
    for state in _states(n, seed):
        if state & (1 << 30):
            accumulator = (
                (accumulator ^ (state >> 5))
                + (accumulator & 65_535) * 5
            ) & MASK
        else:
            accumulator = (3 * accumulator + (state >> 3) + 17) & MASK
    return (accumulator ^ state) & MASK


def _float_recurrence(n: int, seed: int) -> int:
    x = 0.123456789012345 + float(seed & 65_535) * 0.00000123456789
    y = 0.987654321098765 + float((seed >> 8) & 65_535) * 0.00000034567891
    accumulated = 0.0
    for _ in range(n):
        # Evaluate both right-hand sides using the previous pair. Parentheses
        # spell out the rounding order used by the no-fast-math C reference.
        x, y = (
            (x * 0.9999991 + y * 0.0000003) + 0.0000007,
            (y * 0.9999989 + x * 0.0000002) + 0.0000005,
        )
        accumulated = (
            accumulated + x * 0.333333333333333
        ) + y * 0.142857142857143
    return int(accumulated * 1000.0) & MASK


def _mandelbrot(n: int, seed: int) -> int:
    scale = 3.0 / float(n)
    offset = float(seed & 255) * 0.0000001
    total = 0
    for row in range(n):
        cy = -1.5 + float(row) * scale
        for column in range(n):
            cx = (-2.0 + float(column) * scale) + offset
            real = imaginary = real_squared = imaginary_squared = 0.0
            for _ in range(80):
                if not real_squared + imaginary_squared <= 4.0:
                    break
                imaginary = (2.0 * real) * imaginary + cy
                real = (real_squared - imaginary_squared) + cx
                real_squared = real * real
                imaginary_squared = imaginary * imaginary
                total += 1
    return total


def _tree_value(root: int) -> int:
    # The benchmark adds every internal node's low byte and every leaf's
    # transformed low 16 bits. Level-order enumeration derives that sum
    # independently of the benchmark's recursive call structure.
    frontier = [root]
    total = 0
    for _ in range(10):
        total += sum(value & 255 for value in frontier)
        frontier = [
            child
            for value in frontier
            for child in (
                _next_state(value),
                (value * 22_695_477 + 1) & MASK,
            )
        ]
    total += sum((value ^ (value >> 11)) & 65_535 for value in frontier)
    return total & MASK


def _recursive_tree(n: int, seed: int) -> int:
    state = seed
    total = 0
    for _ in range(n):
        state = (state * 48_271 + 31) & MASK
        total += _tree_value(state)
    return total & MASK


def _ascii_parse(n: int, seed: int) -> int:
    # All generated values have six decimal digits and a final newline.
    # Their mathematical sum is independent of the formatting/parser loops.
    return sum(100_000 + state % 900_000 for state in _states(n, seed)) & MASK


def _string_result(n: int, seed: int) -> int:
    # Each eight-digit half is emitted least-significant hexadecimal nibble
    # first by the benchmark. Reverse Python's fixed-width formatted result
    # instead of duplicating its mutable scratch-buffer digit loop.
    chunks = [
        f"{state:08x}"[::-1]
        + f"{(state ^ 0x55555555) & MASK:08x}"[::-1]
        for state in _states(n, seed)
    ]
    text = "".join(chunks)
    checksum = 0
    for byte in text.encode("ascii"):
        checksum = (checksum * 131 + byte) & MASK
    return checksum


def _byte_copy(n: int, seed: int) -> int:
    # Every round copies the full source. The final destination therefore
    # equals the original fill with the last write to each changed index.
    # Dict overwrite preserves the final write even when small n causes
    # several mutation rounds to target the same position.
    writes = {
        (seed + round_index * 7_919) % n: (seed + round_index) & 255
        for round_index in range(32)
    }
    final_buffer = bytearray([seed & 255]) * n
    for index, value in writes.items():
        final_buffer[index] = value
    checksum = 5_381
    for byte in final_buffer:
        checksum = ((checksum * 33) ^ byte) & MASK
    return checksum


def _byte_search(n: int, seed: int) -> int:
    # For n >= 32 the only marker starts after all search offsets (0..6),
    # so every one of the 32 searches returns this absolute position.
    span = min(n - 16, 4_096)
    position = n - 7 - seed % span
    return (32 * position) & MASK


_ORACLES = {
    "int_mix": _int_mix,
    "branch_mix": _branch_mix,
    "float_recurrence": _float_recurrence,
    "mandelbrot": _mandelbrot,
    "recursive_tree": _recursive_tree,
    "ascii_parse": _ascii_parse,
    "string_concat": _string_result,
    "string_builder": _string_result,
    "byte_copy": _byte_copy,
    "byte_search": _byte_search,
}


def expected_checksum(case: str, n: int, seed: int) -> int:
    """Return the expected result of one bench(n, seed), without driver work."""
    _check_input(case, n, seed)
    return _ORACLES[case](n, seed)


def expected_batch_checksum(case: str, n: int, reps: int, seed: int) -> int:
    """Return the measured driver's sum for its repeating eight-seed cycle.

    Supports small verification counts such as 1 and 3, in addition to the
    balanced multiples of eight used for performance measurements. Each
    unique seed is evaluated at most once, even for a very large reps value.
    """
    _check_input(case, n, seed)
    if type(reps) is not int or not 1 <= reps <= 10_000_000:
        raise ValueError("reps must be an integer in 1..10000000")
    cycles, tail = divmod(reps, 8)
    count = 8 if cycles else tail
    values = [
        expected_checksum(case, n, (seed + offset) & MASK)
        for offset in range(count)
    ]
    return (cycles * sum(values) + sum(values[:tail])) & MASK


def expected_warmup_checksum(case: str, n: int, seed: int) -> int:
    """Return the driver's untimed warmup result."""
    _check_input(case, n, seed)
    return expected_checksum(case, n, (seed + 65_536) & MASK)
