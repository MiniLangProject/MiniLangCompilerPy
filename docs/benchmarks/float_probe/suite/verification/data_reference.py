#!/usr/bin/env python3
"""Reproduce correctness checks for the five data kernels (no timing).

Linux/WSL example:
  python3 verification/data_reference.py \
      --compiler /path/to/MiniLangCompilerPy/mlc_win64.py \
      --stdlib /path/to/MiniLangCompilerPy \
      --report results/data_reference_validation.json

An existing Linux native MiniLang compiler can be supplied instead of the .py
entry point. The default checks use only tiny inputs. The reference sieve uses
independent trial division and is intentionally not suitable for large n.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile


MASK32 = (1 << 32) - 1
CHECKSUM_MASK = (1 << 30) - 1
DEFAULT_SIZES = [-2, 0, 1, 2, 3, 17, 257]
DEFAULT_SEEDS = [0, 1, 12345, 4294967295, -17]
CASES = ["array_scan", "array_scatter", "sieve", "heapsort", "escaped_nodes"]


def generate_values(n: int, seed: int) -> tuple[list[int], int]:
    state = seed & MASK32
    values = []
    for _ in range(n):
        state = (state * 1664525 + 1013904223) & MASK32
        values.append(state)
    return values, state


def expected_checksum(case: str, n: int, seed: int) -> int:
    """Independent mathematical/reference answer for one kernel input.

    Heapsort uses Python's sorted rather than a copy of the heap algorithm;
    sieve uses trial division; scan uses the closed form of preceding updates;
    nodes use reversed values without constructing any linked objects.
    The scatter reference directly interprets the stated RMW sequence.
    """
    if case not in CASES:
        raise ValueError(f"unknown data kernel: {case}")
    if case == "sieve":
        count = sum(
            all(candidate % divisor for divisor in range(2, math.isqrt(candidate) + 1))
            for candidate in range(2, n + 1)
        )
        return count ^ (seed & 65535)
    if n <= 0:
        return 0
    values, state = generate_values(n, seed)
    checksum = 0
    if case == "array_scan":
        original = [value & 65535 for value in values]
        for round_index in range(16):
            offset = round_index * (seed & 255) + round_index * (round_index - 1) // 2
            round_sum = sum((value + offset) & 65535 for value in original) & CHECKSUM_MASK
            checksum = (checksum * 33 + round_sum) & CHECKSUM_MASK
    elif case == "array_scatter":
        values = [value & 65535 for value in values]
        for round_index in range(8):
            for _ in range(n):
                state = (state * 1664525 + 1013904223) & MASK32
                index = state % n
                value = values[index]
                values[index] = (value + (state & 1023) + round_index) & 65535
                checksum = (checksum + value + (index & 255)) & CHECKSUM_MASK
    elif case == "heapsort":
        for value in sorted(value & 2147483647 for value in values):
            checksum = (checksum * 257 + value) & CHECKSUM_MASK
    elif case == "escaped_nodes":
        for value in reversed(values):
            checksum = (checksum * 33 + (value & 65535)) & CHECKSUM_MASK
    return checksum


ML_MAIN = """
function main(args)
  print bench(toNumber(args[0]), toNumber(args[1]))
  return 0
end function
"""

C_MAIN = r'''
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    printf("%lld\n", (long long)bench((int64_t)strtoll(argv[1], NULL, 10),
                                    (int64_t)strtoll(argv[2], NULL, 10)));
    return 0;
}
'''

CPP_MAIN = r'''
#include <iostream>
#include <cstdlib>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    std::cout << bench((int64_t)std::strtoll(argv[1], nullptr, 10),
                       (int64_t)std::strtoll(argv[2], nullptr, 10)) << "\n";
    return 0;
}
'''


def checked_command(command: list[str], timeout: float) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {command!r}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result.stdout.strip()


def validate(args: argparse.Namespace, build: Path) -> dict:
    build.mkdir(parents=True, exist_ok=True)
    compiler = args.compiler.resolve()
    stdlib = args.stdlib.resolve()
    minilang_command = [str(compiler)]
    if compiler.suffix.lower() == ".py":
        minilang_command.insert(0, sys.executable)
    results = []
    total_checks = 0
    for case in args.cases:
        for suffix, wrapper in [(".ml", ML_MAIN), (".c", C_MAIN), (".cpp", CPP_MAIN)]:
            source = (args.kernels / (case + suffix)).read_text(encoding="utf-8")
            (build / (case + suffix)).write_text(source + wrapper, encoding="utf-8")
        commands = [
            minilang_command + [str(build / (case + ".ml")), str(build / (case + "_ml")),
                                "--target", "linux-x64", "-I", str(stdlib)],
            [args.gcc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(build / (case + ".c")), "-o", str(build / (case + "_c"))],
            [args.gxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
             str(build / (case + ".cpp")), "-o", str(build / (case + "_cpp"))],
        ]
        for command in commands:
            checked_command(command, args.compile_timeout)
        count = 0
        for n in args.sizes:
            for seed in args.seeds:
                expected = expected_checksum(case, n, seed)
                for language in ("ml", "c", "cpp"):
                    command = [str(build / (case + "_" + language)), str(n), str(seed)]
                    output = checked_command(command, args.run_timeout)
                    if output != str(expected):
                        raise AssertionError(
                            f"{case}/{language}: n={n}, seed={seed}, "
                            f"expected {expected}, received {output!r}"
                        )
                    count += 1
        total_checks += count
        results.append({"id": case, "status": "PASS", "process_checks": count,
                        "sizes": args.sizes, "seeds": args.seeds,
                        "compile_commands": commands})
        print(f"{case}: {count} exact-output checks PASS", flush=True)
    return {"purpose": "correctness only; no timing measurements",
            "status": "PASS", "total_process_checks": total_checks,
            "compiler": str(compiler), "stdlib": str(stdlib), "cases": results}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--compiler", type=Path, required=True, help="Python entry point or native Linux MiniLang compiler")
    parser.add_argument("--stdlib", type=Path, required=True, help="import root containing std/")
    parser.add_argument("--kernels", type=Path, default=Path(__file__).resolve().parents[1] / "kernels" / "data")
    parser.add_argument("--build-dir", type=Path, help="retain generated wrappers and binaries here; otherwise use a temporary directory")
    parser.add_argument("--report", type=Path, help="optional JSON correctness report")
    parser.add_argument("--gcc", default="gcc")
    parser.add_argument("--gxx", default="g++")
    parser.add_argument("--cases", choices=CASES, nargs="+", default=CASES)
    parser.add_argument("--sizes", type=int, nargs="+", default=DEFAULT_SIZES)
    parser.add_argument("--seeds", type=int, nargs="+", default=DEFAULT_SEEDS)
    parser.add_argument("--compile-timeout", type=float, default=120.0)
    parser.add_argument("--run-timeout", type=float, default=10.0)
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("this reproduction runner targets Linux or WSL")
    if args.build_dir:
        result = validate(args, args.build_dir.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="minilang-data-reference-") as directory:
            result = validate(args, Path(directory))
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Total: {result['total_process_checks']} checks PASS; no timing was measured.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
