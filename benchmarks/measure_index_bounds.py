"""Measure separately compiled versions of the dynamic-index benchmark."""

import argparse
import json
import statistics
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read-old", type=Path, required=True)
    parser.add_argument("--read-new", type=Path, required=True)
    parser.add_argument("--write-old", type=Path, required=True)
    parser.add_argument("--write-new", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=30)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be positive")

    report = {}
    for mode, expected in (("read", "30000000"), ("write", "59999743")):
        paths = [getattr(args, f"{mode}_old").resolve(),
                 getattr(args, f"{mode}_new").resolve()]
        samples = {str(path): [] for path in paths}
        for _ in range(2):
            for path in paths:
                result = subprocess.run([str(path)], capture_output=True, text=True, check=True)
                if result.stdout.strip() != expected:
                    raise AssertionError(f"{path}: {result.stdout!r}")
        for round_id in range(args.rounds):
            for path in (paths if round_id % 2 == 0 else paths[::-1]):
                start = time.perf_counter()
                result = subprocess.run([str(path)], capture_output=True, text=True, check=True)
                elapsed = time.perf_counter() - start
                if result.stdout.strip() != expected:
                    raise AssertionError(f"{path}: {result.stdout!r}")
                samples[str(path)].append(elapsed * 1000)
        old, new = (statistics.median(samples[str(path)]) for path in paths)
        report[mode] = {"expected_output": expected, "old_median_ms": old,
                        "new_median_ms": new, "change_percent": (new / old - 1) * 100,
                        "samples_ms": samples}
        print(f"{mode}: {old:.2f} -> {new:.2f} ms ({(new / old - 1) * 100:+.2f}%)")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
