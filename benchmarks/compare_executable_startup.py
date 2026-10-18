#!/usr/bin/env python3
"""Measure warm executable startup, including unpacking, with peak OS RSS.

Compare unpacked/packed images using the same single argument (default: -version).
This is not a cold-storage, antivirus or managed-heap benchmark.
"""
import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import time
from pathlib import Path
from compare_runtime_codegen import run_measured


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--argument", default="-version")
    parser.add_argument("--runs", type=int, default=11)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("at least three runs are required")
    paths = {"before": args.before.resolve(), "after": args.after.resolve()}
    expected = None
    for path in paths.values():
        result = subprocess.run([str(path), args.argument], capture_output=True,
                                check=True, text=True, timeout=60)
        if expected is None:
            expected = result.stdout
        assert result.stdout == expected, "warm-up output differs"
    samples = []
    for index in range(args.runs):
        for version in (("before", "after") if index % 2 == 0 else ("after", "before")):
            start = time.perf_counter_ns()
            stdout, peak = run_measured(paths[version], args.argument)
            elapsed = (time.perf_counter_ns() - start) / 1e6
            assert stdout == expected, "packed/unpacked output differs"
            samples.append(dict(version=version, run=index, wall_ms=elapsed, peak_rss_bytes=peak))
    summary = {version: {key: statistics.median(row[key] for row in samples if row["version"] == version)
                         for key in ("wall_ms", "peak_rss_bytes")} for version in paths}
    payload = dict(platform=platform.platform(), argument=args.argument, runs=args.runs,
                   summary=summary, samples=samples,
                   images={v: dict(size=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest())
                           for v, p in paths.items()})
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
