#!/usr/bin/env python3
"""Measure explicit stop-the-world GC pauses on one retained object graph.

Run inside each target OS. Samples exclude setup/output and are not safepoint
wait-time measurements for a contended, multithreaded application.
"""
import argparse
import hashlib
import json
import platform
import statistics
from pathlib import Path

from compare_runtime_codegen import run_measured


def percentile(values, fraction):
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("at least three process pairs are required")
    paths = {"before": args.before.resolve(), "after": args.after.resolve()}
    samples = []
    for run in range(args.runs):
        for version in (("before", "after") if run % 2 == 0 else ("after", "before")):
            output, peak = run_measured(paths[version], "pause-samples")
            lines = output.strip().splitlines()
            if len(lines) != 101 or not lines[0].startswith("frequency="):
                raise RuntimeError(f"Unexpected pause output: {output!r}")
            frequency = int(lines[0].split("=", 1)[1])
            if frequency <= 0:
                raise RuntimeError("Invalid timer frequency")
            pauses = [int(value) * 1000.0 / frequency for value in lines[1:]]
            if min(pauses) < 0:
                raise RuntimeError("Non-monotonic clock")
            samples.append(dict(version=version, run=run, pauses_ms=pauses,
                                peak_rss_bytes=peak))
    summary = {}
    for version in paths:
        values = [value for sample in samples if sample["version"] == version
                  for value in sample["pauses_ms"]]
        summary[version] = dict(count=len(values), p50_ms=statistics.median(values),
                                p95_ms=percentile(values, 0.95), max_ms=max(values))
    payload = dict(platform=platform.platform(), runs=args.runs, summary=summary,
                   samples=samples, images={
                       version: dict(size=path.stat().st_size,
                                     sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                       for version, path in paths.items()})
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
