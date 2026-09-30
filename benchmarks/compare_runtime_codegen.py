#!/usr/bin/env python3
"""Compare preserved before/after images; execute this inside each target OS.

Wall time includes process startup and finalization. The program's ms value
uses a high-resolution monotonic clock and measures only the workload.
Heap deltas are managed allocation bytes, not process working set.
"""
import argparse
import hashlib
import json
import platform
import re
import statistics
import subprocess
import time
from pathlib import Path

CASES = ("division", "repeat", "repeat-one", "concat-empty", "join-one",
         "concat-control", "concat-small-control", "repeat-two-control",
         "repeat-two-multi-control", "join-control")
PATTERN = re.compile(r"(\S+) ms=([0-9.eE+-]+) bytes=(\d+) checksum=(-?\d+)")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--runs", type=int, default=11)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("at least three runs are required")
    paths = {"before": args.before.resolve(), "after": args.after.resolve()}
    rows = []
    for case in CASES:
        # Warm each executable once, then alternate order to reduce drift.
        for path in paths.values():
            subprocess.run([str(path), case], check=True, capture_output=True, timeout=60)
        for run in range(args.runs):
            for version in (("before", "after") if run % 2 == 0 else ("after", "before")):
                started = time.perf_counter_ns()
                result = subprocess.run([str(paths[version]), case], check=True,
                                        capture_output=True, text=True, timeout=60)
                wall_ms = (time.perf_counter_ns() - started) / 1e6
                match = PATTERN.fullmatch(result.stdout.strip())
                if not match or match[1] != case:
                    raise RuntimeError(f"Unexpected benchmark output: {result.stdout!r}")
                rows.append(dict(case=case, version=version, run=run, wall_ms=wall_ms,
                                 ms=float(match[2]), bytes=int(match[3]), checksum=int(match[4])))
        checksums = {r["checksum"] for r in rows if r["case"] == case}
        if len(checksums) != 1:
            raise RuntimeError(f"Semantic mismatch in {case}: {checksums}")
    summary = {}
    for case in CASES:
        summary[case] = {}
        for version in paths:
            samples = [r for r in rows if r["case"] == case and r["version"] == version]
            summary[case][version] = {key: statistics.median(r[key] for r in samples)
                                      for key in ("wall_ms", "ms", "bytes", "checksum")}
    payload = dict(platform=platform.platform(), runs=args.runs, summary=summary, samples=rows,
                   images={v: dict(path=str(p), size=p.stat().st_size,
                                   sha256=hashlib.sha256(p.read_bytes()).hexdigest())
                           for v, p in paths.items()})
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
