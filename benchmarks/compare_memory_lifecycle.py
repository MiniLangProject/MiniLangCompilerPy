"""Alternate native before/after lifecycle probes; run inside each target OS.

The per-program GC/allocator timers exclude process creation. Private commit is
sampled only by the Windows fixture; Linux reports zero (unavailable), not RSS.
Use --metadata-before/after for images built with --heap-shrink.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import platform
import statistics
import subprocess


def validate_fields(mode, fields):
    """Reject failed native operations even if the probe printed an exit-0 report."""
    if any(not math.isfinite(value) or value < 0
           for values in fields.values() for value in values):
        raise RuntimeError(f"Invalid measurement in {mode}: {fields}")
    if mode in ("contexts", "closed-contexts"):
        expected = [1000.0, 1000.0] if mode == "closed-contexts" else [0.0, 0.0]
        if fields.get("closed") != expected:
            raise RuntimeError(f"Thread lifecycle failed in {mode}: {fields}")
        for key in ("live", "heap_committed", "private_commit", "gc50_ms"):
            if len(fields.get(key, [])) != 3:
                raise RuntimeError(f"Incomplete {mode} samples: {fields}")
    elif mode in ("ids", "cleared-ids") and fields.get("closed") != [0.0]:
        raise RuntimeError(f"Unexpected lifecycle result in {mode}: {fields}")


def run(path, mode):
    process = subprocess.run([str(path), mode], capture_output=True, text=True, timeout=90)
    if process.returncode:
        raise RuntimeError(f"{path} {mode}: {process.returncode}: {process.stdout} {process.stderr}")
    fields = {}
    for line in process.stdout.splitlines():
        key, value = line.split("=", 1)
        fields.setdefault(key, []).append(float(value))
    validate_fields(mode, fields)
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("before", "after", "fragmentation-before", "fragmentation-after",
                 "metadata-before", "metadata-after"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("at least three alternating samples are required")
    pairs = {
        "lifecycle": {"before": args.before.resolve(), "after": args.after.resolve()},
        "fragmentation": {"before": args.fragmentation_before.resolve(), "after": args.fragmentation_after.resolve()},
        "metadata": {"before": args.metadata_before.resolve(), "after": args.metadata_after.resolve()},
    }
    rows, summary = [], {}
    for group, modes in (
        ("lifecycle", ("contexts", "closed-contexts", "ids", "cleared-ids", "handoff")),
        ("fragmentation", ("none", "double", "quadruple")),
        ("metadata", ("worklist",)),
    ):
        for mode in modes:
            for path in pairs[group].values():
                run(path, mode)
            samples = {version: [] for version in pairs[group]}
            for number in range(args.runs):
                for version in (("before", "after") if number % 2 == 0 else ("after", "before")):
                    fields = run(pairs[group][version], mode)
                    samples[version].append(fields)
                    rows.append(dict(group=group, mode=mode, version=version, run=number, values=fields))
            key = group + ":" + mode
            summary[key] = {
                version: {name: [statistics.median(sample[name][i] for sample in values)
                                 for i in range(len(values[0][name]))] for name in values[0]}
                for version, values in samples.items()
            }
            print(key, json.dumps(summary[key]), flush=True)
    images = {group: {version: dict(path=str(path), size=path.stat().st_size,
                                    sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                      for version, path in pair.items()} for group, pair in pairs.items()}
    args.output.write_text(json.dumps(dict(platform=platform.platform(), runs=args.runs,
                                          images=images, summary=summary, samples=rows), indent=2) + "\n",
                           encoding="utf-8")


if __name__ == "__main__":
    main()
