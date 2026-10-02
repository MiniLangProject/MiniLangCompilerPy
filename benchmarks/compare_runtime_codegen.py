#!/usr/bin/env python3
"""Compare preserved before/after images; execute this inside each target OS.

Wall time includes process startup and finalization. The program's ms value
uses a high-resolution monotonic clock and measures only the workload.
Heap deltas are bump-pointer growth, not cumulative allocation or working set.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path


def run_measured(path, case):
    """Capture per-process peak RSS, separately from managed allocation bytes."""
    command = [str(path), case]
    if sys.platform.startswith("linux"):
        command = ["/usr/bin/time", "-f", "peak_rss_kib=%M", *command]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        if process.returncode:
            raise RuntimeError(f"{case}: exit {process.returncode}: {stdout} {stderr}")
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                    (name, ctypes.c_size_t) for name in (
                        "peak_ws", "ws", "peak_paged", "paged", "peak_nonpaged",
                        "nonpaged", "pagefile", "peak_pagefile")]

            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            api = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
            api.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            api.restype = wintypes.BOOL
            if not api(wintypes.HANDLE(int(process._handle)), ctypes.byref(counters), counters.cb):
                raise ctypes.WinError(ctypes.get_last_error())
            peak = counters.peak_ws
        elif sys.platform.startswith("linux"):
            peak = int(re.search(r"peak_rss_kib=(\d+)", stderr)[1]) * 1024
        else:
            raise RuntimeError("Peak RSS measurement supports Windows and Linux only")
        return stdout, peak

CASES = ("struct-projection", "dynamic-index", "local-register", "inline-literal", "cold-errors",
         "division", "division-constants", "division-wide", "local-cse",
         "integer-format", "integer-format-small", "repeat", "repeat-one", "concat-empty", "join-one",
         "concat-control", "concat-small-control", "repeat-two-control",
         "repeat-two-multi-control", "join-control")
PATTERN = re.compile(r"(\S+) ms=([0-9.eE+-]+) bytes=(\d+) checksum=(-?\d+)")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--runs", type=int, default=11)
    parser.add_argument("--cpu", type=int, help="pin this runner and inherited child processes to one logical CPU")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("at least three runs are required")
    if args.cpu is not None:
        if args.cpu < 0:
            parser.error("CPU index must be nonnegative")
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes
            if args.cpu >= ctypes.sizeof(ctypes.c_size_t) * 8:
                parser.error("CPU index exceeds the current Windows processor group")
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            kernel.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
            kernel.SetProcessAffinityMask.restype = wintypes.BOOL
            if not kernel.SetProcessAffinityMask(kernel.GetCurrentProcess(), 1 << args.cpu):
                raise ctypes.WinError(ctypes.get_last_error())
        elif sys.platform.startswith("linux"):
            os.sched_setaffinity(0, {args.cpu})
        else:
            parser.error("CPU affinity supports Windows and Linux only")
    paths = {"before": args.before.resolve(), "after": args.after.resolve()}
    rows = []
    for case in CASES:
        # Warm each executable once, then alternate order to reduce drift.
        for path in paths.values():
            subprocess.run([str(path), case], check=True, capture_output=True, timeout=60)
        for run in range(args.runs):
            for version in (("before", "after") if run % 2 == 0 else ("after", "before")):
                started = time.perf_counter_ns()
                stdout, peak_rss = run_measured(paths[version], case)
                wall_ms = (time.perf_counter_ns() - started) / 1e6
                match = PATTERN.fullmatch(stdout.strip())
                if not match or match[1] != case:
                    raise RuntimeError(f"Unexpected benchmark output: {stdout!r}")
                rows.append(dict(case=case, version=version, run=run, wall_ms=wall_ms,
                                 ms=float(match[2]), bytes=int(match[3]), checksum=int(match[4]),
                                 peak_rss_bytes=peak_rss))
        checksums = {r["checksum"] for r in rows if r["case"] == case}
        if len(checksums) != 1:
            raise RuntimeError(f"Semantic mismatch in {case}: {checksums}")
    summary = {}
    for case in CASES:
        summary[case] = {}
        for version in paths:
            samples = [r for r in rows if r["case"] == case and r["version"] == version]
            summary[case][version] = {key: statistics.median(r[key] for r in samples)
                                      for key in ("wall_ms", "ms", "bytes", "checksum", "peak_rss_bytes")}
    payload = dict(platform=platform.platform(), runs=args.runs, cpu=args.cpu, summary=summary, samples=rows,
                   images={v: dict(path=str(p), size=p.stat().st_size,
                                   sha256=hashlib.sha256(p.read_bytes()).hexdigest())
                           for v, p in paths.items()})
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
