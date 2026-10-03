#!/usr/bin/env python3
"""Windows commit-charge probe, distinct from peak working-set measurements."""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import statistics
import subprocess
import sys


class Counters(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
        (name, ctypes.c_size_t) for name in (
            "peak_ws", "ws", "peak_paged", "paged", "peak_nonpaged",
            "nonpaged", "pagefile", "peak_pagefile")]


def measure(path):
    # Keep the process handle open after termination so peak counters survive.
    with subprocess.Popen([str(path), "control"], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as process:
        try:
            output, errors = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        if process.returncode:
            raise RuntimeError(f"{process.returncode}: {output} {errors}")
        api = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
        api.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        api.restype = wintypes.BOOL
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not api(wintypes.HANDLE(int(process._handle)), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return dict(peak_working_set_bytes=counters.peak_ws,
                    peak_commit_bytes=counters.peak_pagefile, output=output.strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Windows only: Linux RSS is measured by compare_memory_management.py")
    paths = {"before": args.before.resolve(), "after": args.after.resolve()}
    rows = []
    for run in range(11):
        for version in (("before", "after") if run % 2 == 0 else ("after", "before")):
            rows.append(dict(version=version, run=run, **measure(paths[version])))
    summary = {
        version: {key: statistics.median(row[key] for row in rows if row["version"] == version)
                  for key in ("peak_working_set_bytes", "peak_commit_bytes")}
        for version in paths}
    args.output.write_text(json.dumps(dict(summary=summary, samples=rows), indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
