#!/usr/bin/env python3
"""Sample current process residency at an explicit two-phase child handshake."""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import threading

from compare_memory_commit import Counters


def memory(process):
    if sys.platform == "win32":
        api = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
        api.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        api.restype = wintypes.BOOL
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not api(wintypes.HANDLE(int(process._handle)), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return dict(resident_bytes=counters.ws, commit_bytes=counters.pagefile)
    if sys.platform.startswith("linux"):
        status = (Path("/proc") / str(process.pid) / "status").read_text()
        rss = next(line for line in status.splitlines() if line.startswith("VmRSS:"))
        return dict(resident_bytes=int(rss.split()[1]) * 1024)
    raise RuntimeError("Windows/Linux only")


def measure(path):
    with subprocess.Popen([str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as process:
        watchdog = threading.Timer(60, process.kill)
        watchdog.daemon = True
        watchdog.start()
        try:
            observations = {}
            for phase in ("allocated", "collected"):
                line = process.stdout.readline().strip()
                if line != phase:
                    raise RuntimeError(f"Expected {phase}, got {line!r}")
                observations[phase] = memory(process)
                process.stdin.write("\n")
                process.stdin.flush()
            output, errors = process.communicate(timeout=60)
            if process.returncode or output.strip() != "RESIDENCY [OK]":
                raise RuntimeError(f"{process.returncode}: {output} {errors}")
            return observations
        finally:
            watchdog.cancel()
            if process.poll() is None:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    paths = {"before": args.before.resolve(), "after": args.after.resolve()}
    rows = []
    for run in range(11):
        for version in (("before", "after") if run % 2 == 0 else ("after", "before")):
            rows.append(dict(version=version, run=run, **measure(paths[version])))
    summary = {}
    for version in paths:
        samples = [row for row in rows if row["version"] == version]
        summary[version] = {
            phase: {key: statistics.median(row[phase][key] for row in samples)
                    for key in samples[0][phase]}
            for phase in ("allocated", "collected")}
    args.output.write_text(json.dumps(dict(platform=platform.platform(), summary=summary,
                                          samples=rows), indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
