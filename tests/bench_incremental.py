"""Measure clean, cold-cache, warm and edited multi-module builds.

All emitted images are checked against a clean build of the same inputs.
Windows memory figures sample private bytes of the compiler process tree;
they are not live MiniLang-heap sizes or OS peak counters. No dependencies.
"""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import tempfile
import time


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("pid", wintypes.DWORD),
        ("heap", ctypes.c_size_t), ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
        ("parent", wintypes.DWORD), ("priority", wintypes.LONG), ("flags", wintypes.DWORD),
        ("exe", wintypes.WCHAR * 260)]


class MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [(x, ctypes.c_size_t)
        for x in ("peak_ws", "ws", "peak_paged", "paged", "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile", "private")]


def tree_private(pid):
    if os.name != "nt":
        return None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(MEMORY_COUNTERS), wintypes.DWORD]
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        return None
    entry = PROCESSENTRY32()
    entry.size = ctypes.sizeof(entry)
    parents = {}
    try:
        valid = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while valid:
            parents[entry.pid] = entry.parent
            valid = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    selected = {pid}
    while True:
        enlarged = selected | {child for child, parent in parents.items() if parent in selected}
        if enlarged == selected:
            break
        selected = enlarged
    total = 0
    for child in selected:
        handle = kernel.OpenProcess(0x410, False, child)
        if handle:
            try:
                counters = MEMORY_COUNTERS()
                counters.cb = ctypes.sizeof(counters)
                if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                    total += counters.private
            finally:
                kernel.CloseHandle(handle)
    return total


def measure(command, cwd, log):
    peak = 0
    started = time.perf_counter()
    with log.open("wb") as handle:
        process = subprocess.Popen(command, cwd=cwd, stdout=handle, stderr=subprocess.STDOUT)
        while process.poll() is None:
            peak = max(peak, tree_private(process.pid) or 0)
            if time.perf_counter() - started > 600:
                process.kill()
                raise TimeoutError(command)
            time.sleep(0.04)
    elapsed = time.perf_counter() - started
    output = log.read_text(encoding="utf-8", errors="replace")
    if process.returncode:
        raise AssertionError((command, output[-4000:]))
    counts = re.findall(r"reused=(\d+) compiled=(\d+) invalid=(\d+)", output)
    return dict(seconds=round(elapsed, 6), sampled_peak_tree_private_mib=round(peak / 1048576, 2),
                reused=sum(int(x[0]) for x in counts), compiled=sum(int(x[1]) for x in counts))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ml-compiler", required=True, type=Path)
    ap.add_argument("--python-repo", type=Path)
    ap.add_argument("--modules", default=16, type=int)
    ap.add_argument("--functions", default=16, type=int, help="functions per module")
    ap.add_argument("--repeats", default=3, type=int)
    ap.add_argument("--report", required=True, type=Path)
    args = ap.parse_args()
    repo = Path(__file__).resolve().parents[1]
    pyrepo = args.python_repo or (repo if (repo / "mlc_win64.py").is_file() else repo.parent / "MiniLangCompilerPy")
    backends = [("python", [sys.executable, str(pyrepo / "mlc_win64.py")], []),
        ("ml-mono", [str(args.ml_compiler.resolve())], ["--no-object-pipeline"]),
        ("ml-mlo", [str(args.ml_compiler.resolve())], ["--object-pipeline"])]
    rows = []
    expected = {}
    with tempfile.TemporaryDirectory(prefix="incremental-bench-", dir=repo / "build") as temporary:
        root = Path(temporary)
        sources = []
        calls = []
        for mi in range(args.modules):
            name = f"b{mi:02}"
            body = f"package {name}\n"
            for fi in range(args.functions):
                body += (f"function work{fi:03}(value)\n  total = value\n  for i = 0 to 31\n"
                    "    total = (total * 3 + i) % 100003\n"
                    "    if total > 50000 then\n      total = total - 777\n    end if\n"
                    "  end for\n  return total + 100\nend function\n")
                calls.append(f"  total = total + {name}.work{fi:03}(17)")
            sources.append((root / (name + ".ml"), body))
        main_source = root / "main.ml"
        main_source.write_text("\n".join(f'import "{path.name}"' for path, _ in sources) +
            "\nfunction main(args)\n  total = 0\n" + "\n".join(calls) + "\n  print total\nend function\n", encoding="utf-8")
        for repeat in range(args.repeats):
            # Alternate order to reduce warm filesystem / thermal ordering bias.
            ordered = backends if repeat % 2 == 0 else list(reversed(backends))
            for backend, command, flags in ordered:
                for path, text in sources:
                    path.write_text(text, encoding="utf-8")
                cache = root / f"cache-{backend}-{repeat}"
                output = root / (backend + ".exe")
                phases = ["clean", "cold", "warm", "warm-again", "early-edit", "early-clean", "late-edit", "late-clean"]
                for phase in phases:
                    if phase == "early-edit":
                        sources[0][0].write_text(sources[0][1].replace("+ 100", "+ 101", 1), encoding="utf-8")
                    if phase == "late-edit":
                        sources[-1][0].write_text(sources[-1][1].replace("+ 100", "+ 102", 1), encoding="utf-8")
                    cached = not phase.endswith("clean")
                    extra = ["--incremental-cache", str(cache)] if cached else []
                    row = measure([*command, str(main_source), str(output), "--no-asm", *flags, *extra], repo, root / "run.log")
                    row.update(backend=backend, repeat=repeat, phase=phase, sha256=hashlib.sha256(output.read_bytes()).hexdigest())
                    version = "early" if phase.startswith("early") else "late" if phase.startswith("late") else "base"
                    if version in expected:
                        assert row["sha256"] == expected[version], (backend, phase, "byte mismatch")
                    expected[version] = row["sha256"]
                    run = subprocess.run([str(output)], capture_output=True, timeout=30)
                    assert run.returncode == 0 and b"Error occured" not in run.stdout, run.stdout
                    rows.append(row)
                    print(f"{backend:8} {repeat} {phase:12} {row['seconds']:.3f}s {row['sampled_peak_tree_private_mib']:.1f} MiB reused={row['reused']}", flush=True)
    report = dict(modules=args.modules, functions_per_module=args.functions, repeats=args.repeats,
                  memory="40 ms samples of compiler process-tree private bytes", rows=rows)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for backend, _, _ in backends:
        for phase in ("clean", "cold", "warm", "warm-again", "early-edit", "late-edit"):
            group = [row for row in rows if row["backend"] == backend and row["phase"] == phase]
            print(backend, phase, f"median={statistics.median(r['seconds'] for r in group):.3f}s")


if __name__ == "__main__":
    main()
