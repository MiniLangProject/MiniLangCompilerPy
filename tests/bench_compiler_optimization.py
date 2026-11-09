"""Run alternating compiler experiments, recording time, peak memory and hashes.

The JSON config is a list of {name, command, cwd, artifact?} objects. Commands
must be trusted local experiments. Each round reverses their order; round zero
warms the filesystem and is excluded from medians. On Windows, peaks are OS
high-water marks for the compiler process and its complete Windows job. The
job includes object-pipeline emitter/linker children and tracks their combined
peak commitment, not a sum of unrelated per-process peaks.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import re
import os
from pathlib import Path
import statistics
import subprocess
import time


def measure(command, cwd, timeout=600):
    start = time.perf_counter()
    with subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT) as process:
        job = None
        if os.name == "nt":
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
            kernel.CreateJobObjectW.restype = ctypes.c_void_p
            kernel.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            kernel.QueryInformationJobObject.argtypes = [
                ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            job = kernel.CreateJobObjectW(None, None)
            if not job or not kernel.AssignProcessToJobObject(job, int(process._handle)):
                process.kill()
                process.wait()
                if job:
                    kernel.CloseHandle(job)
                raise ctypes.WinError(ctypes.get_last_error())
        try:
            output, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # The object-pipeline compiler owns emitter/linker children. Stop
            # the complete experiment rather than leaving a timed-out worker.
            if job:
                kernel.TerminateJobObject(job, 1)
            else:
                process.kill()
            process.communicate()
            if job:
                kernel.CloseHandle(job)
            raise
        result = dict(seconds=time.perf_counter() - start,
                      returncode=process.returncode)
        if os.name == "nt":
            class Counters(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulong) for n in ("cb", "faults")] + [
                    (n, ctypes.c_size_t) for n in
                    ("peak_working_set", "working_set", "peak_paged_pool", "paged_pool",
                     "peak_nonpaged_pool", "nonpaged_pool", "pagefile", "peak_private",
                     "private")]
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            api = ctypes.WinDLL("psapi", use_last_error=True)
            api.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
            if not api.GetProcessMemoryInfo(int(process._handle), ctypes.byref(counters), counters.cb):
                raise ctypes.WinError(ctypes.get_last_error())
            result.update(peak_working_set=counters.peak_working_set,
                          peak_private=counters.peak_private)
            class BasicLimits(ctypes.Structure):
                _fields_ = [
                    ("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                    ("flags", ctypes.c_ulong), ("minimum_ws", ctypes.c_size_t),
                    ("maximum_ws", ctypes.c_size_t), ("active", ctypes.c_ulong),
                    ("affinity", ctypes.c_size_t), ("priority", ctypes.c_ulong),
                    ("scheduling", ctypes.c_ulong)]
            class JobLimits(ctypes.Structure):
                _fields_ = [("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
                            ("process_limit", ctypes.c_size_t), ("job_limit", ctypes.c_size_t),
                            ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
            limits = JobLimits()
            ok = kernel.QueryInformationJobObject(job, 9, ctypes.byref(limits),
                                                 ctypes.sizeof(limits), None)
            class Accounting(ctypes.Structure):
                _fields_ = [(name, ctypes.c_int64) for name in
                            ("user", "kernel", "period_user", "period_kernel")] + [
                            (name, ctypes.c_ulong) for name in
                            ("faults", "processes", "active", "terminated")]
            accounting = Accounting()
            ok = ok and kernel.QueryInformationJobObject(job, 1, ctypes.byref(accounting),
                                                         ctypes.sizeof(accounting), None)
            kernel.CloseHandle(job)
            if not ok:
                raise ctypes.WinError(ctypes.get_last_error())
            result.update(peak_tree_private=limits.peak_job,
                          peak_child_private=limits.peak_process,
                          cpu_seconds=(accounting.user + accounting.kernel) / 10000000,
                          processes=accounting.processes)
    if result["returncode"]:
        raise RuntimeError(output.decode("utf-8", errors="replace"))
    return result, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--cpu", type=int, default=4)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("at least one measured round is required")
    if args.cpu < 0:
        parser.error("CPU index must be nonnegative")
    if os.name == "nt":
        if args.cpu >= ctypes.sizeof(ctypes.c_size_t) * 8:
            parser.error("CPU index exceeds the current Windows processor group")
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.GetCurrentProcess.restype = ctypes.c_void_p
        api.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        if not api.SetProcessAffinityMask(api.GetCurrentProcess(), 1 << args.cpu):
            raise ctypes.WinError(ctypes.get_last_error())
    cases = json.loads(args.config.read_text(encoding="utf-8"))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for repeat in range(args.repeats + 1):
        for case in (cases if repeat % 2 == 0 else list(reversed(cases))):
            row, output = measure(case["command"], case["cwd"], case.get("timeout", 600))
            row.update(name=case["name"], round=repeat, warmup=repeat == 0)
            profile = re.search(rb"object_function_batches=\d+ setup_ms=(\d+) codegen_ms=(\d+) serialize_ms=(\d+)", output)
            if profile:
                row.update(zip(("setup_ms", "codegen_ms", "serialize_ms"), map(int, profile.groups())))
            if case.get("artifact"):
                data = Path(case["artifact"]).read_bytes()
                row.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
            rows.append(row)
            args.report.with_name(f'{args.report.stem}-{case["name"]}.log').write_bytes(output)
            args.report.with_name(f'{args.report.stem}-{case["name"]}-{repeat}.log').write_bytes(output)
            args.report.write_text(json.dumps(dict(config=cases, rows=rows), indent=2))
            print(json.dumps(row), flush=True)
    summaries = {}
    for case in cases:
        data = [r for r in rows if r["name"] == case["name"] and not r["warmup"]]
        summaries[case["name"]] = {
            k: statistics.median([r[k] for r in data])
            for k in ("seconds", "cpu_seconds", "peak_working_set", "peak_private",
                      "peak_tree_private", "peak_child_private", "size", "setup_ms", "codegen_ms", "serialize_ms") if k in data[0]}
    args.report.write_text(json.dumps(dict(config=cases, rows=rows, medians=summaries), indent=2))
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
