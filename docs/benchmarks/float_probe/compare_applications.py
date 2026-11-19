#!/usr/bin/env python3
"""Compare two native MiniLang compilers and the real formatter they produce.

Linux-only runner. It compiles the unchanged shipped tools/mlfmt.ml with each
compiler and formats a frozen, real compiler source file. Input/output hashes,
all warmups and measured rows are retained. Times include process startup and
cached filesystem I/O. Results describe these tools, not all MiniLang programs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics
import subprocess
import sys
import time


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def file_record(path: Path) -> dict:
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": digest(path)}


def git(repository: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *arguments], text=True).strip()


def measure(command: list[str], cwd: Path, log: Path, timeout: float) -> dict:
    """Collect one child's wall time and wait4 usage, without memory polling.

    The monolithic compiler has no object-emitter children. maxrss is Linux's
    per-process high-water mark in KiB, not managed allocations or reserved heap.
    """
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Application exceeded {timeout} seconds")

    previous = signal.signal(signal.SIGALRM, timeout_handler)
    environment = os.environ.copy()
    environment.update(LC_ALL="C", TZ="UTC")
    try:
        with log.open("wb") as stream:
            started = time.perf_counter_ns()
            process = subprocess.Popen(
                command, cwd=cwd, env=environment, stdout=stream,
                stderr=subprocess.STDOUT, start_new_session=True)
            reaped = False
            try:
                signal.setitimer(signal.ITIMER_REAL, timeout)
                waited, status, usage = os.wait4(process.pid, 0)
                reaped = True
                elapsed = time.perf_counter_ns() - started
                if waited != process.pid:
                    raise RuntimeError("wait4 returned an unexpected child PID")
                process.returncode = os.waitstatus_to_exitcode(status)
            except BaseException:
                if not reaped:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    _, status, _ = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                raise
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
        if process.returncode != 0:
            raise RuntimeError(
                f"Application exited {process.returncode}: {command!r}\n"
                + log.read_text(errors="replace")[-8000:])
        return {"wall_seconds": elapsed / 1e9,
                "cpu_seconds": usage.ru_utime + usage.ru_stime,
                "user_seconds": usage.ru_utime,
                "system_seconds": usage.ru_stime,
                "peak_rss_kib": usage.ru_maxrss,
                "minor_faults": usage.ru_minflt,
                "major_faults": usage.ru_majflt,
                "voluntary_switches": usage.ru_nvcsw,
                "involuntary_switches": usage.ru_nivcsw,
                "returncode": process.returncode,
                "command": command, "log": str(log)}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def summarize(rows: list[dict], rounds: int) -> dict:
    result = {}
    for case in ("compile_formatter", "format_compiler_source"):
        by_variant = {
            name: [r for r in rows if r["case"] == case
                   and r["variant"] == name and not r["warmup"]]
            for name in ("before", "after")}
        if not all(len(group) == rounds for group in by_variant.values()):
            raise RuntimeError("Measured row count differs from the preset rounds")
        pairs = []
        for round_number in range(rounds):
            pair = {name: next(r for r in group if r["round"] == round_number)
                    for name, group in by_variant.items()}
            pairs.append(pair["before"]["wall_seconds"]
                         / pair["after"]["wall_seconds"])
        medians = {
            name: {field: statistics.median(row[field] for row in group)
                   for field in ("wall_seconds", "cpu_seconds", "peak_rss_kib")}
            for name, group in by_variant.items()}
        spread = {}
        for name, group in by_variant.items():
            values = [row["wall_seconds"] for row in group]
            quartiles = statistics.quantiles(values, n=4, method="inclusive")
            spread[name] = (quartiles[2] - quartiles[0]) / statistics.median(values)
        result[case] = {
            "rounds": rounds, "medians": medians,
            "paired_wall_speedups": pairs,
            "paired_median_wall_speedup": statistics.median(pairs),
            "paired_min_wall_speedup": min(pairs),
            "paired_max_wall_speedup": max(pairs),
            "after_faster_pairs": sum(ratio > 1 for ratio in pairs),
            "relative_wall_iqr": spread,
            "order_counts": {
                name: sum(row["order_in_pair"] == 0 for row in group)
                for name, group in by_variant.items()}}
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True,
                        help="Clean frozen ML repository used by both compilers")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--cpu", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    if sys.platform != "linux" or not hasattr(os, "wait4"):
        parser.error("Linux with os.wait4 is required")
    if args.rounds < 3 or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("At least three rounds and a positive timeout are required")
    if args.cpu not in os.sched_getaffinity(0):
        parser.error("Selected CPU is not available to this process")
    repository = args.repository.resolve()
    compilers = {name: path.resolve()
                 for name, path in (("before", args.before), ("after", args.after))}
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    report = work / "applications.json"
    if report.exists():
        parser.error("Report already exists; use a new work directory")
    if git(repository, "status", "--porcelain"):
        parser.error("The benchmark input repository must be clean and frozen")
    source = repository / "tools/mlfmt.ml"
    original_input = repository / "mlc/codegen/codegen_stmt.ml"
    for path in (*compilers.values(), source, original_input):
        if not path.is_file():
            parser.error(f"Missing input: {path}")
    for directory in ("logs", "build", "inputs"):
        (work / directory).mkdir(exist_ok=True)
    formatter_input = work / "inputs/codegen_stmt.ml"
    shutil.copyfile(original_input, formatter_input)
    target = work / "build/formatter-output"
    formatted = work / "build/formatted-output.ml"
    formatter_images = {name: work / f"build/formatter-{name}"
                        for name in compilers}
    os.sched_setaffinity(0, {args.cpu})
    runner = Path(__file__).resolve()
    payload = {
        "schema": "minilang-real-applications-v1",
        "complete": False,
        "host": {"platform": platform.platform(), "python": sys.version,
                 "cpu_affinity": sorted(os.sched_getaffinity(0))},
        "rounds": args.rounds,
        "runner": file_record(runner),
        "runner_arguments": sys.argv[1:],
        "repository": {"path": str(repository),
                       "revision": git(repository, "rev-parse", "HEAD"),
                       "stdlib_tree": git(repository, "rev-parse", "HEAD:std"),
                       "clean": True},
        "compilers": {name: file_record(path) for name, path in compilers.items()},
        "source": file_record(source),
        "original_formatter_input": file_record(original_input),
        "frozen_formatter_input": file_record(formatter_input),
        "method": {
            "pipeline": "monolithic", "incremental_cache": "disabled",
            "target": "linux-x64", "warmups_per_case_and_variant": 1,
            "scope": "Whole fresh processes, including startup and cached file I/O",
            "memory": "Linux wait4 peak RSS in KiB for the single child process",
            "correctness": "Stable emitted image hash within each variant; identical formatted output across every run and variant",
            "order": "Case order and compiler order alternate by round; variant order is offset between cases",
            "outlier_policy": "Retain all successful measured runs; abort on any failure",
            "limitations": "Two tools from the compiler repository, not a game/database workload. Shared-host timing does not establish controlled-hardware performance."},
        "expected_image_hashes": {}, "expected_formatted_hash": None,
        "rows": []}

    def save() -> None:
        report.write_text(json.dumps(payload, indent=2) + "\n")

    def run_case(case: str, name: str, round_number: int, order: int) -> None:
        warmup = round_number == -1
        if case == "compile_formatter":
            artifact = target
            command = [str(compilers[name]), str(source), str(artifact),
                       "-I", str(repository), "--target", "linux-x64",
                       "--no-object-pipeline", "--no-incremental"]
        else:
            artifact = formatted
            command = [str(formatter_images[name]), str(formatter_input),
                       str(artifact), "--indent", "2", "--max-blank", "2"]
        artifact.unlink(missing_ok=True)
        log = work / f"logs/{case}-{name}-{round_number}.log"
        row = measure(command, repository, log, args.timeout)
        output = file_record(artifact)
        if case == "compile_formatter":
            expected = payload["expected_image_hashes"].setdefault(name, output["sha256"])
            if output["sha256"] != expected:
                raise AssertionError(f"Non-deterministic compiler output: {name}")
            if warmup:
                shutil.copyfile(artifact, formatter_images[name])
                formatter_images[name].chmod(0o755)
        else:
            if payload["expected_formatted_hash"] is None:
                payload["expected_formatted_hash"] = output["sha256"]
            if output["sha256"] != payload["expected_formatted_hash"]:
                raise AssertionError(f"Formatter output differs: {name}")
            if output["bytes"] == 0:
                raise AssertionError("Formatter produced an empty file")
        row.update(case=case, variant=name, round=round_number, warmup=warmup,
                   order_in_pair=order, artifact=output,
                   output_sha256=digest(log), verified=True)
        payload["rows"].append(row)
        save()
        print(json.dumps({key: row[key] for key in
                          ("case", "variant", "round", "wall_seconds",
                           "cpu_seconds", "peak_rss_kib", "verified")}), flush=True)

    save()
    # Generate both immutable formatter executables before any formatter run.
    for case in ("compile_formatter", "format_compiler_source"):
        for order, name in enumerate(("before", "after")):
            run_case(case, name, -1, order)
    for round_number in range(args.rounds):
        cases = ("compile_formatter", "format_compiler_source")
        if round_number % 2:
            cases = tuple(reversed(cases))
        for case in cases:
            offset = 0 if case == "compile_formatter" else 1
            names = ("before", "after") if (round_number + offset) % 2 == 0 else ("after", "before")
            for order, name in enumerate(names):
                run_case(case, name, round_number, order)
    for name, path in compilers.items():
        if digest(path) != payload["compilers"][name]["sha256"]:
            raise RuntimeError("Compiler changed during experiment")
        if digest(formatter_images[name]) != payload["expected_image_hashes"][name]:
            raise RuntimeError("Formatter executable changed during experiment")
    for path, key in ((source, "source"), (original_input, "original_formatter_input"),
                      (formatter_input, "frozen_formatter_input")):
        if digest(path) != payload[key]["sha256"]:
            raise RuntimeError("Input changed during experiment")
    if git(repository, "status", "--porcelain"):
        raise RuntimeError("Benchmark input repository changed during experiment")
    if git(repository, "rev-parse", "HEAD") != payload["repository"]["revision"]:
        raise RuntimeError("Benchmark input revision changed during experiment")
    if digest(runner) != payload["runner"]["sha256"]:
        raise RuntimeError("Benchmark runner changed during experiment")
    payload["summary"] = summarize(payload["rows"], args.rounds)
    payload["formatter_images"] = {name: file_record(path) for name, path in formatter_images.items()}
    payload["formatted_output"] = file_record(formatted)
    payload["complete"] = True
    save()
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()
