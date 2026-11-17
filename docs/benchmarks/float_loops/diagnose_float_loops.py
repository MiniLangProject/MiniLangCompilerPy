#!/usr/bin/env python3
"""Measure guarded float loops against the preceding compiler and original C/C++ kernels.

Uses compare_compilers.py's subprocess, checksum and ELF helpers. A disabled-loop control must reproduce the frozen baseline, including its frame layouts. All builds disable the object cache. Original sources, inputs,
repeat counts, warmups and checksum oracles are retained.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import random
import re
import statistics
import sys
import time

for helper_root in (Path(__file__).resolve().parent, Path(__file__).resolve().parents[1],
                    Path(__file__).resolve().parents[1] / "numeric_flow"):
    if (helper_root / "compare_compilers.py").is_file():
        sys.path.insert(0, str(helper_root))
        break
from compare_compilers import (MASK, SEED, compiler_command, invoke, load_module,
                               run_binary, save, sha, text_size)

CASES = ("float_recurrence", "mandelbrot")
VARIANTS = ("before", "after", "c_o3", "cpp_o3")
ML_VARIANTS = ("before", "after")
GC_FIELDS = ("checksum before_gc after_gc before_used after_used before_count "
             "after_count before_free after_free before_tlab after_tlab "
             "threshold_all threshold_small adaptive post_live post_reclaimed "
             "post_count post_used post_free").split()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "measure", "summarize"))
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--python-compiler", type=Path, required=True)
    parser.add_argument("--stdlib", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--cpu", type=int, default=2)
    parser.add_argument("--rounds", type=int, default=11)
    args = parser.parse_args()
    for field in ("suite", "before", "after", "python_compiler", "stdlib", "work"):
        setattr(args, field, getattr(args, field).resolve())
    args.work.mkdir(parents=True, exist_ok=True)
    calibration = json.loads((args.suite / "results/calibration.json").read_text())

    if args.action == "prepare":
        wrappers = {}
        shared = ("import sys\n"
                  f"sys.path.insert(0, {str(args.python_compiler.parent)!r})\n"
                  "from mlc.codegen import Codegen\n"
                  "from mlc.compiler import main\n")
        loop_disabled = args.work / "loop_disabled_compiler.py"
        loop_disabled.write_text(shared +
            "Codegen._opt_float_loop_arena_bytes = lambda self, fn: 0\n"
            "Codegen._opt_emit_float_loop = lambda self, stmt: False\n"
            "raise SystemExit(main(sys.argv))\n", encoding="utf-8")
        oracle = load_module("phase5_other_reference", args.suite / "verification/other_reference.py")
        preparation, correctness, gc_rows = [], [], []
        compilers = {"before": args.before, "after": args.after,
                     "python": args.python_compiler, "loop_disabled": loop_disabled}
        for case in CASES:
            folder = args.work / case
            folder.mkdir(exist_ok=True)
            source = args.suite / "inputs" / (case + ".ml")
            if not source.exists():
                source = args.suite / "build" / case / (case + ".ml")
            for variant, compiler in compilers.items():
                binary, listing = folder / variant, folder / (variant + ".asm")
                symbols = folder / (variant + ".labels")
                command = [*compiler_command(compiler), str(source), str(binary),
                           "--target", "linux-x64", "--no-object-pipeline", "-I",
                           str(args.stdlib), "--asm", "--asm-out", str(listing),
                           "--dump-labels", str(symbols)]
                invoke(command, cpu=4 if 4 in os.sched_getaffinity(0) else min(os.sched_getaffinity(0)), timeout=180)
                binary.chmod(binary.stat().st_mode | 0o111)
                labels = None
                if symbols.exists():
                    labels_with_offsets = [(name, int(offset)) for name, offset in re.findall(
                        r"(?m)^\[label\] ([^ ]+) (\d+)\s*$", symbols.read_text(encoding="utf-8"))]
                    starts = [offset for name, offset in labels_with_offsets if name == "fn_user_bench"]
                    if len(starts) != 1:
                        raise AssertionError("bench function missing from label dump")
                    start = starts[0]
                    end = min((offset for name, offset in labels_with_offsets
                               if name.startswith("fn_user_") and offset > start), default=2**64)
                    labels = [name for name, offset in labels_with_offsets if start <= offset < end]
                elif compiler.suffix == ".py":
                    raise AssertionError("Python label dump missing")
                # The native monolithic ELF writer currently emits raw-byte
                # listings without a label sidecar. Its exact byte equality
                # with Python is checked below; do not report missing labels
                # as zero optimized sites.
                row = dict(case=case, variant=variant, command=command,
                           sha256=sha(binary), source_sha256=sha(source),
                           executable_segment_bytes=text_size(binary),
                           bench_labels=None if labels is None else [label for label in labels if
                               "numeric_float_fast" in label or "float_parent" in label or
                               "child_box" in label or "float_tree" in label or "float_loop" in label])
                preparation.append(row)
            if sha(folder / "after") != sha(folder / "python"):
                raise AssertionError(f"Python/native image mismatch: {case}")
            if sha(folder / "before") != sha(folder / "loop_disabled"):
                raise AssertionError(f"Disabled loop hooks does not reproduce frozen baseline: {case}")

            # Zero is outside the timed driver's allowed input and is covered
            # separately by the compiler's semantic regression fixtures.
            for n in (1, 17, 67):
                for seed in (0, SEED, MASK):
                    checksum = sum(oracle.expected_checksum(case, n, (seed + r) & MASK)
                                   for r in range(8)) & MASK
                    warmup = oracle.expected_checksum(case, n, (seed + 65536) & MASK)
                    for variant in ML_VARIANTS:
                        observed = run_binary(folder / variant, n, 8, seed, args)
                        if (observed["checksum"], observed["warmup_checksum"]) != (checksum, warmup):
                            raise AssertionError((case, variant, observed, checksum, warmup))
                        correctness.append(dict(case=case, variant=variant, correct=True, **observed))

            gc_source = args.suite / "gc" / (case + "_gc.ml")
            if not gc_source.exists():
                gc_source = args.suite / "build/supplemental" / (case + "_gc.ml")
            for variant in ML_VARIANTS:
                binary = folder / (variant + "_gc")
                command = [*compiler_command(compilers[variant]), str(gc_source), str(binary),
                           "--target", "linux-x64", "--no-object-pipeline", "-I", str(args.stdlib)]
                invoke(command, cpu=4 if 4 in os.sched_getaffinity(0) else min(os.sched_getaffinity(0)))
                binary.chmod(binary.stat().st_mode | 0o111)
                sizes = (1, 10, 100, 1000) if case == "float_recurrence" else (1, 3, 5, 17)
                workloads = [(n, 1) for n in sizes] + [(calibration[case]["n"], 8)]
                for n, reps in workloads:
                    stdout = invoke([binary, n, reps, SEED], cpu=args.cpu, timeout=90)
                    match = re.search(r"^GC ((?:-?\d+ ?)+)$", stdout, re.M)
                    if not match:
                        raise AssertionError(stdout)
                    values = list(map(int, match[1].split()))
                    if len(values) != len(GC_FIELDS):
                        raise AssertionError(values)
                    observed = dict(zip(GC_FIELDS, values))
                    observed["collections"] = observed["after_gc"] - observed["before_gc"]
                    observed["frontier_growth"] = observed["after_used"] - observed["before_used"]
                    observed["block_delta"] = observed["after_count"] - observed["before_count"]
                    gc_rows.append(dict(case=case, variant=variant, n=n, reps=reps, seed=SEED,
                                        binary_sha256=sha(binary), command=command, stdout=stdout, **observed))
            print("PREPARED", case, flush=True)
        for row in gc_rows:
            matches = [r for r in gc_rows if r["case"] == row["case"] and r["n"] == row["n"]
                       and r["reps"] == row["reps"]]
            if len({r["checksum"] for r in matches}) != 1:
                raise AssertionError("GC probe changed benchmark result")
        save(args.work / "preparation.json", preparation)
        save(args.work / "correctness.json", correctness)
        save(args.work / "gc_diagnostics.json", gc_rows)
        save(args.work / "environment.json", dict(
            date_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), cpu=args.cpu,
            before_sha256=sha(args.before), after_sha256=sha(args.after), rounds=args.rounds,
            calibration_sha256=sha(args.suite / "results/calibration.json"),
            method="Original sources; previous and current MiniLang plus original GCC/G++ -O3 images. "
                   "Original calibrated repeats per language; internal CLOCK_MONOTONIC, untimed full "
                   "warmup, balanced eight-seed cycle. GC diagnostics are separate untimed programs. "
                   "Disabled loop hooks reproduce the frozen baseline; no object cache."))

    if args.action == "measure":
        randomizer = random.Random(20261119)
        with (args.work / "measurements.jsonl").open("w", encoding="utf-8") as handle:
            for round_number in range(args.rounds):
                case_order = list(CASES)
                randomizer.shuffle(case_order)
                for case in case_order:
                    variants = list(VARIANTS)
                    # Pair each rotation with its reverse: every variant visits all
                    # four positions, and every pair runs in both orders 5/6 times.
                    shift = (round_number // 2) % len(variants)
                    variants = variants[shift:] + variants[:shift]
                    if round_number % 2:
                        variants.reverse()
                    for position, variant in enumerate(variants):
                        config = calibration[case]["configs"][variant if variant in ("c_o3", "cpp_o3") else "minilang"]
                        binary = (args.suite / "build" / case / variant if variant in ("c_o3", "cpp_o3")
                                  else args.work / case / variant)
                        observed = run_binary(binary, calibration[case]["n"], config["reps"], SEED, args)
                        expected = (config["cycle_checksum"] * (config["reps"] // 8)) & MASK
                        if (observed["checksum"], observed["warmup_checksum"]) != (expected, config["warmup_checksum"]):
                            raise AssertionError((case, variant, observed))
                        row = dict(case=case, variant=variant, round=round_number, position=position,
                                   binary_sha256=sha(binary), correct=True, **observed)
                        handle.write(json.dumps(row) + "\n")
                        handle.flush()
                print("MEASURED float round", round_number + 1, "/", args.rounds, flush=True)

    if args.action == "summarize":
        rows = [json.loads(line) for line in (args.work / "measurements.jsonl").read_text().splitlines()]
        summary = []
        for case in CASES:
            values = {v: [row["ns_per_call"] for row in rows if row["case"] == case and row["variant"] == v]
                      for v in VARIANTS}
            if any(len(v) != args.rounds for v in values.values()):
                raise AssertionError("incomplete float measurement set")
            comparisons = {}
            for left, right in (("before", "after"), ("after", "c_o3"), ("after", "cpp_o3")):
                ratios = [a / b for a, b in zip(values[left], values[right])]
                comparisons[left + "/" + right] = dict(median_ratio=statistics.median(ratios),
                                                       ratios_above_one=sum(r > 1 for r in ratios),
                                                       min_ratio=min(ratios), max_ratio=max(ratios))
            row = dict(case=case, median_ms={k: statistics.median(v) / 1e6 for k, v in values.items()},
                       relative_iqr={k: (statistics.quantiles(v, n=4)[2] - statistics.quantiles(v, n=4)[0]) /
                                     statistics.median(v) for k, v in values.items()}, comparisons=comparisons)
            summary.append(row)
            print(json.dumps(row), flush=True)
        save(args.work / "summary.json", summary)


if __name__ == "__main__":
    main()
