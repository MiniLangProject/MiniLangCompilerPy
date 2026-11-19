#!/usr/bin/env python3
"""One preset four-way ablation of Phase8 numeric consumers and float literals.

All four variants are semantics-preserving compiler choices. Disable both new
hooks to reproduce the complete Phase7 executable exactly. Seven balanced
rounds, original workload/repeats/seeds and checksums distinguish component
contributions. This diagnostic series is separate from final primary/C timings.
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
from pathlib import Path
import random
import statistics
import sys

from compare_compilers import (MASK, SEED, compiler_command, invoke, load_module,
                               run_binary, save, sha, text_size)

CASES = ("float_recurrence", "mandelbrot")
VARIANTS = ("before", "normalization_only", "literal_only", "after")


def compiler_sources(root):
    return {str(path.relative_to(root)): sha(path) for path in
            [root / "mlc_win64.py", *sorted((root / "mlc").rglob("*.py"))]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "measure", "summarize"))
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--python-compiler", type=Path, required=True)
    parser.add_argument("--stdlib", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--cpu", type=int, default=2)
    parser.add_argument("--rounds", type=int, default=7)
    args = parser.parse_args()
    for field in ("suite", "before", "python_compiler", "stdlib", "work"):
        setattr(args, field, getattr(args, field).resolve())
    args.work.mkdir(parents=True, exist_ok=True)
    assert args.cpu in os.sched_getaffinity(0) and args.rounds >= 3
    calibration = json.loads((args.suite / "results/calibration.json").read_text())

    if args.action == "prepare":
        shared = ("import sys\n" + f"sys.path.insert(0, {str(args.python_compiler.parent)!r})\n"
                  "from mlc.codegen import Codegen\nfrom mlc.compiler import main\n")
        no_consumer = "Codegen._opt_float_loop_double_consumer = lambda self, other: False\n"
        no_literal = "Codegen._opt_emit_float_loop_literal = lambda self, expr, target: False\n"
        compilers = {"before": args.before, "after": args.python_compiler}
        for variant, hooks in (("normalization_only", no_literal), ("literal_only", no_consumer),
                               ("disabled_both", no_consumer + no_literal)):
            path = args.work / (variant + "_compiler.py")
            path.write_text(shared + hooks + "raise SystemExit(main(sys.argv))\n")
            compilers[variant] = path
        oracle = load_module("phase8_ablation_oracle", args.suite / "verification/other_reference.py")
        builds, checks = [], []
        for case in CASES:
            folder = args.work / case
            folder.mkdir(exist_ok=True)
            source = args.suite / "inputs" / (case + ".ml")
            for variant, compiler in compilers.items():
                binary = folder / variant
                command = [*compiler_command(compiler), str(source), str(binary),
                           "--target", "linux-x64", "--no-object-pipeline", "--no-incremental",
                           "-I", str(args.stdlib), "--asm", "--asm-out", str(folder / (variant + ".asm")),
                           "--dump-labels", str(folder / (variant + ".labels"))]
                invoke(command, cpu=4 if 4 in os.sched_getaffinity(0) else min(os.sched_getaffinity(0)))
                binary.chmod(binary.stat().st_mode | 0o111)
                builds.append(dict(case=case, variant=variant, binary_sha256=sha(binary),
                                   source_sha256=sha(source), executable_segment_bytes=text_size(binary),
                                   command=command))
            assert sha(folder / "before") == sha(folder / "disabled_both"), "Disabled hooks must reproduce Phase7"
            cfg = calibration[case]
            workloads = [(n, seed, 8) for n in (1, 17, 67) for seed in (0, SEED, MASK)]
            workloads.append((cfg["n"], SEED, cfg["configs"]["minilang"]["reps"]))
            for n, seed, reps in workloads:
                expected = (sum(oracle.expected_checksum(case, n, (seed + r) & MASK) for r in range(8))
                            * (reps // 8)) & MASK
                warmup = oracle.expected_checksum(case, n, (seed + 65536) & MASK)
                for variant in VARIANTS:
                    observed = run_binary(folder / variant, n, reps, seed, args)
                    assert (observed["checksum"], observed["warmup_checksum"]) == (expected, warmup)
                    checks.append(dict(case=case, variant=variant, correct=True, **observed))
            print("PREPARED ablation", case, flush=True)
        save(args.work / "preparation.json", builds)
        save(args.work / "correctness.json", checks)
        save(args.work / "method.json", dict(method=__doc__, rounds=args.rounds, variants=VARIANTS,
            calibration_sha256=sha(args.suite / "results/calibration.json"),
            before_compiler_sha256=sha(args.before), compiler_source_sha256=compiler_sources(args.python_compiler.parent),
            helper_sha256=sha(Path(__file__)), cpu=args.cpu,
            disabled_both_exact_baseline=True, original_repeats_and_seed_cycle=True,
            code_cache_disabled=True, no_outlier_removal=True))

    if args.action == "measure":
        method = json.loads((args.work / "method.json").read_text())
        assert method["rounds"] == args.rounds
        assert method["compiler_source_sha256"] == compiler_sources(args.python_compiler.parent)
        assert method["calibration_sha256"] == sha(args.suite / "results/calibration.json")
        for row in json.loads((args.work / "preparation.json").read_text()):
            assert sha(args.work / row["case"] / row["variant"]) == row["binary_sha256"]
        rng = random.Random(20261119)
        with (args.work / "measurements.jsonl").open("w") as output:
            for number in range(args.rounds):
                cases = list(CASES)
                rng.shuffle(cases)
                shift = (number // 2) % len(VARIANTS)
                variants = list(VARIANTS[shift:] + VARIANTS[:shift])
                if number % 2:
                    variants.reverse()
                for case in cases:
                    cfg = calibration[case]
                    settings = cfg["configs"]["minilang"]
                    expected = settings["cycle_checksum"] * (settings["reps"] // 8) & MASK
                    for position, variant in enumerate(variants):
                        observed = run_binary(args.work / case / variant, cfg["n"], settings["reps"], SEED, args)
                        assert (observed["checksum"], observed["warmup_checksum"]) == (expected, settings["warmup_checksum"])
                        row = dict(case=case, variant=variant, round=number, position=position,
                                   correct=True, **observed)
                        output.write(json.dumps(row) + "\n")
                        output.flush()
                print("MEASURED ablation round", number + 1, "/", args.rounds, flush=True)

    if args.action == "summarize":
        rows = [json.loads(line) for line in (args.work / "measurements.jsonl").read_text().splitlines()]
        assert len(rows) == len(CASES) * len(VARIANTS) * args.rounds
        assert len({(row["case"], row["variant"], row["round"]) for row in rows}) == len(rows)
        summary = []
        for case in CASES:
            values = {variant: [row["ns_per_call"] for row in sorted(rows, key=lambda r: r["round"])
                                if row["case"] == case and row["variant"] == variant] for variant in VARIANTS}
            assert all(len(series) == args.rounds for series in values.values())
            comparisons = {}
            for left, right in itertools.combinations(VARIANTS, 2):
                ratios = [a / b for a, b in zip(values[left], values[right])]
                left_first = sum(next(row["position"] for row in rows if row["case"] == case and row["round"] == n and row["variant"] == left)
                                 < next(row["position"] for row in rows if row["case"] == case and row["round"] == n and row["variant"] == right)
                                 for n in range(args.rounds))
                assert left_first in (args.rounds // 2, (args.rounds + 1) // 2)
                comparisons[left + "/" + right] = dict(median_ratio=statistics.median(ratios),
                    ratios_above_one=sum(r > 1 for r in ratios), min_ratio=min(ratios), max_ratio=max(ratios),
                    left_first_pairs=left_first)
            row = dict(case=case, rounds=args.rounds,
                       median_ms={k: statistics.median(v) / 1e6 for k, v in values.items()},
                       relative_iqr={k: (statistics.quantiles(v, n=4)[2] - statistics.quantiles(v, n=4)[0]) /
                                     statistics.median(v) for k, v in values.items()}, comparisons=comparisons)
            summary.append(row)
            print(json.dumps(row), flush=True)
        save(args.work / "summary.json", summary)


if __name__ == "__main__":
    main()
