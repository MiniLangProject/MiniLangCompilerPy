# Float-normalizer probe: evidence and reproduction

Read [the report](../../performance_float_probe.md) for the measured result,
semantic proof, discarded experiment and platform limits.

## Source boundary and evidence

| Compiler | Before: completed Phase 8 | After: measured source |
| --- | --- | --- |
| MiniLangCompilerPy | [`6bdcab1eaf91c117fc5a5295ed4345c81d78509e`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/6bdcab1eaf91c117fc5a5295ed4345c81d78509e) | [`1da8b8bced4ca7f356b57c4c57e656b11e35e359`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/1da8b8bced4ca7f356b57c4c57e656b11e35e359) |
| MiniLangCompilerML | [`c92a678308d408c4f566f007c8ab16fcb5298ca2`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/c92a678308d408c4f566f007c8ab16fcb5298ca2) | [`0c0726f272a157cc13a7b82d7b076799cd60bfb0`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/0c0726f272a157cc13a7b82d7b076799cd60bfb0) |

| Path | Contents |
| --- | --- |
| `primary/` | Fifteen-case independent confirmation, hashes, checksums and all timings |
| `float_comparison/` | Separate before/after/C/C++ comparison, fresh references, exact ablation and untimed GC observations |
| `profiles/` | Current Phase-8 baseline image/map identities and ranges, 96 original-cadence processes, raw samples and summaries |
| `experiments/scratch_zero/` | Rejected six-variant zeroing experiment, 84 timings and correctness data |
| `experiments/dead_compare/` | Separate two-variant candidate-selection pilot, 44 timings and correctness data |
| `application/` | Real compiler/formatter workloads, every process record and verified artifact hashes |
| `mxcsr/` | Targeted exact-bit/status driver, bridge and results |
| `suite/` | Original benchmark sources, drivers, checksum oracles and fixed calibration |
| `source_revisions.json`, `validation_summary.json` | Exact source identities and completed validation scope |

Requirements: Linux x86-64, Python 3.11+, Git, Bash, GCC/G++, and `taskset`.
Sampling additionally needs `libatomic.so.1` and permission for per-process Linux
software perf events. Hardware PMU events are not required. Start in the Python
repository containing this report, with the native repository beside it. Choose
a new reproduction directory. Worktrees are detached; no branch is created.

## Build the frozen source pairs

```bash
set -euo pipefail
MINILANG_PY_REPO="$PWD"
MINILANG_ML_REPO="$(cd ../MiniLangCompilerML && pwd)"
BENCH_EVIDENCE="$MINILANG_PY_REPO/docs/benchmarks/float_probe"
BENCH_RUN="$MINILANG_PY_REPO/build/float-probe-reproduction"
BENCH_CPU="$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')"
BENCH_BEFORE_PY="6bdcab1eaf91c117fc5a5295ed4345c81d78509e"
BENCH_BEFORE_ML="c92a678308d408c4f566f007c8ab16fcb5298ca2"
BENCH_AFTER_PY="1da8b8bced4ca7f356b57c4c57e656b11e35e359"
BENCH_AFTER_ML="0c0726f272a157cc13a7b82d7b076799cd60bfb0"
mkdir -p "$BENCH_RUN"
git -C "$MINILANG_PY_REPO" fetch origin "$BENCH_BEFORE_PY" "$BENCH_AFTER_PY"
git -C "$MINILANG_ML_REPO" fetch origin "$BENCH_BEFORE_ML" "$BENCH_AFTER_ML"
git -C "$MINILANG_PY_REPO" worktree add --detach "$BENCH_RUN/before-py" "$BENCH_BEFORE_PY"
git -C "$MINILANG_ML_REPO" worktree add --detach "$BENCH_RUN/before-ml" "$BENCH_BEFORE_ML"
git -C "$MINILANG_PY_REPO" worktree add --detach "$BENCH_RUN/after-py" "$BENCH_AFTER_PY"
git -C "$MINILANG_ML_REPO" worktree add --detach "$BENCH_RUN/after-ml" "$BENCH_AFTER_ML"
sh "$BENCH_RUN/before-ml/build.sh" --compiler "$BENCH_RUN/before-py/mlc_win64.py" \
  --output "$BENCH_RUN/before-compiler"
sh "$BENCH_RUN/after-ml/build.sh" --compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --output "$BENCH_RUN/after-compiler"
sh "$BENCH_RUN/after-ml/build.sh" --compiler "$BENCH_RUN/after-compiler" \
  --output "$BENCH_RUN/after-selfhost"
cmp "$BENCH_RUN/after-compiler" "$BENCH_RUN/after-selfhost"
```

The recorded experiment reused the verified Phase-8 baseline artifact. The
commands above rebuild that baseline for an independent reproduction; they do
not claim that a fresh baseline compiler build was part of the recorded timing.

## Correctness before timing

```bash
(
  cd "$BENCH_RUN/after-py"
  python3 -m unittest discover -s tests -p 'test_*.py'
  python3 tests/check_codegen_structure.py mlc_win64.py
  python3 tests/check_codegen_structure.py "$BENCH_RUN/after-compiler"
)
bash "$BENCH_RUN/after-ml/scripts/run_native_linux_regressions.sh" "$BENCH_RUN/after-compiler"
python3 "$BENCH_RUN/after-py/tests/check_proven_check_elision.py" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --native-compiler "$BENCH_RUN/after-compiler" \
  --baseline-compiler "$BENCH_RUN/before-compiler" --target linux-x64 \
  --output "$BENCH_RUN/linux-matrix.json"
python3 "$MINILANG_PY_REPO/docs/benchmarks/float_consumers/check_consumer_mxcsr.py" \
  --before "$BENCH_RUN/before-compiler" --after "$BENCH_RUN/after-compiler" \
  --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/consumer-mxcsr"
```

The Linux matrix executes the output. Windows/MinUX and concurrent-GC matrix
entries in `validation_summary.json` are compile-only. Their exact fixture lists
remain in the preceding [consumer reproduction instructions](../float_consumers/README.md#reproduce-semantics-and-compiler-parity);
use the source pairs and variables above when repeating those commands.

The targeted helper adds exact numeric-payload checks and verifies the new
normalizer bytes. Its input files default to the bundled `mxcsr/` directory:

```bash
python3 "$BENCH_EVIDENCE/check_float_probe_mxcsr.py" \
  --before "$BENCH_RUN/before-compiler" --after "$BENCH_RUN/after-compiler" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/probe-mxcsr"
```

Both drivers use masked exceptions. The targeted driver records 576
before/after pairs and the same 576 Python-built observations; these are 1,728
rows, not 1,728 independent pairs. It captures MXCSR before inspecting numeric
payloads, then restores the initial control state before printing.

## Prepare the fixed numeric workloads and inverse ablation

```bash
mkdir -p "$BENCH_RUN/suite/build"
cp -R "$BENCH_EVIDENCE/suite/." "$BENCH_RUN/suite/"
gcc -O3 -std=c11 -shared -fPIC "$BENCH_RUN/suite/drivers/observe.c" \
  -o "$BENCH_RUN/suite/build/libbench_observe.so"
python3 "$BENCH_EVIDENCE/restore_probe_compare_compiler.py" \
  --compiler-root "$BENCH_RUN/after-py" --output "$BENCH_RUN/restore-compare.py"
for action in build validate; do
  python3 "$BENCH_EVIDENCE/compare_compilers.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/primary" \
    --cpu "$BENCH_CPU" --rounds 11
done
python3 "$BENCH_EVIDENCE/diagnose_float_dependencies.py" prepare \
  --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
  --after "$BENCH_RUN/after-compiler" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --disabled-compiler "$BENCH_RUN/restore-compare.py" \
  --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/float-comparison" \
  --cpu "$BENCH_CPU" --rounds 11
```

The generated inverse-hook wrapper appends the original comparison to the new
normalizer. Preparation requires byte-exact baseline reconstruction and current
Python/native image parity. Fresh strict C/C++ references use the original
sources and separate translation units; no LTO or fast-math is enabled.

## Sampling is separate from timing

Build unchanged baseline images and matching label maps, then sample complete
processes with sixteen calls and sixteen processes for each of three periods.

```bash
for case in float_recurrence mandelbrot; do
  mkdir -p "$BENCH_RUN/profile-images/$case"
  python3 "$BENCH_RUN/before-py/mlc_win64.py" \
    "$BENCH_RUN/suite/inputs/$case.ml" "$BENCH_RUN/profile-images/$case/python" \
    --target linux-x64 --no-object-pipeline --no-incremental -I "$BENCH_RUN/after-py" \
    --asm --asm-out "$BENCH_RUN/profile-images/$case/python.asm" \
    --dump-labels "$BENCH_RUN/profile-images/$case/python.labels"
  "$BENCH_RUN/before-compiler" \
    "$BENCH_RUN/suite/inputs/$case.ml" "$BENCH_RUN/profile-images/$case/native" \
    --target linux-x64 --no-object-pipeline --no-incremental -I "$BENCH_RUN/after-py"
  chmod +x "$BENCH_RUN/profile-images/$case/native" "$BENCH_RUN/profile-images/$case/python"
  cmp "$BENCH_RUN/profile-images/$case/native" "$BENCH_RUN/profile-images/$case/python"
done
python3 "$BENCH_EVIDENCE/profile_float_costs.py" \
  --images "$BENCH_RUN/profile-images" --suite "$BENCH_RUN/suite" \
  --output "$BENCH_RUN/baseline-profile" --cpu "$BENCH_CPU" \
  --reps 16 --processes-per-period 16
python3 "$BENCH_EVIDENCE/summarize_float_profile.py" \
  --profiles "$BENCH_RUN/baseline-profile" --images "$BENCH_RUN/profile-images"
```

This helper verifies the complete original 32-byte normalizers and Phase-8 rejoin
stubs. It is for the frozen baseline, not an interchangeable profiler for the
new 28-byte code. IP shares cannot establish exclusive instruction costs or
causal runtime callers.

## Run final comparisons without competing project jobs

Complete compilation, tests and sampling before these commands. Retain the
preset rounds, every warmup and every measured observation.

```bash
for action in measure summarize; do
  python3 "$BENCH_EVIDENCE/compare_compilers.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/primary" \
    --cpu "$BENCH_CPU" --rounds 11
done
for action in measure summarize; do
  python3 "$BENCH_EVIDENCE/diagnose_float_dependencies.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
    --disabled-compiler "$BENCH_RUN/restore-compare.py" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/float-comparison" \
    --cpu "$BENCH_CPU" --rounds 11
done
python3 "$BENCH_EVIDENCE/compare_applications.py" \
  --before "$BENCH_RUN/before-compiler" --after "$BENCH_RUN/after-compiler" \
  --repository "$BENCH_RUN/before-ml" --work "$BENCH_RUN/applications" \
  --rounds 7 --cpu "$BENCH_CPU" --timeout 300
```

Application work uses the same clean baseline ML checkout for both variants.
`applications.json` preserves four warmups and 28 measured process records, input
and output hashes, paired wall-time ratios, CPU time and Linux peak RSS. The
real formatter's output must match exactly. Whole-process application times
cannot be directly substituted for internal numeric time per call.

## Reproduce the two separate exploratory experiments

```bash
for action in prepare measure summarize; do
  python3 "$BENCH_EVIDENCE/ablate_scratch_dependencies.py" "$action" \
    --suite "$BENCH_RUN/suite" --compiler-root "$BENCH_RUN/before-py" \
    --baseline "$BENCH_RUN/before-compiler" --stdlib "$BENCH_RUN/after-py" \
    --work "$BENCH_RUN/scratch-zero-pilot" --cpu "$BENCH_CPU" --rounds 7
done
for action in prepare measure summarize; do
  python3 "$BENCH_EVIDENCE/ablate_dead_compare.py" "$action" \
    --suite "$BENCH_RUN/suite" --compiler-root "$BENCH_RUN/before-py" \
    --baseline "$BENCH_RUN/before-compiler" --stdlib "$BENCH_RUN/after-py" \
    --work "$BENCH_RUN/dead-compare-pilot" --cpu "$BENCH_CPU" --rounds 11
done
```

These pilots remain separate from final confirmation. Their published helpers
have portable imports/default paths adapted after the recorded experiments;
recorded original-helper hashes are retained as provenance, and fresh runs write
their own helper hashes. Algorithm variants, scheduling, checksums, seeds and
round counts are unchanged. Published summaries retain every preselected variant
and observation. A failed or unexpectedly slow run is not an invitation to remove a
row or rerun until a preferred result appears.
