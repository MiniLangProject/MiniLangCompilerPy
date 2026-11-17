# Nested float loops: benchmark evidence

This sixth round compares nested numeric-loop lowering and compound-loop
reentry against the completed fifth round. See
[performance_float_nested.md](../../performance_float_nested.md) for the design,
results and limitations. The original fifteen sources, fixed-input drivers,
calibration and checksum oracles come from the unchanged
[numeric-flow suite](../numeric_flow/suite/).

## Exact source boundary

| Compiler | Before: Phase 5 | After: measured Phase 6 source |
|---|---|---|
| Python | [`b1f8cc0ef85831895724ec40665a07ec74d7740b`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/b1f8cc0ef85831895724ec40665a07ec74d7740b) | [`173979dcf01bebe278b364ce9c4a673b18cac49f`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/173979dcf01bebe278b364ce9c4a673b18cac49f) |
| MiniLang | [`b15ec01c44ebba4b27d4c079604c4554caf000ed`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/b15ec01c44ebba4b27d4c079604c4554caf000ed) | [`11dab16a271267bed9f5b6343bd70a69bcde3990`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/11dab16a271267bed9f5b6343bd70a69bcde3990) |

The after-source commits precede this report and its evidence. Use the report
revision's helpers and suite, and build compilers from the four detached source
worktrees below. Both compilers compile benchmark inputs against the same
after-source standard-library paths. This avoids unrelated source-path or
library differences in the before/after images.

## Published files

| File | Contents |
|---|---|
| `primary/measurements.jsonl` | 330 runs: 15 cases, 2 variants, 11 rounds |
| `primary/summary.json` | Per-call medians, IQR, paired ratios and byte controls |
| `float_comparison/measurements.jsonl` | 88 runs: 2 cases, 4 variants, 11 rounds |
| `float_comparison/summary.json` | Separate before/after and C/C++ comparisons |
| `float_comparison/gc_diagnostics.json` | 20 separate GC/allocation observations |
| `float_comparison/code_summary.json` | Segment sizes, static sites and ablation controls |
| `validation_summary.json` | Correctness, parity and execution boundaries |
| `compare_compilers.py` | Primary build, oracle validation and timing runner |
| `diagnose_float_nested.py` | Phase 6 ablation, GC probes and four-variant runner |

Timed variants are `before`, `after`, `c_o3` and `cpp_o3`. Preparation also
builds Python after and `nested_disabled` controls. The latter restores direct
function-body discovery and rejects compound conditions; it must reproduce
Phase 5 bytes while preserving the earlier recurrence optimization. Neither
control is another timed variant. Benchmark builds explicitly disable the
object pipeline. The semantic matrix separately compares native MLO output.

## Measurement protocol

Each process performs a full untimed warmup and the original eight-seed cycle
starting at 12345. Inputs and language-specific repeat counts come from the
original calibration. Measured and warmup checksums must match. Internal
`CLOCK_MONOTONIC` timing excludes compilation, startup and printing; elapsed
time is divided by the number of kernel calls.

Primary rounds shuffle cases and alternate before/after order. The separate
schedule uses `shift = (round // 2) % 4` and reverses odd rounds. Every pair
runs in each relative order five or six times across eleven rounds. Individual
positions occur two to four times. Paired ratios are medians of within-round
ratios and need not equal ratios of separately reported time medians. Relative
IQR is the interquartile range divided by the median.

Recorded timings used CPU 2 on a shared Linux x86-64 VM, without another
compiler or benchmark job from this evaluation running concurrently. Host load
and frequency were uncontrolled. Fourteen unchanged primary images, including
recurrence, are timing controls. GC probes are separate programs; after a
collection, heap/block deltas are net changes rather than cumulative allocations.
Static code sites include fallback paths and are not dynamic allocation counts.

The recorded C/C++ images use GCC/G++ 14.2.0, strict floating-point options,
separate translation units and no LTO. A fresh reproduction may use another
host or toolchain; record its versions and expect different absolute results.

## Reproduce the source builds

Requirements: Linux x86-64, Python 3, Git, Bash, GCC/G++, and `taskset`. Start in
a checkout of `MiniLangCompilerPy` containing this report, with
`MiniLangCompilerML` beside it. Choose an empty `BENCH_RUN` directory. The
worktrees below are detached and do not create branches.

```bash
set -euo pipefail
MINILANG_PY_REPO="$PWD"
MINILANG_ML_REPO="$(cd ../MiniLangCompilerML && pwd)"
BENCH_EVIDENCE="$MINILANG_PY_REPO/docs/benchmarks/float_nested"
BENCH_ORIGINAL="$MINILANG_PY_REPO/docs/benchmarks/numeric_flow"
BENCH_RUN="$MINILANG_PY_REPO/build/float-nested-reproduction"
BENCH_CPU="$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')"
BENCH_BEFORE_PY="b1f8cc0ef85831895724ec40665a07ec74d7740b"
BENCH_BEFORE_ML="b15ec01c44ebba4b27d4c079604c4554caf000ed"
BENCH_AFTER_PY="173979dcf01bebe278b364ce9c4a673b18cac49f"
BENCH_AFTER_ML="11dab16a271267bed9f5b6343bd70a69bcde3990"
mkdir -p "$BENCH_RUN"

git -C "$MINILANG_PY_REPO" fetch origin "$BENCH_BEFORE_PY" "$BENCH_AFTER_PY"
git -C "$MINILANG_ML_REPO" fetch origin "$BENCH_BEFORE_ML" "$BENCH_AFTER_ML"
git -C "$MINILANG_PY_REPO" worktree add --detach "$BENCH_RUN/before-py" "$BENCH_BEFORE_PY"
git -C "$MINILANG_ML_REPO" worktree add --detach "$BENCH_RUN/before-ml" "$BENCH_BEFORE_ML"
git -C "$MINILANG_PY_REPO" worktree add --detach "$BENCH_RUN/after-py" "$BENCH_AFTER_PY"
git -C "$MINILANG_ML_REPO" worktree add --detach "$BENCH_RUN/after-ml" "$BENCH_AFTER_ML"

sh "$BENCH_RUN/before-ml/build.sh" \
  --compiler "$BENCH_RUN/before-py/mlc_win64.py" \
  --output "$BENCH_RUN/before-compiler"
sh "$BENCH_RUN/after-ml/build.sh" \
  --compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --output "$BENCH_RUN/after-compiler"
sh "$BENCH_RUN/after-ml/build.sh" \
  --compiler "$BENCH_RUN/after-compiler" \
  --output "$BENCH_RUN/after-selfhost"
cmp "$BENCH_RUN/after-compiler" "$BENCH_RUN/after-selfhost"
```

## Reproduce semantics, structure and compiler parity

Finish these checks before starting either timing series. The first matrix
command runs all 36 Linux fixtures and compares runtime output with Phase 5.
The two explicit fixture sets reproduce the recorded 19+19 cross-target and
14 concurrent-GC configurations. Each configuration compares Python, native
monolithic and native MLO images. Windows and MinUX output is compile-only on
this Linux host.

```bash
(
  cd "$BENCH_RUN/after-py"
  python3 -m unittest discover -s tests -p 'test_*.py'
  python3 tests/check_codegen_structure.py mlc_win64.py
)
bash "$BENCH_RUN/after-ml/scripts/run_native_linux_regressions.sh" \
  "$BENCH_RUN/after-compiler"

python3 "$BENCH_RUN/after-py/tests/check_proven_check_elision.py" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --native-compiler "$BENCH_RUN/after-compiler" \
  --baseline-compiler "$BENCH_RUN/before-compiler" --target linux-x64 \
  --output "$BENCH_RUN/linux-matrix.json"

BENCH_CROSS_FIXTURES=(
  numeric_float_loop
  numeric_float_loop_threads
  numeric_float_loop_typeof
  numeric_float_nested
  numeric_float_nested_threads
  numeric_float_nested_typeof
  numeric_float_tree
  numeric_float_tree_tofloat
  numeric_float_tree_typeof
  numeric_nullable_boxing
  numeric_nullable_tofloat
  numeric_nullable_typeof
  numeric_typeflow_boxing
  numeric_typeflow_tofloat
  numeric_typeflow_typeof
  proven_check_elision
  proven_check_elision_typeof
  type_flow_context
  type_flow_rebinding
)
BENCH_CROSS_ARGS=()
for fixture in "${BENCH_CROSS_FIXTURES[@]}"; do
  BENCH_CROSS_ARGS+=(--fixture "$fixture")
done
python3 "$BENCH_RUN/after-py/tests/check_proven_check_elision.py" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --native-compiler "$BENCH_RUN/after-compiler" \
  --target windows-x64 --target minux-x64 "${BENCH_CROSS_ARGS[@]}" \
  --output "$BENCH_RUN/cross-matrix.json"

BENCH_CONCURRENT_FIXTURES=(
  gc_box_float_safepoint
  gc_float_call_roots
  numeric_float_loop
  numeric_float_loop_threads
  numeric_float_loop_typeof
  numeric_float_nested
  numeric_float_nested_threads
  numeric_float_nested_typeof
  numeric_float_tree
  numeric_float_tree_tofloat
  numeric_float_tree_typeof
  numeric_nullable_boxing
  numeric_typeflow_boxing
  proven_check_elision
)
BENCH_CONCURRENT_ARGS=()
for fixture in "${BENCH_CONCURRENT_FIXTURES[@]}"; do
  BENCH_CONCURRENT_ARGS+=(--fixture "$fixture")
done
python3 "$BENCH_RUN/after-py/tests/check_proven_check_elision.py" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --native-compiler "$BENCH_RUN/after-compiler" --target windows-x64 \
  --gc-concurrent "${BENCH_CONCURRENT_ARGS[@]}" \
  --output "$BENCH_RUN/concurrent-matrix.json"
```

## Prepare the original benchmarks and C/C++ images

Keep the helper paths pointing to the report checkout. The pinned after-source
worktrees intentionally contain no Phase 6 report helpers. Both compiler
variants below receive the same benchmark source and after-library paths.

```bash
mkdir -p "$BENCH_RUN/suite"
cp -R "$BENCH_ORIGINAL/suite/." "$BENCH_RUN/suite/"
mkdir -p "$BENCH_RUN/suite/build"
gcc -O3 -std=c11 -shared -fPIC "$BENCH_RUN/suite/drivers/observe.c" \
  -o "$BENCH_RUN/suite/build/libbench_observe.so"
for kernel in float_recurrence mandelbrot; do
  mkdir -p "$BENCH_RUN/suite/build/$kernel"
  gcc -O3 -march=x86-64 -mtune=generic -std=c11 \
    -ffp-contract=off -fno-fast-math -Wall -Wextra -x c \
    "$BENCH_RUN/suite/kernels/numeric/$kernel.c" \
    "$BENCH_RUN/suite/drivers/driver.c" \
    -o "$BENCH_RUN/suite/build/$kernel/c_o3"
  g++ -O3 -march=x86-64 -mtune=generic -std=c++17 \
    -ffp-contract=off -fno-fast-math -Wall -Wextra -x c++ \
    "$BENCH_RUN/suite/kernels/numeric/$kernel.c" \
    "$BENCH_RUN/suite/drivers/driver.c" \
    -o "$BENCH_RUN/suite/build/$kernel/cpp_o3"
done

for action in build validate; do
  python3 "$BENCH_EVIDENCE/compare_compilers.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/primary" \
    --cpu "$BENCH_CPU" --rounds 11
done
python3 "$BENCH_EVIDENCE/diagnose_float_nested.py" prepare \
  --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
  --after "$BENCH_RUN/after-compiler" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/float-comparison" \
  --cpu "$BENCH_CPU" --rounds 11
```

Preparation verifies Python/native images, the Phase 6-only ablation, small and
full-size checksum cases, and the separate GC probes. Do not proceed if any
preparation command fails. No compiler or test process should run concurrently
with the following timing commands.

## Measure and summarize sequentially

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
  python3 "$BENCH_EVIDENCE/diagnose_float_nested.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/float-comparison" \
    --cpu "$BENCH_CPU" --rounds 11
done
```

Runners stop on invalid measured or warmup checksums, incomplete rounds,
Python/native mismatch or failed ablation. The published files contain named
cases/variants and selected numeric observations. Reproduction commands,
logs, environment details and image hashes remain local evidence inputs.
