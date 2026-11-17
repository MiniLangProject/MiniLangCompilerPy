# Guarded nullable arithmetic: benchmark evidence — Phase 3 checkpoint

This is the third optimization round. The implementation and interpretation are
described in [performance_numeric_nullable.md](../../performance_numeric_nullable.md).
The original 15 kernels, drivers and independent checksum oracles are reused
from [the preceding evidence folder](../numeric_flow/suite/).

These observations describe a historical checkpoint. The pull requests now
also contain [Phase 4](../../performance_float_trees.md). Reproduce this
folder's `after` compiler with the following source revisions:

| Repository | Required Phase 3 commit |
|---|---|
| MiniLangCompilerPy | `45f63f6ef125863003cd6e2959916635f34a72ec` |
| MiniLangCompilerML | `a96f41f6396e3bbaf841643d9a174c1a39902ada` |

The [Phase 4 observations](../float_trees/README.md) use a separate baseline
and measurement series.

## Comparison boundary

`before` is the completed second round, including its float-recurrence boxing
optimization. Its public compiler revisions are:

- Python: [`0d9fdec53c26281b3b26b75f9c06539a20202ebd`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/0d9fdec53c26281b3b26b75f9c06539a20202ebd).
- MiniLang: [`0e852366880d51ccc39f6fa2e05b384dcc875910`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/0e852366880d51ccc39f6fa2e05b384dcc875910).

`after` is the compiler at the two Phase 3 commits listed above. It combines
guarded nullable numeric candidates with variable-RHS
float-parent box elision. A candidate is not a guaranteed numeric type and is
not a new language annotation. Actual numeric leaf tags and an actual float RHS
are checked before evaluating an eligible expression.

The measurements are relative to the second-round checkpoint, not release 1.3.9.
Keep this series separate from the earlier measurements; their absolute medians
were collected at different times.

## Records and variants

| File | Contents |
|---|---|
| `primary/measurements.jsonl` | 330 timed runs: 15 kernels, before/after, 11 paired rounds |
| `primary/summary.json` | Per-call medians, relative IQR, paired ratios and byte-equality controls |
| `float_ablation/measurements.jsonl` | 132 timed runs: two kernels, six variants, 11 rounds |
| `float_ablation/summary.json` | Separate-series medians and within-round ratios |
| `float_ablation/code_summary.json` | Executable segment sizes, identity controls and emitted RHS sites |
| `float_ablation/gc_diagnostics.json` | 40 separate untimed probes with numeric allocation/GC counters |
| `validation_summary.json` | Correctness, parity and platform-execution results |
| `diagnose_numeric_nullable.py` | Preparation, ablation, GC and timing runner |

The separate float series contains four MiniLang variants plus C and C++:

| Variant | Enabled changes |
|---|---|
| `before` | Original second-round compiler |
| `nullable_only` | New candidate facts, but only float-literal parent RHS values |
| `rhs_only` | New variable-RHS path, but nullable local facts removed before emission |
| `after` | Both changes |
| `c_o3` | Original C kernel and separate driver compiled as C11 |
| `cpp_o3` | The same kernel and driver compiled as C++17 |

Both single-change Mandelbrot variants are byte-identical to `before`; only the
combination changes its code. Every MiniLang recurrence variant is byte-identical.
These identities make the ablations useful noise controls as well as checking
which combination enables the new paths. The ablation wrappers always build
without the object cache.

## Measurement protocol

All timings use the original fixed sizes and repeat counts from
[`calibration.json`](../numeric_flow/suite/results/calibration.json). Each program
performs one full untimed warmup, then its batch using the balanced eight-seed
cycle starting at 12345. `CLOCK_MONOTONIC` is read within the process; compilation,
process startup and result printing are outside the interval. Every warmup and
measured checksum must match its oracle. Times are normalized per kernel call.

The primary series shuffles kernel order and alternates AB/BA order. The separate
six-variant series rotates and reverses variant order, also for 11 rounds. Paired
speedup is the median of within-round before/after ratios, not necessarily the
ratio of overall medians. Relative IQR is IQR divided by median.

The host was a shared Linux x86-64 VM. Timed programs were pinned to CPU 2, with
no other compiler or benchmark job from this evaluation running during timing.
Host load and CPU frequency were not controlled. The 14 unchanged primary images
provide measured controls for that variability. C/C++ use the original GCC/G++
14.2.0 `-O3` images, `-march=x86-64 -mtune=generic`, `-ffp-contract=off`,
`-fno-fast-math`, separate translation units and no LTO.

GC probes are untimed and retain the default collector settings. In samples
without a collection, `frontier_growth` measures allocation-frontier growth in
bytes and `block_delta` measures block-count growth. After a collection these
are net changes and must not be interpreted as cumulative allocation totals.
There is no RSS claim. Three static RHS sites in Mandelbrot include a cold
fallback site; this does not mean three saved objects per iteration.

## Reproduce

Requirements: Linux x86-64, Python 3, GCC/G++, `taskset`, Git and clean matching
checkouts of both repositories at the Phase 3 commits above. Run from
`MiniLangCompilerPy`, with
`MiniLangCompilerML` next to it. Use an empty `BENCH_RUN` directory for a new run.
The baseline worktrees use the public historical revisions, while the measured
benchmark source and standard-library paths are identical for before and after.

```sh
git checkout 45f63f6ef125863003cd6e2959916635f34a72ec
git -C ../MiniLangCompilerML checkout a96f41f6396e3bbaf841643d9a174c1a39902ada

MINILANG_PY_REPO="$PWD"
MINILANG_ML_REPO="$(cd ../MiniLangCompilerML && pwd)"
BENCH_EVIDENCE="$MINILANG_PY_REPO/docs/benchmarks/numeric_nullable"
BENCH_PREVIOUS="$MINILANG_PY_REPO/docs/benchmarks/numeric_flow"
BENCH_RUN="$MINILANG_PY_REPO/build/numeric-nullable-reproduction"
BENCH_CPU="$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')"
mkdir -p "$BENCH_RUN"

git -C "$MINILANG_PY_REPO" fetch origin 0d9fdec53c26281b3b26b75f9c06539a20202ebd
git -C "$MINILANG_PY_REPO" worktree add --detach "$BENCH_RUN/baseline-py" \
  0d9fdec53c26281b3b26b75f9c06539a20202ebd
git -C "$MINILANG_ML_REPO" fetch origin 0e852366880d51ccc39f6fa2e05b384dcc875910
git -C "$MINILANG_ML_REPO" worktree add --detach "$BENCH_RUN/baseline-ml" \
  0e852366880d51ccc39f6fa2e05b384dcc875910

sh "$BENCH_RUN/baseline-ml/build.sh" \
  --compiler "$BENCH_RUN/baseline-py/mlc_win64.py" \
  --output "$BENCH_RUN/baseline-compiler"
sh "$MINILANG_ML_REPO/build.sh" \
  --compiler "$MINILANG_PY_REPO/mlc_win64.py" \
  --output "$BENCH_RUN/after-compiler"

mkdir -p "$BENCH_RUN/suite"
cp -R "$BENCH_PREVIOUS/suite/." "$BENCH_RUN/suite/"
mkdir -p "$BENCH_RUN/suite/build"
gcc -O3 -std=c11 -shared -fPIC "$BENCH_RUN/suite/drivers/observe.c" \
  -o "$BENCH_RUN/suite/build/libbench_observe.so"

python3 "$BENCH_PREVIOUS/compare_compilers.py" all \
  --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/baseline-compiler" \
  --after "$BENCH_RUN/after-compiler" \
  --python-compiler "$MINILANG_PY_REPO/mlc_win64.py" \
  --stdlib "$MINILANG_PY_REPO" --work "$BENCH_RUN/primary" \
  --cpu "$BENCH_CPU" --rounds 11

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

for action in prepare measure summarize; do
  python3 "$BENCH_EVIDENCE/diagnose_numeric_nullable.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/baseline-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$MINILANG_PY_REPO/mlc_win64.py" \
    --stdlib "$MINILANG_PY_REPO" --work "$BENCH_RUN/float-ablation" \
    --cpu "$BENCH_CPU" --rounds 11
done
```

The runners abort on an invalid result or a Python/native parity mismatch.
Fresh runs generate local build records; the published records above contain
only benchmark names, variant names and whitelisted numeric observations.
