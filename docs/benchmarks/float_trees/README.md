# Bounded float trees: benchmark evidence

This is the fourth optimization round. The implementation, validation and
interpretation are described in
[performance_float_trees.md](../../performance_float_trees.md). The original
fifteen programs, drivers, fixed inputs and checksum oracles are reused from
[the numeric-flow evidence](../numeric_flow/suite/).

## Comparison boundary

`before` is the completed third round, including guarded nullable candidates
and variable-RHS child-root box elision. Its public compiler revisions are:

- Python: [`45f63f6ef125863003cd6e2959916635f34a72ec`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/45f63f6ef125863003cd6e2959916635f34a72ec).
- MiniLang: [`a96f41f6396e3bbaf841643d9a174c1a39902ada`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/a96f41f6396e3bbaf841643d9a174c1a39902ada).

`after` is the completed fourth-round source at these fixed commits:

- Python: [`6a953bb4f7f51947ba149fd64e2cbbdcefb17876`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/6a953bb4f7f51947ba149fd64e2cbbdcefb17876).
- MiniLang: [`ddc67c9c4f9c5828101e884076915f6536a3942c`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/ddc67c9c4f9c5828101e884076915f6536a3942c).

The pull requests now also include [Phase 5](../float_loops/README.md); choose
both Phase 4 commits before running the reproduction commands below.
It adds bounded, call-free float expression trees, including comparison roots.
All variable leaves must pass actual-float guards. Every non-root arithmetic
result must retain a float representation under the existing normalizer;
integer and unordered results return to the previous expression path. Only the
arithmetic root materializes its final Value. Comparison roots produce a bool.

This comparison is incremental against Phase 3, not pristine MiniLang or an
earlier optimization baseline. Keep the timing series separate: absolute
medians from earlier rounds were collected at different times.

## Published observations

| File | Contents |
|---|---|
| `primary/measurements.jsonl` | 330 timed runs: fifteen kernels, before/after, eleven rounds |
| `primary/summary.json` | Per-call medians, relative IQR, paired ratios and byte-equality controls |
| `float_ablation/measurements.jsonl` | 132 timed runs: two kernels, six variants, eleven rounds |
| `float_ablation/summary.json` | Separate-series medians and within-round comparisons |
| `float_ablation/code_summary.json` | Executable segment sizes, byte controls and static tree sites |
| `float_ablation/gc_diagnostics.json` | Forty separate untimed probes with allocation and GC counters |
| `validation_summary.json` | Correctness, compiler parity and platform-execution results |
| `diagnose_float_trees.py` | Preparation, root-class ablations, GC probes and timing runner |

The separate series uses these variants:

| Variant | Enabled new tree roots |
|---|---|
| `before` | Frozen Phase 3 native compiler |
| `arithmetic_only` | `+`, `-`, `*` roots; previous optimizations remain enabled |
| `comparison_only` | `==`, `!=`, `<`, `<=`, `>`, `>=` roots; previous optimizations remain enabled |
| `after` | Both root classes |
| `c_o3` | Original C kernel and separate driver compiled as C11 |
| `cpp_o3` | Same kernel and separate driver compiled as C++17 |

These ablations select the **root class**. A comparison tree contains arithmetic
internally, and ordinary fallback expressions can still optimize eligible
descendants. The wrappers do not globally disable arithmetic or comparisons.

Preparation also compiles a `tree_disabled` control with the new hook disabled
and requires it to reproduce the frozen `before` bytes for both kernels. The
control is not an additional timed variant. Python and native `after` images
must also be byte-identical. All ablation builds disable the object pipeline.

## Protocol and limits

Timings retain the original sizes, language-specific repeat counts and checksum
oracles from [`calibration.json`](../numeric_flow/suite/results/calibration.json).
Each process runs one full untimed warmup, then the timed batch with the original
balanced eight-seed cycle starting at 12345. `CLOCK_MONOTONIC` is read inside the
program. Compilation, startup and printing are outside that interval. Every
measured and warmup checksum must match. Times are normalized per kernel call.

The primary series shuffles case order and alternates before/after order. The
separate six-variant series pairs each cyclic rotation with its reverse:
`shift = (round // 2) % 6`, reversing odd rounds. Across eleven rounds, every
variant visits each of the six positions once or twice, and every variant pair
runs in each order five or six times. Both summaries use the median of
within-round ratios. That need not equal the ratio of independent time medians.
Relative IQR is IQR divided by the median.

The host was a shared Linux x86-64 VM. Timed programs were pinned to CPU 2, with
no other compiler or benchmark process from this evaluation running during
timing. CPU frequency and unrelated host load were uncontrolled. Thirteen
byte-identical primary images provide controls for that variation. The separate
series reuses the original GCC/G++ 14.2.0 images with `-O3`,
`-march=x86-64 -mtune=generic`, `-ffp-contract=off -fno-fast-math`, separate
translation units and no LTO. These are local kernel comparisons.

GC probes are separate untimed programs using the existing collector settings.
Without a collection, `block_delta` records allocation-block growth and
`frontier_growth` records allocation-frontier bytes. After collections, those
deltas are net changes, not cumulative allocation totals. Static tree labels
include fallback copies and must not be interpreted as objects saved per loop.

## Reproduce

Requirements: Linux x86-64, Python 3, GCC/G++, Git, `taskset`, and matching
checkouts at both Phase 4 commits listed above. Run from `MiniLangCompilerPy`, with
`MiniLangCompilerML` beside it. Use an empty `BENCH_RUN` directory. The baseline
compilers come from pinned worktrees; both measured variants compile the same
benchmark and standard-library paths.

```sh
MINILANG_PY_REPO="$PWD"
MINILANG_ML_REPO="$(cd ../MiniLangCompilerML && pwd)"
BENCH_EVIDENCE="$MINILANG_PY_REPO/docs/benchmarks/float_trees"
BENCH_ORIGINAL="$MINILANG_PY_REPO/docs/benchmarks/numeric_flow"
BENCH_RUN="$MINILANG_PY_REPO/build/float-tree-reproduction"
BENCH_CPU="$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')"
mkdir -p "$BENCH_RUN"

git -C "$MINILANG_PY_REPO" fetch origin 45f63f6ef125863003cd6e2959916635f34a72ec
git -C "$MINILANG_PY_REPO" worktree add --detach "$BENCH_RUN/baseline-py" \
  45f63f6ef125863003cd6e2959916635f34a72ec
git -C "$MINILANG_ML_REPO" fetch origin a96f41f6396e3bbaf841643d9a174c1a39902ada
git -C "$MINILANG_ML_REPO" worktree add --detach "$BENCH_RUN/baseline-ml" \
  a96f41f6396e3bbaf841643d9a174c1a39902ada

sh "$BENCH_RUN/baseline-ml/build.sh" \
  --compiler "$BENCH_RUN/baseline-py/mlc_win64.py" \
  --output "$BENCH_RUN/baseline-compiler"
sh "$MINILANG_ML_REPO/build.sh" \
  --compiler "$MINILANG_PY_REPO/mlc_win64.py" \
  --output "$BENCH_RUN/after-compiler"

mkdir -p "$BENCH_RUN/suite"
cp -R "$BENCH_ORIGINAL/suite/." "$BENCH_RUN/suite/"
mkdir -p "$BENCH_RUN/suite/build"
gcc -O3 -std=c11 -shared -fPIC "$BENCH_RUN/suite/drivers/observe.c" \
  -o "$BENCH_RUN/suite/build/libbench_observe.so"

python3 "$BENCH_ORIGINAL/compare_compilers.py" all \
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
  python3 "$BENCH_EVIDENCE/diagnose_float_trees.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/baseline-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$MINILANG_PY_REPO/mlc_win64.py" \
    --stdlib "$MINILANG_PY_REPO" --work "$BENCH_RUN/float-ablation" \
    --cpu "$BENCH_CPU" --rounds 11
done
```

The runners abort on an invalid result, a Python/native mismatch or a failed
disabled-hook baseline control. Fresh runs produce local build records. The
published JSON and JSONL files contain only named kernels/variants and selected
numeric observations.
