# Guarded float loops: benchmark evidence

This is the fifth optimization round. See
[performance_float_loops.md](../../performance_float_loops.md) for implementation,
validation and interpretation. All fifteen original benchmark sources, drivers,
fixed inputs and checksum oracles are reused from
[the numeric-flow suite](../numeric_flow/suite/).

## Source boundary

`before` is the completed fourth-round compiler:

- Python: [`6a953bb4f7f51947ba149fd64e2cbbdcefb17876`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/6a953bb4f7f51947ba149fd64e2cbbdcefb17876).
- MiniLang: [`ddc67c9c4f9c5828101e884076915f6536a3942c`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/ddc67c9c4f9c5828101e884076915f6536a3942c).

`after` is the matching fifth-round source in the companion pull requests. It
adds the guarded, transactional raw loop; previous expression optimizations
remain enabled. Both variants compile identical benchmark and standard-library
paths. Earlier reports retain their own pinned revisions and measurement series.

## Published observations

| File | Contents |
|---|---|
| `primary/measurements.jsonl` | 330 timed runs: 15 cases, 2 variants, 11 rounds |
| `primary/summary.json` | Per-call medians, IQR, paired ratios and byte controls |
| `float_comparison/measurements.jsonl` | 88 runs: 2 cases, 4 variants, 11 rounds |
| `float_comparison/summary.json` | Separate before/after and C/C++ comparisons |
| `float_comparison/gc_diagnostics.json` | 20 untimed GC and allocation observations |
| `float_comparison/code_summary.json` | Segment sizes, static sites and byte controls |
| `validation_summary.json` | Correctness, parity and execution-platform boundaries |
| `compare_compilers.py` | Primary build, oracle validation and timing runner |
| `diagnose_float_loops.py` | Disabled-loop control, GC probes and four-variant runner |

The four timed variants are `before`, `after`, `c_o3` and `cpp_o3`. Preparation
also builds Python `after` and `loop_disabled` controls. The latter disables both
`_opt_float_loop_arena_bytes` and `_opt_emit_float_loop` and must reproduce the
frozen baseline bytes. These controls are not additional timed variants.
All MiniLang benchmark builds explicitly disable the object pipeline; native
MLO parity is verified separately by the semantic matrix.

## Protocol and limits

The runners retain the original calibrated inputs and language-specific repeat
counts. Each process performs a full untimed warmup and then the original
eight-seed cycle starting at 12345. Measured and warmup checksums must match.
Timing is internal `CLOCK_MONOTONIC`, excluding compilation, process startup and
printing. Elapsed time is divided by the repeat count.

Primary rounds shuffle cases and alternate AB/BA order. The separate schedule
uses `shift = (round // 2) % 4`, followed by reversal on odd rounds. Across eleven
rounds each variant visits all positions, and every pair runs in each relative
order five or six times. Position counts are 2–4; they are not equal. Summaries
report the median of within-round ratios, which need not equal a ratio of the
individual time medians. Relative IQR is IQR divided by the median.

The recorded host was a shared Linux x86-64 VM. Timed children were pinned to
CPU 2, with no other compiler or benchmark process from this evaluation running.
Unrelated host load and CPU frequency were uncontrolled. Fourteen byte-identical
primary images, including Mandelbrot, are noise controls. GC probes are separate
untimed programs. After collection, heap/block deltas describe net changes,
not cumulative allocations. Static loop/normalizer sites include fallback code
and must not be interpreted as runtime allocation savings.

The C/C++ comparison reuses original GCC/G++ 14.2.0 images with strict floating
point options, separate translation units and no LTO. A fresh reproduction may
use another host/toolchain; record its versions and expect different absolute
numbers. These are kernel comparisons, not universal language-speed estimates.

## Reproduce

Requirements: Linux x86-64, Python 3, Git, GCC/G++, `taskset`, and matching Phase 5
checkouts of both companion repositories. Start in `MiniLangCompilerPy`, with
`MiniLangCompilerML` beside it. Use an empty `BENCH_RUN` directory. Finish all
preparation before timing and do not run compilation concurrently with timings.

```sh
MINILANG_PY_REPO="$PWD"
MINILANG_ML_REPO="$(cd ../MiniLangCompilerML && pwd)"
BENCH_EVIDENCE="$MINILANG_PY_REPO/docs/benchmarks/float_loops"
BENCH_ORIGINAL="$MINILANG_PY_REPO/docs/benchmarks/numeric_flow"
BENCH_RUN="$MINILANG_PY_REPO/build/float-loop-reproduction"
BENCH_CPU="$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')"
mkdir -p "$BENCH_RUN"

git -C "$MINILANG_PY_REPO" fetch origin 6a953bb4f7f51947ba149fd64e2cbbdcefb17876
git -C "$MINILANG_PY_REPO" worktree add --detach "$BENCH_RUN/baseline-py" \
  6a953bb4f7f51947ba149fd64e2cbbdcefb17876
git -C "$MINILANG_ML_REPO" fetch origin ddc67c9c4f9c5828101e884076915f6536a3942c
git -C "$MINILANG_ML_REPO" worktree add --detach "$BENCH_RUN/baseline-ml" \
  ddc67c9c4f9c5828101e884076915f6536a3942c

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
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/baseline-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$MINILANG_PY_REPO/mlc_win64.py" \
    --stdlib "$MINILANG_PY_REPO" --work "$BENCH_RUN/primary" \
    --cpu "$BENCH_CPU" --rounds 11
done
python3 "$BENCH_EVIDENCE/diagnose_float_loops.py" prepare \
  --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/baseline-compiler" \
  --after "$BENCH_RUN/after-compiler" \
  --python-compiler "$MINILANG_PY_REPO/mlc_win64.py" \
  --stdlib "$MINILANG_PY_REPO" --work "$BENCH_RUN/float-comparison" \
  --cpu "$BENCH_CPU" --rounds 11

for action in measure summarize; do
  python3 "$BENCH_EVIDENCE/compare_compilers.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/baseline-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$MINILANG_PY_REPO/mlc_win64.py" \
    --stdlib "$MINILANG_PY_REPO" --work "$BENCH_RUN/primary" \
    --cpu "$BENCH_CPU" --rounds 11
done
for action in measure summarize; do
  python3 "$BENCH_EVIDENCE/diagnose_float_loops.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/baseline-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$MINILANG_PY_REPO/mlc_win64.py" \
    --stdlib "$MINILANG_PY_REPO" --work "$BENCH_RUN/float-comparison" \
    --cpu "$BENCH_CPU" --rounds 11
done
```

The runners stop on invalid checksums, missing rounds, Python/native mismatch
or a failed disabled-loop control. Build records generated by a reproduction
remain local. The published data contains only named cases/variants and selected
numeric observations.

## Reproduce focused semantics and parity

With the compilers above built, run from `MiniLangCompilerPy`:

```sh
python3 tests/check_proven_check_elision.py \
  --python-compiler mlc_win64.py --native-compiler "$BENCH_RUN/after-compiler" \
  --baseline-compiler "$BENCH_RUN/baseline-compiler" --target linux-x64 \
  --output "$BENCH_RUN/linux-matrix.json"
python3 tests/check_proven_check_elision.py \
  --python-compiler mlc_win64.py --native-compiler "$BENCH_RUN/after-compiler" \
  --target windows-x64 --target minux-x64 \
  --fixture numeric_float_loop --fixture numeric_float_loop_typeof \
  --fixture numeric_float_loop_threads --output "$BENCH_RUN/loop-cross.json"
python3 tests/check_proven_check_elision.py \
  --python-compiler mlc_win64.py --native-compiler "$BENCH_RUN/after-compiler" \
  --target windows-x64 --gc-concurrent \
  --fixture numeric_float_loop --fixture numeric_float_loop_typeof \
  --fixture numeric_float_loop_threads --output "$BENCH_RUN/loop-concurrent.json"
```

The first command runs the complete Linux catalog; the other commands focus on
this phase's new fixtures. The recorded cross-platform gates additionally reran
the earlier numeric, check-elision, scope and GC fixtures represented in the
validation summary. Windows and MinUX output is compared without being executed
on the Linux host.
