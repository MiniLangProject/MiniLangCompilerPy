# Numeric-flow benchmark evidence — Phase 2 checkpoint

This directory contains the benchmark source code, independent checksum oracles,
fixed inputs, individual numeric observations and summaries for the second
optimization round. The compiler changes and interpretation are described in
[performance_numeric_flow.md](../../performance_numeric_flow.md).

This is a historical checkpoint. The pull requests now also contain the
[Phase 3 extension](../../performance_numeric_nullable.md). Reproducing the
observations in this directory requires both repositories at the Phase 2 source
state, rather than their moving pull-request heads:

| Repository | Required Phase 2 commit |
|---|---|
| MiniLangCompilerPy | `0d9fdec53c26281b3b26b75f9c06539a20202ebd` |
| MiniLangCompilerML | `0e852366880d51ccc39f6fa2e05b384dcc875910` |

References below to the final compiler and the `after` variant mean this
checkpoint. The [Phase 3 evidence](../numeric_nullable/README.md) is separate.

## Published observations

| File | Contents |
|---|---|
| `primary/measurements.jsonl` | 330 timed runs: 15 kernels, two compiler variants, 11 paired rounds |
| `primary/summary.json` | Medians, relative IQR, paired ratios, code size and byte-equality controls |
| `float_ablation/measurements.jsonl` | 110 timed runs: two float kernels, five variants, 11 rounds |
| `float_ablation/summary.json` | Separate-series medians and within-round comparisons |
| `float_ablation/gc_diagnostics.json` | 27 untimed GC probes with numeric counters |
| `validation_summary.json` | Final correctness, parity and platform-execution counts |
| `baseline_reproduction.json` | Workload-specific reproduction checks for all 15 before images |
| `suite/results/calibration.json` | Fixed sizes, repeat counts and expected checksums |

The records use explicit numeric fields and known benchmark/variant names. The
earlier exploratory round has its own [numeric observations](../proven_checks/).
The two rounds and the two final timing series must not be combined as if they
were measured at the same time.

## What the variants mean

- `before`: the retained first-round proven-check optimizations, before the new
  numeric-flow and boxing work. It is not pristine MiniLang 1.3.9.
- `inference`: the Phase 2 compiler with only the new child-box elimination hook
  disabled. This isolates the contribution of boxing from numeric inference.
- `after`: the compiler at the two Phase 2 commits listed above.
- `c_o3` / `cpp_o3`: the same numeric kernel and separate C driver compiled as C11
  or C++17 with GCC/G++ 14.2.0, `-O3 -march=x86-64 -mtune=generic`,
  `-ffp-contract=off -fno-fast-math`, without LTO.

`before_compiler.py` uses the Phase 2 Python compiler with the new numeric type
queries and child-box elimination disabled. For **all 15 published benchmark
inputs**, it was checked to reproduce the measured historical `before` images
byte for byte, using identical source and import paths. This is a
workload-specific ablation, not a restoration of the historical compiler for
arbitrary programs: the captured-parameter and NaN-folding parity fixes remain.
Moving a source tree can change embedded error-provenance paths, so hashes from
unrelated checkout locations are not a cross-machine identity requirement.

## Measurement protocol and limits

The target was Linux x86-64 in a shared virtual machine. Every timed process was
pinned to one allowed CPU, with no other compiler or benchmark job started by
the evaluation during timing. CPU frequency and unrelated host load were not
controlled. Each process performs one full untimed warmup and then the original
fixed repeat count, using the balanced eight-seed cycle starting at 12345.
`CLOCK_MONOTONIC` is read inside the program. Compilation, process startup and
printing the result are outside that interval. Every timed checksum and warmup
checksum was checked. There is no RSS or process-startup performance claim.

The primary runner shuffles kernel order and alternates AB/BA order within each
round. The separate float runner rotates and reverses the five-variant order.
Times are divided by each language's original repeat count before comparison.
Paired speedup is the median of within-round before/after ratios; it need not
equal the ratio of overall medians. Relative IQR is IQR divided by median.
Thirteen primary before/after images were identical, providing noise controls.

GC probes are separate untimed programs. In collection-free samples,
`frontier_growth` describes allocation-frontier growth in bytes and `block_delta`
describes block-count growth. After a collection they are net heap changes,
not cumulative allocation totals.
Only Linux outputs were executed. Windows, MinUX and Windows concurrent-GC
configurations were compiled and compared, not runtime-tested.

## Reproduce the historical checkpoint

Requirements: Linux x86-64, Python 3, GCC/G++, `taskset`, and matching checkouts of
both compiler repositories at the pinned commits above. Run the following in `MiniLangCompilerPy`, with
`MiniLangCompilerML` next to it. The commands create their outputs under `build`.
Choose an available CPU appropriate to your machine; the example uses the first
allowed one. Retain the fixed inputs and repeat counts for a comparable run.

```sh
git checkout 0d9fdec53c26281b3b26b75f9c06539a20202ebd
git -C ../MiniLangCompilerML checkout 0e852366880d51ccc39f6fa2e05b384dcc875910

export MINILANG_PY_REPO="$PWD"
MINILANG_ML_REPO="$(cd ../MiniLangCompilerML && pwd)"
BENCH_EVIDENCE="$MINILANG_PY_REPO/docs/benchmarks/numeric_flow"
BENCH_RUN="$MINILANG_PY_REPO/build/numeric-flow-reproduction"
BENCH_CPU="$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')"
mkdir -p "$BENCH_RUN/suite"
cp -R "$BENCH_EVIDENCE/suite/." "$BENCH_RUN/suite/"
mkdir -p "$BENCH_RUN/suite/build"

sh "$MINILANG_ML_REPO/build.sh" \
  --compiler "$MINILANG_PY_REPO/mlc_win64.py" \
  --output "$MINILANG_ML_REPO/build/mlc_numeric_flow"

gcc -O3 -std=c11 -shared -fPIC \
  "$BENCH_RUN/suite/drivers/observe.c" \
  -o "$BENCH_RUN/suite/build/libbench_observe.so"

python3 "$BENCH_EVIDENCE/compare_compilers.py" all \
  --suite "$BENCH_RUN/suite" \
  --before "$BENCH_EVIDENCE/before_compiler.py" \
  --after "$MINILANG_ML_REPO/build/mlc_numeric_flow" \
  --python-compiler "$MINILANG_PY_REPO/mlc_win64.py" \
  --stdlib "$MINILANG_PY_REPO" \
  --work "$BENCH_RUN/primary" --cpu "$BENCH_CPU" --rounds 11

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
  python3 "$BENCH_EVIDENCE/phase2/diagnose_float_changes.py" "$action" \
    --suite "$BENCH_RUN/suite" \
    --before "$BENCH_EVIDENCE/before_compiler.py" \
    --after "$MINILANG_ML_REPO/build/mlc_numeric_flow" \
    --python-compiler "$MINILANG_PY_REPO/mlc_win64.py" \
    --stdlib "$MINILANG_PY_REPO" \
    --work "$BENCH_RUN/float-ablation" --cpu "$BENCH_CPU" --rounds 11
done
```

The public runner copies only adjust source-file locations and select an allowed
build CPU when CPU 4 is unavailable; timing, warmup, input, checksum and ordering
logic are unchanged. They generate local build records for a fresh run. Only
the whitelisted numeric observations from the completed evaluation are included
here. Checksum or parity failure aborts the runners instead of accepting a time.
