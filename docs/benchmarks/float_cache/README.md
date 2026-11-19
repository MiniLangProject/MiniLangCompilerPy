# Float-loop register cache: evidence and reproduction

This seventh round compares bounded fresh-definition register caching against
the completed sixth round. Read [the report](../../performance_float_cache.md)
for the measured outcome and semantic limits. Original sources, inputs, drivers,
calibration and oracles remain in [the numeric-flow suite](../numeric_flow/suite/).

## Exact source boundary

| Compiler | Before: Phase 6 | After: Phase 7 measured source |
| --- | --- | --- |
| MiniLangCompilerPy | [`c6c71076121111a687b61386ef2735f12c73164f`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/c6c71076121111a687b61386ef2735f12c73164f) | [`f5297ba9df6112aa53e5652c1011811d05a28fc4`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/f5297ba9df6112aa53e5652c1011811d05a28fc4) |
| MiniLangCompilerML | [`2c7c2637cebc8d0edcbc480cbfe1cb02a8523f1e`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/2c7c2637cebc8d0edcbc480cbfe1cb02a8523f1e) | [`30a7325cdfe5ca82a770a3dd8f5ba305d1148dcf`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/30a7325cdfe5ca82a770a3dd8f5ba305d1148dcf) |

After-source commits precede this report and its helpers. Use helpers from the
report checkout and compiler sources from the pinned revisions above.
[Source provenance](source_revisions.json) preserves the measured boundary.
Both variants receive the same after-source standard-library paths and benchmark
source paths. No additional branch is needed.

## Published files

| Path | Contents |
| --- | --- |
| `primary/measurements.jsonl`, `primary/summary.json` | 330 runs; fifteen cases, two variants, eleven rounds |
| `primary/builds.json`, `primary/method.json` | Image/source hashes, sizes and measurement method |
| `float_comparison/measurements.jsonl`, `float_comparison/summary.json` | 88 runs; two cases, four variants, eleven rounds |
| `float_comparison/code_summary.json` | Segment sizes, cache/normalizer markers and exact ablation controls |
| `float_comparison/gc_diagnostics.json` | Twenty separate allocation/GC probes |
| `float_comparison/c_reference_builds.json`, `float_comparison/method.json` | Fresh C/C++ commands, toolchain versions, hashes and method |
| `float_comparison/c_reference_correctness.json` | Thirty-six C/C++ checksum checks |
| `residual_costs/before/counts.json`, `residual_costs/after/counts.json` | Twenty-four counter probes per compiler |
| `residual_costs/before/sites.json`, `residual_costs/after/sites.json` | Static instrumentation sites for both kernels |
| `residual_costs/comparison.json`, `residual_costs/method.json` | Paired invariant checks, memory-instruction deltas and method |
| `validation_summary.json` | Correctness, parity and execution boundaries |
| `source_revisions.json` | Public measured source commits and parent/tree identities |
| `compare_compilers.py` | Primary preparation, validation, timing and summary runner |
| `diagnose_float_cache.py` | Fresh C/C++ builds, cache-only ablation, GC and separate timing runner |
| `diagnose_float_movement.py` | Separate untimed instruction/event counter programs |

## Build the frozen compilers

Requirements: Linux x86-64, Python 3.11 or newer, Git, Bash, GCC/G++, and `taskset`. Begin
in a Python compiler checkout containing this report, with the native repository
beside it. Choose a new empty `BENCH_RUN` path. Source worktrees are detached.
Both compilers are rebuilt; release 1.3.9 packages do not replace these source
builds.

```bash
set -euo pipefail
MINILANG_PY_REPO="$PWD"
MINILANG_ML_REPO="$(cd ../MiniLangCompilerML && pwd)"
BENCH_EVIDENCE="$MINILANG_PY_REPO/docs/benchmarks/float_cache"
BENCH_ORIGINAL="$MINILANG_PY_REPO/docs/benchmarks/numeric_flow"
BENCH_RUN="$MINILANG_PY_REPO/build/float-cache-reproduction"
BENCH_CPU="$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')"
BENCH_BEFORE_PY="c6c71076121111a687b61386ef2735f12c73164f"
BENCH_BEFORE_ML="2c7c2637cebc8d0edcbc480cbfe1cb02a8523f1e"
BENCH_AFTER_PY="f5297ba9df6112aa53e5652c1011811d05a28fc4"
BENCH_AFTER_ML="30a7325cdfe5ca82a770a3dd8f5ba305d1148dcf"
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

## Reproduce semantics and three-compiler parity

Finish correctness checks before either timing series. The Linux command
executes all 37 configurations and compares their output with Phase 6. Each
configuration builds Python, native monolithic and native MLO images and requires
exact byte equality. Windows/MinUX output is not executed by these Linux commands.

```bash
(
  cd "$BENCH_RUN/after-py"
  python3 -m unittest discover -s tests -p 'test_*.py'
  python3 tests/check_codegen_structure.py mlc_win64.py
  python3 tests/check_codegen_structure.py "$BENCH_RUN/after-compiler"
)
bash "$BENCH_RUN/after-ml/scripts/run_native_linux_regressions.sh" \
  "$BENCH_RUN/after-compiler"
python3 "$BENCH_RUN/after-py/tests/check_proven_check_elision.py" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --native-compiler "$BENCH_RUN/after-compiler" \
  --baseline-compiler "$BENCH_RUN/before-compiler" --target linux-x64 \
  --output "$BENCH_RUN/linux-matrix.json"

BENCH_CROSS_FIXTURES=(
  numeric_float_loop numeric_float_loop_threads numeric_float_loop_typeof
  numeric_float_nested numeric_float_nested_threads numeric_float_nested_typeof
  numeric_float_cache numeric_float_tree numeric_float_tree_tofloat
  numeric_float_tree_typeof numeric_nullable_boxing numeric_nullable_tofloat
  numeric_nullable_typeof numeric_typeflow_boxing numeric_typeflow_tofloat
  numeric_typeflow_typeof proven_check_elision proven_check_elision_typeof
  type_flow_context type_flow_rebinding
)
BENCH_CROSS_ARGS=()
for fixture in "${BENCH_CROSS_FIXTURES[@]}"; do
  BENCH_CROSS_ARGS+=(--fixture "$fixture")
done
python3 "$BENCH_RUN/after-py/tests/check_proven_check_elision.py" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --native-compiler "$BENCH_RUN/after-compiler" --target windows-x64 \
  --target minux-x64 "${BENCH_CROSS_ARGS[@]}" \
  --output "$BENCH_RUN/cross-matrix.json"

BENCH_CONCURRENT_FIXTURES=(
  gc_box_float_safepoint gc_float_call_roots numeric_float_loop
  numeric_float_loop_threads numeric_float_loop_typeof numeric_float_nested
  numeric_float_nested_threads numeric_float_nested_typeof numeric_float_cache
  numeric_float_tree numeric_float_tree_tofloat numeric_float_tree_typeof
  numeric_nullable_boxing numeric_typeflow_boxing proven_check_elision
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

## Prepare the original suite and exact ablation

The separate helper freshly builds C11/C++17 references from original sources
with strict floating-point flags, separate translation units and no LTO. It
records actual toolchain and binary hashes. It also requires Python/native current
image equality and that disabling **only** the register-cache mapping reproduces
Phase 6 images for both kernels. Do not disable earlier nested-loop or recurrence
optimizations.

```bash
mkdir -p "$BENCH_RUN/suite/build"
cp -R "$BENCH_ORIGINAL/suite/." "$BENCH_RUN/suite/"
gcc -O3 -std=c11 -shared -fPIC "$BENCH_RUN/suite/drivers/observe.c" \
  -o "$BENCH_RUN/suite/build/libbench_observe.so"
for action in build validate; do
  python3 "$BENCH_EVIDENCE/compare_compilers.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/primary" \
    --cpu "$BENCH_CPU" --rounds 11
done
python3 "$BENCH_EVIDENCE/diagnose_float_cache.py" prepare \
  --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
  --after "$BENCH_RUN/after-compiler" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/float-comparison" \
  --cpu "$BENCH_CPU" --rounds 11
```

## Reproduce separate counter observations

This step compiles instrumented and ordinary diagnostic programs with a one-call
driver, checks both against the oracle and compares event counts. It is untimed.
The original benchmark function is retained. Counter increments preserve
arithmetic flags, GPR/XMM/MXCSR and restore RSP, but intentionally add overhead. Do not time these
programs or interpret an instruction-count fraction as a CPU-time fraction.

```bash
for variant in before after; do
  python3 "$BENCH_EVIDENCE/diagnose_float_movement.py" run \
    --compiler-root "$BENCH_RUN/$variant-py" --suite "$BENCH_RUN/suite" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/residual-costs" \
    --variant "$variant" --cpu "$BENCH_CPU" --seeds 0 12345 2147483647
done
python3 "$BENCH_EVIDENCE/diagnose_float_movement.py" compare \
  --work "$BENCH_RUN/residual-costs" --before before --after after
```

The comparison checks identical source hashes, checksums and documented semantic
event counts. It reports body/commit memory-traffic changes separately. The
recorded set has 24 matching probe pairs, each with an ordinary uninstrumented
checksum check. This is distinct from the timing and correctness totals.

## Measure sequentially and summarize

Complete compilation, tests and diagnostics first. Run these two series
sequentially without another compiler or benchmark job from this evaluation.
The helpers check measured/warmup checksums and reject incomplete rounds.
Preparation records executable and calibration hashes; the separate runner
verifies them again before timing.

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
  python3 "$BENCH_EVIDENCE/diagnose_float_cache.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/float-comparison" \
    --cpu "$BENCH_CPU" --rounds 11
done
```

Both use internal `CLOCK_MONOTONIC`, a full warmup, the original eight-seed cycle
and fixed inputs/repeats. Primary rounds alternate pair order and shuffle cases.
The four-variant schedule balances each pair's relative order five/six times;
individual positions occur two to four times. Paired ratios need not equal the
ratio of separate medians. Affinity does not control host load or frequency.
Keep the thirteen identical primary images as noise controls and do not multiply
historical phase ratios. Fresh reproductions may use another host/toolchain and
are expected to have different absolute times.

Public evidence omits transient machine paths and complete subprocess logs;
it retains numeric observations, checksums, relevant hashes and reproduction
commands. The diagnostic method's `compiler_revision` records checkout HEAD at
capture time; the after working tree contained the measured edits before they
were committed. That field alone does not prove a pristine tree. The separate
`source_revisions.json` records the subsequently published measured source
boundary. Diagnostic capture did not record a separate per-file fingerprint of
compiler source; those missing fields are not reconstructed retrospectively.
Windows/MinUX execution and actual threaded raw-loop optimization are not claimed
by this Linux evaluation.
