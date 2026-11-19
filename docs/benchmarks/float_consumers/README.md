# Float-loop numeric consumers: evidence and reproduction

Read [the report](../../performance_float_consumers.md) for the measured outcome,
semantic proof and limits. Original programs, language drivers, calibrated inputs
and checksum oracles remain in [the numeric-flow suite](../numeric_flow/suite/).

## Exact source boundary

| Compiler | Before: Phase 7 | After: measured Phase 8 source |
| --- | --- | --- |
| MiniLangCompilerPy | [`d67b64bac4cc8abe2ced18d10a6188c610d2bd30`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/d67b64bac4cc8abe2ced18d10a6188c610d2bd30) | [`f53fdace586b3d1bacf6726d9bf0850f890dd91f`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/f53fdace586b3d1bacf6726d9bf0850f890dd91f) |
| MiniLangCompilerML | [`65d62add8bf7cc6d3c0439a0ba1d1e7e3690ad8d`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/65d62add8bf7cc6d3c0439a0ba1d1e7e3690ad8d) | [`f4f89844372d397348b6d93a950285148c1122b3`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/f4f89844372d397348b6d93a950285148c1122b3) |

The after-source commits contain implementation and tests. The report and
helpers are committed afterwards without changing those sources. Use the report
checkout for helpers and the pinned source worktrees for compilers. Both variants
receive the same after-source standard-library paths and benchmark source paths.

## Published evidence

| Path | Contents |
| --- | --- |
| `primary/` | Fifteen original cases, 330 timed runs, image hashes, correctness and method |
| `float_comparison/` | 88 separate MiniLang/C/C++ runs, exact ablation control, fresh C/C++ builds, correctness and twenty GC observations |
| `ablation/` | 56 component runs, four variants, preparation, eighty correctness observations and method |
| `residual_costs/` | Twenty-four before/after transition-counter pairs, static sites, provenance and invariant checks |
| `profiles/builds.json` | Exact executable/source/label identities used for sampling |
| `profiles/original_processes/` | Final original-cadence sampling: 48 sixteen-call processes per kernel |
| `profiles/extended_repeat_pilot/` | Earlier 256-call pilot, kept separate from original-cadence interpretation |
| `mxcsr/` | Exact C bridge, MiniLang input and 272 paired floating-point-status observations |
| `source_revisions.json`, `validation_summary.json` | Measured source boundary and tested platform limits |

Public helpers are `compare_compilers.py`, `diagnose_float_consumers.py`,
`ablate_float_consumers.py`, `diagnose_float_transitions.py`,
`profile_float_costs.py`, `profile_float_costs_long_calls.py`, and
`check_consumer_mxcsr.py`. Numeric data, checksums, source fingerprints and relevant
hashes are retained; transient machine paths and full process logs are omitted.

## Build frozen compilers

Requirements: Linux x86-64, Python 3.11 or newer, Git, Bash, GCC/G++, and `taskset`.
Sampling additionally requires `libatomic.so.1` and permission for per-process
Linux software perf events. Hardware-cycle events are not required. Start in the Python repository
checkout containing this report, with the native repository beside it. Choose a
new empty `BENCH_RUN` path. Worktrees are detached; no extra branch is created.

```bash
set -euo pipefail
MINILANG_PY_REPO="$PWD"
MINILANG_ML_REPO="$(cd ../MiniLangCompilerML && pwd)"
BENCH_EVIDENCE="$MINILANG_PY_REPO/docs/benchmarks/float_consumers"
BENCH_ORIGINAL="$MINILANG_PY_REPO/docs/benchmarks/numeric_flow"
BENCH_RUN="$MINILANG_PY_REPO/build/float-consumer-reproduction"
BENCH_CPU="$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')"
BENCH_BEFORE_PY="d67b64bac4cc8abe2ced18d10a6188c610d2bd30"
BENCH_BEFORE_ML="65d62add8bf7cc6d3c0439a0ba1d1e7e3690ad8d"
BENCH_AFTER_PY="f53fdace586b3d1bacf6726d9bf0850f890dd91f"
BENCH_AFTER_ML="f4f89844372d397348b6d93a950285148c1122b3"
mkdir -p "$BENCH_RUN"
git -C "$MINILANG_PY_REPO" fetch origin "$BENCH_BEFORE_PY" "$BENCH_AFTER_PY"
git -C "$MINILANG_ML_REPO" fetch origin "$BENCH_BEFORE_ML" "$BENCH_AFTER_ML"
git -C "$MINILANG_PY_REPO" worktree add --detach "$BENCH_RUN/before-py" "$BENCH_BEFORE_PY"
git -C "$MINILANG_ML_REPO" worktree add --detach "$BENCH_RUN/before-ml" "$BENCH_BEFORE_ML"
git -C "$MINILANG_PY_REPO" worktree add --detach "$BENCH_RUN/after-py" "$BENCH_AFTER_PY"
git -C "$MINILANG_ML_REPO" worktree add --detach "$BENCH_RUN/after-ml" "$BENCH_AFTER_ML"
sh "$BENCH_RUN/before-ml/build.sh" \
  --compiler "$BENCH_RUN/before-py/mlc_win64.py" --output "$BENCH_RUN/before-compiler"
sh "$BENCH_RUN/after-ml/build.sh" \
  --compiler "$BENCH_RUN/after-py/mlc_win64.py" --output "$BENCH_RUN/after-compiler"
sh "$BENCH_RUN/after-ml/build.sh" \
  --compiler "$BENCH_RUN/after-compiler" --output "$BENCH_RUN/after-selfhost"
cmp "$BENCH_RUN/after-compiler" "$BENCH_RUN/after-selfhost"
```

## Reproduce semantics and compiler parity

Run all correctness work before timing. The Linux matrix executes 38
configurations and compares their outputs with Phase 7. Each configuration
builds Python, native monolithic and native MLO images and requires byte equality.
Windows/MinUX commands below compile and compare images; they do not execute them.

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

BENCH_CROSS_FIXTURES=(
  numeric_float_loop numeric_float_loop_threads numeric_float_loop_typeof
  numeric_float_nested numeric_float_nested_threads numeric_float_nested_typeof
  numeric_float_cache numeric_float_consumer numeric_float_tree
  numeric_float_tree_tofloat numeric_float_tree_typeof numeric_nullable_boxing
  numeric_nullable_tofloat numeric_nullable_typeof numeric_typeflow_boxing
  numeric_typeflow_tofloat numeric_typeflow_typeof proven_check_elision
  proven_check_elision_typeof type_flow_context type_flow_rebinding
)
BENCH_CROSS_ARGS=()
for fixture in "${BENCH_CROSS_FIXTURES[@]}"; do
  BENCH_CROSS_ARGS+=(--fixture "$fixture")
done
python3 "$BENCH_RUN/after-py/tests/check_proven_check_elision.py" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --native-compiler "$BENCH_RUN/after-compiler" --target windows-x64 \
  --target minux-x64 "${BENCH_CROSS_ARGS[@]}" --output "$BENCH_RUN/cross-matrix.json"

BENCH_CONCURRENT_FIXTURES=(
  gc_box_float_safepoint gc_float_call_roots numeric_float_loop
  numeric_float_loop_threads numeric_float_loop_typeof numeric_float_nested
  numeric_float_nested_threads numeric_float_nested_typeof numeric_float_cache
  numeric_float_consumer numeric_float_tree numeric_float_tree_tofloat
  numeric_float_tree_typeof numeric_nullable_boxing numeric_typeflow_boxing
  proven_check_elision
)
BENCH_CONCURRENT_ARGS=()
for fixture in "${BENCH_CONCURRENT_FIXTURES[@]}"; do
  BENCH_CONCURRENT_ARGS+=(--fixture "$fixture")
done
python3 "$BENCH_RUN/after-py/tests/check_proven_check_elision.py" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --native-compiler "$BENCH_RUN/after-compiler" --target windows-x64 \
  --gc-concurrent "${BENCH_CONCURRENT_ARGS[@]}" --output "$BENCH_RUN/concurrent-matrix.json"
```

## Prepare original workloads, references and independent ablations

The separate helper rebuilds strict C11/C++17 references from the original
sources, records compiler/command/source/image provenance and checks 36
additional reference results. Its disabled-both control must reproduce Phase 7
exactly. Current Python and native images must also be byte-identical.

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
python3 "$BENCH_EVIDENCE/diagnose_float_consumers.py" prepare \
  --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
  --after "$BENCH_RUN/after-compiler" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/float-comparison" \
  --cpu "$BENCH_CPU" --rounds 11
python3 "$BENCH_EVIDENCE/ablate_float_consumers.py" prepare \
  --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
  --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
  --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/ablation" \
  --cpu "$BENCH_CPU" --rounds 7
```

The ablation helper uses the current Python compiler for its three new variants;
it has no `--after` option. The separate preparation establishes current
Python/native image identity. Disabling the two Phase 8 hooks must not disable
the earlier register cache, nested-loop discovery or any normalizer probe.

## Reproduce untimed transition and MXCSR observations

The transition helper compiles separate instrumented and ordinary programs,
checks each result against the oracle and compares total body iterations.
Per-stage normalization branches are attempts minus float-path passes; integer
rejoins are recorded separately from actual deoptimization. Changed raw/ordinary
iteration counts are expected. Do not time these counter programs.

```bash
for variant in before after; do
  python3 "$BENCH_EVIDENCE/diagnose_float_transitions.py" run \
    --compiler-root "$BENCH_RUN/$variant-py" --suite "$BENCH_RUN/suite" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/residual-costs" \
    --variant "$variant" --cpu "$BENCH_CPU" --seeds 0 12345 2147483647
done
python3 "$BENCH_EVIDENCE/diagnose_float_transitions.py" compare \
  --work "$BENCH_RUN/residual-costs" --before before --after after
python3 "$BENCH_EVIDENCE/check_consumer_mxcsr.py" \
  --before "$BENCH_RUN/before-compiler" --after "$BENCH_RUN/after-compiler" \
  --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/mxcsr"
```

MXCSR inputs default to the exact `mxcsr/` directory beside the helper. It covers
17 probes under sixteen rounding/DAZ/FTZ control combinations, with exceptions
masked. It compares flags, control bits, result tags and iteration counts; it
does not compare exact numeric result bits or exercise traps. Result formatting
avoids the baseline infinity-formatting failure found in an earlier driver.

## Reproduce baseline sampling separately

The profile uses unchanged native executable bytes and the matching Python label
map. Generate both from the pinned Phase 7 sources. Sampling covers the complete
process, including startup, one warmup and printing. It is not a timing series.

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
  --output "$BENCH_RUN/profiles-original" --cpu "$BENCH_CPU" \
  --reps 16 --processes-per-period 16
python3 "$BENCH_EVIDENCE/profile_float_costs_long_calls.py" \
  --images "$BENCH_RUN/profile-images" --suite "$BENCH_RUN/suite" \
  --output "$BENCH_RUN/profiles-extended-pilot" --cpu "$BENCH_CPU" --reps 256
```

The second command reproduces the earlier pilot's shape. Keep it separate from
the original sixteen-call profile. Software-clock interrupt skid and correlated
samples prevent interpreting an IP-range percentage as an exact instruction
cost or removable runtime fraction. No callchain attribution is available;
samples inside GC/allocation routines do not prove which caller caused them.

## Measure sequentially and summarize

Finish all compilation, correctness work, instrumentation and sampling first.
Run the three timing series sequentially without another compiler, test, sampler
or benchmark job from this evaluation. Preparation records hashes. The explicit
check below verifies primary compiler, calibration, source and image hashes;
the separate and ablation runners also check their prepared hashes. All timing
runners validate warmup/measured checksums. The component
series precedes the final primary and separate series, as in the recorded run.

```bash
python3 - "$BENCH_RUN" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

run = Path(sys.argv[1])
def verify(path, expected):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"Prepared input changed: {path}")

environment = json.loads((run / "primary/results/environment.json").read_text())
for variant in ("before", "after"):
    verify(run / f"{variant}-compiler", environment[variant + "_sha256"])
verify(run / "suite/results/calibration.json", environment["calibration_sha256"])
for row in json.loads((run / "primary/results/builds.json").read_text()):
    verify(run / "suite/inputs" / (row["case"] + ".ml"), row["source_sha256"])
    for variant, details in row["variants"].items():
        verify(run / "primary/build" / row["case"] / variant, details["sha256"])
ablation = json.loads((run / "ablation/method.json").read_text())
for relative, expected in ablation["compiler_source_sha256"].items():
    verify(run / "after-py" / relative, expected)
print("Prepared primary inputs, images and current compiler sources match.")
PY
for action in measure summarize; do
  python3 "$BENCH_EVIDENCE/ablate_float_consumers.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
    --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/ablation" \
    --cpu "$BENCH_CPU" --rounds 7
done
for action in measure summarize; do
  python3 "$BENCH_EVIDENCE/compare_compilers.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/primary" \
    --cpu "$BENCH_CPU" --rounds 11
done
for action in measure summarize; do
  python3 "$BENCH_EVIDENCE/diagnose_float_consumers.py" "$action" \
    --suite "$BENCH_RUN/suite" --before "$BENCH_RUN/before-compiler" \
    --after "$BENCH_RUN/after-compiler" \
    --python-compiler "$BENCH_RUN/after-py/mlc_win64.py" \
    --stdlib "$BENCH_RUN/after-py" --work "$BENCH_RUN/float-comparison" \
    --cpu "$BENCH_CPU" --rounds 11
done
```

All use internal `CLOCK_MONOTONIC` timing, original inputs/calibrated repeats,
full warmups and the eight-seed cycle. Primary rounds shuffle cases and alternate
before/after order. Four-variant schedules rotate and reverse order. Pair ratios
need not equal the ratio of separate medians. CPU affinity does not control host
load or frequency; new reproductions can have different absolute times.

Transition methods record the compiler checkout HEAD at capture time and actual
compiler source-file fingerprints. The after working tree contained the measured
edits before its source commit was created; the HEAD field alone is not a claim
of a pristine tree. `source_revisions.json` identifies the subsequently published
source boundary. Windows/MinUX runtime execution, threaded raw-loop optimization,
unmasked floating-point exceptions and release packages are outside this run.
