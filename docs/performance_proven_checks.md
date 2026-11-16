# Proven check elision: implementation and measurement

Date: 2026-11-16. Branch: `perf/proven-check-elision`.

This document records the completed **first optimization round**. The current
branch also contains the subsequent numeric-flow and bounded boxing work
described in [Numeric type flow and bounded float-box elision](performance_numeric_flow.md).
The measurements below apply to the first-round checkpoint, not the later work.

## Decision

Keep two conservative optimizations that remove redundant generated checks:
valid integer-literal byte stores and independently proven primitive literal
contracts. Correctness and cross-compiler parity are the acceptance gates.
**The measurements do not establish a general runtime speedup.**

A third candidate, an additional numeric-add dispatch path, was implemented,
verified and measured, then removed from the final branch because its targeted
benchmark showed no consistent benefit while its executable code grew.
Its measured outcome is recorded below. The additional dispatch path is not
enabled by the final change. The first-round primary measurements compare the
1.3.9 baseline with the completed check-elision changes.

## Retained code changes

### Byte stores

`codegen_stmt` recognizes only a numeric AST literal whose actual value is an
integer in 0..255. Such a byte store omits the RHS integer-tag and range checks,
removing three conditional branches. Both the specialized and generic store
paths use the same proof. Floats, booleans, out-of-range literals, computed
expressions and compound updates retain their previous checks.

Target/index/RHS evaluation, target validation, index validation, negative-index
handling, bounds checks, decoding, writes and error priority retain the same
order. A failed write still leaves the buffer unchanged. Array stores are
unchanged. Python and MiniLang emit the same resulting instructions.

### Primitive literal contracts

`codegen_expr` proves a guard redundant only from primitive literal leaves and
the existing constant evaluator. Names, calls, member reads and nested guards
cannot supply the proof. The exact folded runtime type must match the contract,
including aliases. An annotation never proves its own initializer safe.

The proof also checks the existing `typeof` resolver. An actually called custom
`typeof` can have effects, so its check remains. Parameter contracts and dynamic
initializers remain checked. A normalized expression such as `0.5 + 0.5` is an
integer, so an `as float` contract still fails as before. The rule can also
apply to a synthetic literal field guard, because the proof concerns the
expression and contract rather than the declaration's location.

ABI, integer representation, float normalization, boxing, GC and language syntax
are unchanged. Existing project-cache identities already hash compiler sources
(Python) or executable contents (native), so stale artifacts cannot survive a
compiler change merely because its displayed release version stays 1.3.9.

## Regression checks

The new fixtures are `tests/proven_check_elision.ml` and
`tests/proven_check_elision_typeof.ml`. They are registered in the existing test
runners in both repositories. The portable
`tests/check_proven_check_elision.py` also checks Python/native/MLO byte parity
and executes only targets supported by its host.

Coverage includes byte boundaries and invalid values; unchanged buffers after
failed stores; negative indices; evaluation/error order; literal, local,
parameter and return contracts; a custom `typeof` with observable calls;
integer precision above 2^53 and both signed61 wrap boundaries; float-to-int
normalization; captured Error/void behavior; and float results under an actual
forced GC collection. The numeric semantic cases are retained even though the
extra numeric optimization was removed. The runner checks emitted code to
confirm that safe literal guards disappear while fallible guards remain.

Validation completed for this work:

- Python unittest discovery: 61 tests, 58 passed, 3 skipped. The skips are two
  Windows-only native checks and the optional NASM verification.
- 21 targeted Linux runtime fixtures, including the new fixtures, type flow,
  rebinding, operator overloading, GC roots, optimizer safety and class dispatch.
- Python, native monolithic and native MLO output parity across those Linux
  fixtures, plus five fixture cases on each of Windows and MinUX.
- Two additional Windows concurrent-GC fixtures compiled with the same parity.
  This option is Windows-only in the existing compiler.
- Native Linux path, executable-mode, project/incremental-cache regressions.
- Existing structural code-generation checks with Python and native compilers.
- A native bootstrap and native self-rebuild with identical executable bytes.
- 294 benchmark correctness runs, including 30 full-size runs; all 330 timed
  primary runs checked both measured and warmup checksums.

Windows and MinUX images were **not executed** in this Linux environment.
This is targeted regression coverage, not a claim that every upstream
platform-specific integration test was run.

## Runtime measurements

The original 15 kernels, original input sizes and original repeat counts were
kept. Each pair used the same input seed and balanced eight-seed cycle. The
standard driver performed one full untimed warmup, then measured the batch with
`CLOCK_MONOTONIC` inside the program. Default GC behavior was preserved.
Compilation, process startup and stdout were outside the measured interval.

There were eleven paired rounds per kernel, with alternating before/after order
and shuffled kernel order: 330 timed runs in total. Runs were pinned to CPU 2
on the same shared Linux x86-64 environment. No other compiler or benchmark job
from this work ran during timing. There was no frequency/governor control.

The table reports milliseconds per kernel call. Paired speedup is the median of
the eleven before/after ratios; values above 1 favor the patch. It need not equal
the ratio of the two separately reported time medians when the environment
varies. The last column identifies byte-identical before/after controls.

| Kernel | n | Before ms | After ms | Paired speedup | Faster pairs | Identical bytes |
|---|---:|---:|---:|---:|---:|---|
| `byte_copy` | 8388608 | 15.373 | 15.658 | 0.958x | 3/11 | yes |
| `byte_search` | 8388608 | 3.876 | 4.217 | 0.962x | 5/11 | no |
| `array_scan` | 194470 | 22.587 | 22.988 | 0.998x | 5/11 | yes |
| `array_scatter` | 225245 | 26.313 | 26.759 | 0.989x | 4/11 | yes |
| `sieve` | 1977051 | 17.201 | 17.625 | 1.094x | 7/11 | no |
| `heapsort` | 82396 | 31.883 | 30.820 | 1.027x | 8/11 | yes |
| `escaped_nodes` | 262144 | 7.758 | 7.793 | 1.029x | 7/11 | yes |
| `int_mix` | 2097152 | 11.099 | 11.260 | 1.008x | 6/11 | no |
| `branch_mix` | 1909761 | 21.455 | 20.598 | 1.012x | 8/11 | no |
| `float_recurrence` | 260986 | 33.215 | 32.605 | 0.992x | 5/11 | no |
| `mandelbrot` | 126 | 23.173 | 22.319 | 1.001x | 6/11 | no |
| `recursive_tree` | 1265 | 26.856 | 26.059 | 1.027x | 7/11 | no |
| `ascii_parse` | 262144 | 24.935 | 24.706 | 1.027x | 7/11 | no |
| `string_concat` | 7262 | 16.153 | 16.294 | 1.007x | 6/11 | no |
| `string_builder` | 114195 | 25.378 | 25.574 | 0.976x | 4/11 | no |

Five programs are byte-identical before and after. Even these controls show
measurement differences, and the primary measurements have substantial
interquartile spread (roughly 6-28% depending on kernel/configuration).
Consequently, the observed small changes should not be presented as reliable
speedups or regressions. For example, sieve has a paired median of 1.094x but
only seven faster pairs; its ratio of separate medians is below 1. That result
is insufficient for a performance claim.

Ten of the fifteen generated programs have smaller executable code segments,
with reductions between 32 and 864 bytes. Five are unchanged. These are concrete
code-generation results, distinct from elapsed-time improvement.

### Discarded numeric-add experiment

The candidate preserved int/int precision before converting to double and kept
the complete generic fallback for captured errors or void. Its targeted phase
accumulation kernel reaches exactly two new addition sites. It was verified
against an independent Python calculation and the baseline compiler in twenty
checks, then measured in eleven before/after pairs at n=250000 and 16 repeats.

| Targeted experiment | Before ms | After ms | Paired speedup | Faster pairs |
|---|---:|---:|---:|---:|
| Numeric phase accumulation | 5.5095 | 5.5017 | 0.993x | 4/11 |

The difference between separate medians is about 0.14%, while relative IQR is
4.4% before and 7.4% after. Executable code grows from 201539 to 202019 bytes.
This does not justify retaining the extra dispatch code.

Neither original `float_recurrence` nor original `mandelbrot` emitted the new
numeric-add path (or the existing exact-float specialization). This was checked
in compiler listings, not inferred from timing. Better propagation of safe
numeric facts and avoiding repeated float boxing were left for the subsequent
round documented separately; this first-round checkpoint did not solve those
bottlenecks.

The fifteen final benchmark images are checked byte-for-byte against the images
used for the primary timings after removal of the numeric candidate. This makes
the measured primary results applicable to the final check-elision patch
without recalibrating or replacing inputs.

## Reproduction

The following commands validate the retained checks in the current branch.
They do not recreate the first-round compiler or the discarded experiment.

From a Python repository beside `../MiniLangCompilerML`:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh ../MiniLangCompilerML/build.sh --compiler "$PWD/mlc_win64.py" --output build/mlc_proven_checks_final
python3 tests/check_proven_check_elision.py \
  --python-compiler mlc_win64.py \
  --native-compiler ../MiniLangCompilerML/build/mlc_proven_checks_final \
  --output build/proven_checks_linux.json
python3 tests/check_proven_check_elision.py \
  --python-compiler mlc_win64.py \
  --native-compiler ../MiniLangCompilerML/build/mlc_proven_checks_final \
  --fixture proven_check_elision --fixture proven_check_elision_typeof \
  --target windows-x64 --target minux-x64 \
  --output build/proven_checks_cross.json
bash ../MiniLangCompilerML/scripts/run_native_linux_regressions.sh \
  ../MiniLangCompilerML/build/mlc_proven_checks_final
```

The portable runner can be invoked from either repository when both compiler
paths are supplied explicitly. Its optional `--baseline-compiler` argument can
compare observable runtime output against a separately supplied release compiler.

First-round numerical evidence is published as a
[summary](benchmarks/proven_checks/summary.json) and
[raw measurement records](benchmarks/proven_checks/measurements.jsonl).
The [numeric-flow evidence README](benchmarks/numeric_flow/README.md) documents
the original benchmark sources, scripts and current-source ablations used for
the subsequent phase. Its baseline wrapper reproduces that phase's fifteen
measured before images; it does not reconstruct every compiler state from this
first-round study.
