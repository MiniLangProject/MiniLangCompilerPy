# Numeric value flow and bounded float box elision

Date: 2026-11-16. Branch: `perf/proven-check-elision`.

This phase adds conservative numeric facts and removes one temporary float
materialization in a restricted arithmetic pattern. The historical
[proven-check report](performance_proven_checks.md) covers the earlier literal
contracts, byte stores and their measurements. Implementation is in the
[code generation modules](../mlc/codegen/).

## Measured result and decision

Keep the bounded changes. On the original `float_recurrence` input, the primary
comparison improved from **31.765 to 26.525 ms per call**, with **1.198x paired
median speedup and eleven faster pairs out of eleven**. A separate ablation
series reproduced the gain and attributes most of it to the skipped intermediate
materializations. No general speedup is claimed: thirteen other primary images
are byte-identical, and Mandelbrot has no consistent timing improvement.

The measured comparison baseline is the completed first-round check-elision
compiler. The public baseline wrapper uses the current Python compiler with new
known-type queries forced to legacy and child-root box elision disabled.
For the fifteen original benchmark programs with matching source/import paths,
it reproduces every actually measured before image byte-for-byte. This is a
workload-specific ablation,
not a restoration of the full historical compiler. The
[benchmark evidence README](benchmarks/numeric_flow/README.md) describes its scope
and reproduction procedure.

## Two independent fact maps

The existing general fact map keeps its legacy behavior. Index diagnostics and
lowering, `typeof`, return contracts, operator resolution, integer paths and
promotion continue using that map. Existing call optimizations are retained.

A separate safe numeric map feeds only the additional float-pair fallback and
bounded box elision. Float lowering first tries the complete legacy operand
pair. Only if that pair is insufficient does it try the complete new pair.
It never combines a new fact for one operand with a legacy fact for the other.
The additional pair fallback is disabled while `try` suppresses error
propagation. Inline emission receives no new numeric fact set and cannot
inherit the caller's numeric assumptions.

This separation preserves existing diagnostic timing, observable custom
`typeof` calls and error behavior while allowing explicitly selected numeric
paths to use stronger proofs.

## Conservative numeric facts

The new map retains function-wide categories only when every write supports
them. Initialization inside a lexical block must dominate the binding's reads.
Initialization does not flow unconditionally out of branches or loops; a loop
might execute zero times. Reads before initialization retain possible `void`
behavior.

Nonoptional primitive parameter contracts seed facts only with proven builtin
guard semantics. Real entry guards remain; annotations cannot justify removing
their own checks. Every later assignment joins the analysis. Integer and float
writes may join to internal `number`, a tagged integer-or-float union rather
than an unboxed double or new source type.

Globals, captures, boxed bindings, synchronized values, optional or untyped
parameters, and ambiguous same-name lexical bindings remain excluded.

## Builtin identity and proof boundaries

A new `toFloat` fact requires actual builtin resolution, accounting for
shadowing and import aliases, plus a proven numeric argument in the accepted
primitive-expression subset. Uncertain calls and fallible division/modulo do
not establish this argument proof.

A NaN divisor does not satisfy the new ordered, nonzero constant-divisor proof.
Likewise, a declared numeric user-function return does not exclude implicit
`void` fallthrough, including calls through aliases. Numeric returns from
opaque user functions or overloaded operators therefore remain unknown in
the safe map. These restrictions do not remove legacy call facts or their
previously selected paths.

## One intermediate materialization

The box-elision emitter accepts this pattern, with each operator independently
chosen from `+`, `-` and `*`:

```text
(child_left op child_right) op FLOAT_LITERAL
```

The child has at most two binary-operation levels. Leaves are numeric literals
or proven ordinary numeric locals/parameters. Calls, indexing, members, globals,
captures and boxed bindings are excluded. The parent right operand must be a
float literal. Folded and statically integer-only children keep their existing
lowering.

Runtime guards check local leaves before operand evaluation. A mismatch runs
the original expression once. Stable leaves and total primitive operations make
later conversion failures unreachable, avoiding duplicated language effects.

Child operands retain ordinary rooted evaluation and deeper materializations.
Only the child root stays in an XMM register until the parent consumes it.
No raw float enters a GC root slot or survives across a call. The parent uses
normal normalization/materialization and the existing allocation/GC path.
ABI, object layout and collector protocol remain unchanged.

## Preserve normalization at every operation

Integer payloads are signed 61-bit values. Actual integer/integer child operands
complete their operation with existing precision and wrap behavior before
conversion to double. Earlier conversion would lose cancellation above 2^53.

A floating child still reproduces normalization followed by unboxing. Integral
results undergo the same tag/untag sequence, including signed61 wrap, before
conversion for the parent. The existing normalizer maps NaN through its
unordered integer branch to zero; the new path preserves this behavior.
The exact binary32 roundtrip probe remains.

Evaluation order, intermediate normalization, signed zero and infinity behavior
remain compatible. Arithmetic is not reassociated or fused. Eligible sites can
allocate less, but runtime guards and fallback code can offset timing gains.

## Separate Python parity fixes

Captured parameters previously encountered a Python shortcut that loaded or
overwrote the cell pointer instead of accessing its payload. A typed captured
float could consequently fail its entry contract. Boxed parameters now use the
existing scoped helpers and write barrier; ordinary parameters retain direct
stack access. This matches the native compiler's existing handling.

A second existing difference concerned arithmetic constant folding: Python kept
NaN from expressions such as `inf - inf`, while native folding and runtime
normalization produced integer zero. Python now normalizes NaN results of unary
minus and numeric `+`, `-`, `*`, `/` to integer zero. Raw float literals and constant-value lookup, FFI and runtime
code are unaffected. Floating remainder remains outside constant folding.

## Validation and measurements

The final source state passed 61 Python unittest cases (58 passed, three platform
or optional-tool skips), the Python and native structural checks, and native
Linux path, executable-mode and incremental-cache regressions.

The portable runner compared 126 images across 42 fixture/configuration cases:
72 Linux images for 24 fixtures, 42 Windows/MinUX images for seven fixtures per
target, and 12 Windows concurrent-GC images for four fixtures. Every case has
identical Python, native monolithic and native MLO bytes. The 24 Linux programs
ran and matched the unchanged first-round native compiler's observable output.
Windows/MinUX programs were not executed on this Linux host.

Coverage includes ten positive boxing functions, over twenty exclusions,
call-free raw-XMM regions, actual forced collections, rooted deeper operands,
integer cancellation above 2^53, signed61 wrap, NaN/Infinity/signed zero,
shadowed builtins, parameter rebinding, implicit-void aliases, existing Error/void
paths, catchable index failures and both Python parity fixes. Twenty additional
constant-evaluation probes distinguish the seven corrected NaN-result cases
from thirteen unchanged controls.

A final Python bootstrap and a native self-rebuild are byte-identical:
65,225,488 bytes. The final Python NaN-fold correction was followed by another
bootstrap, also identical to that self-build.

### Measurement method

Both series use the original source programs, input sizes, seeds and calibration.
The primary suite has 294 correctness runs, including 30 full-size runs, and
330 timed runs: eleven alternating before/after pairs for each of fifteen cases,
with shuffled case order. The separate float series has 54 oracle checks and
110 timed runs: eleven rounds of three MiniLang variants plus C and C++ for two
kernels. Every timed run checks its checksum and its untimed warmup checksum.

Programs use internal `CLOCK_MONOTONIC` timings, a full untimed warmup, the same
balanced eight-seed cycle, default GC, and CPU affinity to CPU 2. Compilation,
startup and printing are outside the timed interval. No other compiler or
benchmark process from this work ran during timings. The shared Linux x86-64 VM
has no controlled frequency/governor or hardware isolation.

Each primary run uses the original MiniLang repeat count. In the separate
cross-language series, each configuration retains its original calibrated
repeat count; results are normalized per kernel call. The C/C++ programs are the
original GCC/G++ 14.2 `-O3 -march=x86-64 -mtune=generic` images, with FP contraction
disabled, no fast-math and no LTO.

### Original fifteen-program comparison

Times are milliseconds per call. Paired speedup is the median of eleven
within-round before/after ratios; it need not equal the ratio of separate time
medians. Values above 1 favor the patch.

| Kernel | n | Before ms | After ms | Paired speedup | Faster pairs | Identical image |
|---|---:|---:|---:|---:|---:|---|
| `byte_copy` | 8388608 | 16.024 | 15.814 | 1.023x | 7/11 | yes |
| `byte_search` | 8388608 | 3.993 | 4.150 | 0.894x | 3/11 | yes |
| `array_scan` | 194470 | 23.034 | 23.210 | 0.997x | 5/11 | yes |
| `array_scatter` | 225245 | 24.830 | 24.425 | 0.968x | 4/11 | yes |
| `sieve` | 1977051 | 16.500 | 17.024 | 0.979x | 4/11 | yes |
| `heapsort` | 82396 | 30.775 | 30.701 | 0.998x | 4/11 | yes |
| `escaped_nodes` | 262144 | 8.038 | 8.212 | 0.991x | 2/11 | yes |
| `int_mix` | 2097152 | 10.809 | 11.034 | 1.002x | 6/11 | yes |
| `branch_mix` | 1909761 | 20.433 | 20.612 | 1.006x | 6/11 | yes |
| `float_recurrence` | 260986 | 31.765 | 26.525 | 1.198x | 11/11 | no |
| `mandelbrot` | 126 | 22.315 | 22.599 | 0.994x | 5/11 | no |
| `recursive_tree` | 1265 | 26.636 | 27.256 | 0.987x | 1/11 | yes |
| `ascii_parse` | 262144 | 25.973 | 25.494 | 1.056x | 7/11 | yes |
| `string_concat` | 7262 | 16.301 | 16.097 | 1.045x | 8/11 | yes |
| `string_builder` | 114195 | 25.127 | 25.509 | 1.000x | 5/11 | yes |

Thirteen byte-identical controls nevertheless show paired ratios from 0.894x to
1.056x. Relative IQR across primary configurations ranges from about 3.7% to
22.8%. Small timing differences in those controls cannot be code improvements
or regressions. The recurrence improvement is supported by all eleven positive
pairs and by the separate ablation series. Mandelbrot's result is inconclusive.

### Separate float ablation

The inference-only variant uses the final Python compiler with exactly
`_opt_emit_float_parent_without_child_box` replaced by a hook returning `False`.
Its builds explicitly disable the object cache. The full variant is verified
byte-for-byte against the native compiler. This isolates materialization elision
without changing the source program or recalibrating workloads.

| Kernel | Before ms | Inference only ms | Full ms | Before/full paired | Inference/full paired |
|---|---:|---:|---:|---:|---:|
| `float_recurrence` | 30.194 | 29.719 | 25.690 | 1.207x (11/11) | 1.189x (11/11) |
| `mandelbrot` | 20.577 | 20.738 | 20.641 | 1.004x (6/11) | 1.012x (7/11) |

Inference alone has a recurrence paired ratio of 1.013x with only seven faster
pairs; it does not establish an isolated runtime gain. Adding boxing elision
has 1.189x paired speedup with all eleven pairs faster. Together, the separate
series gives 1.207x with all eleven pairs faster. Do not mix the absolute medians
of this series with the primary series: they were collected at different times.

Mandelbrot's inference-only and full images are themselves byte-identical.
Their varying timings are an additional control, not evidence of boxing gain.
Only two setup float sites become specialized. The potentially zero divisor in
`scale = 3.0 / toFloat(n)` prevents an unconditional numeric proof for the inner
state, so the inner Mandelbrot loop is not improved by this patch.

### Allocations, GC and emitted code

Separate, untimed diagnostics use the same kernels. For recurrence at seed 12345
and n = 1, 10, 100 and 1000 without collections, the observed object deltas follow
`12*n + 5` before/inference-only and `10*n + 5` with full optimization. Byte deltas
are `288*n + 120` and `240*n + 120`. This is two fewer 24-byte objects per loop
iteration for those inputs, a 16.7% reduction in iteration allocations.

At n=1000 that is 12,005 versus 10,005 objects and 288,120 versus 240,120 bytes.
For eight full-size calls, recurrence collections fall from 71 to 59, with the
same checksum. Mandelbrot remains at 50 collections. Large-run heap/block
*deltas after collection* are not cumulative allocation totals.

The original recurrence emits thirteen specialized float sites in the
inference-only listing and two bounded elision sites in the full listing.
Its final listing also contains the retained cold fallbacks; static label counts
do not represent the number of executed operations. Python/native image parity
connects these listing observations to the measured native images.

| Executable segment | Before bytes | Inference only bytes | Full bytes |
|---|---:|---:|---:|
| `float_recurrence` | 208803 | 205603 | 208291 |
| `mandelbrot` | 70986 | 70826 | 70826 |

The elision guards and cold fallback add 2,688 bytes relative to inference alone,
while the combined recurrence executable segment is still 512 bytes smaller than
before. The measurable allocation and runtime benefit justifies retaining this
bounded version. The earlier extra numeric-add dispatch candidate remains removed.

### Remaining gap to C and C++

These are the same separate-series measurements, normalized per call. Slowdown
is the median of the within-round full-MiniLang/C or C++ time ratios.

| Kernel | Full MiniLang ms | C -O3 ms | C++ -O3 ms | ML/C paired slowdown | ML/C++ paired slowdown |
|---|---:|---:|---:|---:|---:|
| `float_recurrence` | 25.690 | 0.707 | 0.692 | 35.88x | 36.98x |
| `mandelbrot` | 20.641 | 0.637 | 0.634 | 32.55x | 32.13x |

This is a useful local improvement, not C-like floating-point performance.
Tagged values, normalization and remaining intermediate allocations still cost
substantially more in these kernels. Future work includes sound nonzero/range
proofs for Mandelbrot and broader unboxed numeric regions that preserve every
intermediate normalization. Neither is implemented by this change.

## Reproduction and evidence

From the Python repository next to the MiniLang repository:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh ../MiniLangCompilerML/build.sh --compiler "$PWD/mlc_win64.py" \
  --output "$PWD/../MiniLangCompilerML/build/mlc_numeric_flow"
sh ../MiniLangCompilerML/build.sh \
  --compiler "$PWD/../MiniLangCompilerML/build/mlc_numeric_flow" \
  --output "$PWD/../MiniLangCompilerML/build/mlc_numeric_flow_selfhost"
cmp ../MiniLangCompilerML/build/mlc_numeric_flow \
  ../MiniLangCompilerML/build/mlc_numeric_flow_selfhost
python3 tests/check_proven_check_elision.py --python-compiler mlc_win64.py \
  --native-compiler ../MiniLangCompilerML/build/mlc_numeric_flow \
  --output build/numeric_flow_linux.json
python3 tests/check_codegen_structure.py mlc_win64.py
python3 tests/check_codegen_structure.py ../MiniLangCompilerML/build/mlc_numeric_flow
bash ../MiniLangCompilerML/scripts/run_native_linux_regressions.sh \
  ../MiniLangCompilerML/build/mlc_numeric_flow
```

The portable runner also accepts `--target windows-x64 --target minux-x64` and
repeated `--fixture` selections. `--gc-concurrent` is the existing Windows-only
option. These commands check the current compilers. The historical baseline
output comparisons reported above were recorded during evaluation; the public
benchmark wrapper does not replace that compiler for general regression tests.

The [benchmark evidence README](benchmarks/numeric_flow/README.md) links the
original benchmark sources and scripts, raw numerical measurement records and
numeric summaries, with the procedure for baseline, inference-only and full
builds. Its baseline reproduction guarantee covers the fifteen measured
benchmark programs. The first-round numerical results remain separately
available as [summary](benchmarks/proven_checks/summary.json) and
[measurement records](benchmarks/proven_checks/measurements.jsonl).
