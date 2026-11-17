# Guarded nullable numeric candidates and variable float operands

Date: 2026-11-17. Branch: `perf/proven-check-elision`.

This phase extends the bounded float-box optimization from the
[Phase 2 checkpoint](performance_numeric_flow.md). It adds guarded candidates
for potentially void numeric results and permits a stable local or parameter
as the parent operation's right operand. It changes `codegen_expr` and
`codegen_stmt` in each backend: four code-generation files across the Python
and MiniLang repositories. The runtime, Value layout and collector are unchanged.

## Measured result and decision

Keep the bounded extension. On the original Mandelbrot input, the primary
comparison improves from **19.626 to 16.158 ms per call**, with **1.217x paired
median speedup and eleven faster pairs out of eleven**. The separate ablation
reproduces the improvement at **1.209x**, also with all eleven pairs faster.
That corresponds to about **17–18% less elapsed time** in these two series.
Collection-free allocation probes show fewer temporary objects, and the
full-size GC probe falls from 50 to 38 collections.

The comparison baseline is the completed Phase 2 compiler, not pristine
MiniLang or the first-round baseline. Fourteen other primary images are
byte-identical, including the float recurrence. No additional recurrence
speedup or regression follows from their timing differences. The older
Phase 2 recurrence improvement was not remeasured against its original baseline.
The [primary summary](benchmarks/numeric_nullable/primary/summary.json) and
[separate ablation summary](benchmarks/numeric_nullable/float_ablation/summary.json)
contain the numerical results.

## Why guarded candidates are needed

The original Mandelbrot program computes:

```minilang
scale = 3.0 / toFloat(n)
```

An integer parameter contract does not prove that `n` is nonzero. With `n=0`,
the division produces `void`; if the subsequent loops are empty, the function
still returns its original zero checksum. The benchmark's positive input sizes
cannot be treated as a compiler proof about every caller. A later loop condition
also cannot justify an unconditional fact for the earlier division.

This change implements **no new nonzero or range analysis**. Instead, it keeps
the uncertainty visible until an eligible arithmetic expression can check the
actual Values. Even a nonzero divisor would not make `scale` an exact float:
results such as `3.0 / 1.0` normalize to an integer.

## A candidate is not a type guarantee

The separate numeric map from Phase 2 gains the internal label `number?`.
This is an optimization candidate that admits a void result, not a new source
type or permission to use unchecked numeric lowering.

The added rules are deliberately limited:

| Expression or write set | Additional candidate rule |
|---|---|
| `/` with two proven numeric operands | `number?` when the existing ordered, nonzero constant-divisor rule cannot establish a guaranteed numeric result |
| `+`, `-` or `*` with numeric/nullable operands | Preserve `number?` if either operand is nullable |
| Mixed writes containing numeric facts and `number?` | Join to `number?`, never to guaranteed `number` |
| `/` with a nullable operand, `%` or `div` | No new rule |

There is no upgrade to guaranteed `number` after a `+`. The generic operators
have different failure behavior: multiplying or subtracting void can return
void, while a numeric `+` with void creates an Error. Error suppression under
`try` makes a normal-continuation shortcut especially inappropriate here.
The guarded consumer retains the existing behavior on every guard miss.

The legacy fact map is unchanged. Static diagnostics, type queries, operator
resolution, return contracts, integer paths and register promotion keep their
existing inputs. Direct float-pair lowering and the builtin `toFloat` proof do
not accept `number?`. Opaque user-call return annotations, captured or boxed
bindings, globals, synchronized values, optional parameters and ambiguous
lexical bindings remain outside the added proof rules.

## Extend the parent operand without losing integer precision

The existing child-root optimization accepts a bounded expression of the form:

```text
(child_left op child_right) op parent_right
```

Each operation is independently `+`, `-` or `*`. The child still has at most
two binary-operation levels and only primitive literals or ordinary local and
parameter leaves. Source-level calls, indexing, member access, captures and
globals are excluded. Folded children and statically integer-only children keep
their existing lowering.

`parent_right` may now be an eligible local or parameter with a `float`,
`number` or `number?` candidate, in addition to the existing float literal.
The new runtime guard accepts only an **actual float Value**, either immediate
binary32 or boxed binary64. It executes before all child guards and before any
child arithmetic. An actual integer, void or other tag selects the complete
original expression.

That integer fallback is necessary. The child may normalize to an integer above
2^53; converting it to double before an integer/integer parent operation would
lose precision. The fallback preserves exact integer arithmetic and signed61
wrapping. The successful float path retains the existing exact integer/integer
child computation and the complete floating-child normalization before the
parent consumes it. Arithmetic is not reassociated or fused.

All local child leaves are checked too. A nullable candidate contributes no
unchecked assumption: its actual tag must be integer or float. Once every
guard passes, the bounded primitive tree is numeric. The same guarded path is
therefore eligible inside `try`; a miss uses the original expression with its
original suppression context. This does not enable the separate unguarded
numeric-pair extension under `try`.

## One child root, with the same GC boundary

Only the selected child root avoids materialization. Deeper operands retain
ordinary rooted Value evaluation, including any allocations they require.
The right-hand local remains a normal root while those operands execute and is
loaded again after their possible GC safepoints. An earlier raw pointer or
double is not carried across that work.

After the child normalization boundary, its value lives in an XMM register only
until the parent consumes it. The permitted right-operand load cannot call or
allocate. The parent then performs its usual normalization and materialization.
No raw double occupies a GC root slot or crosses a call. Signed61 intermediate
wrap, existing NaN-to-zero normalization, binary32 exactness, signed zero and
infinity behavior remain part of the required semantics.

This is not a broader unboxed numeric region. More aggressive elision would
need to preserve both exact tagged integers and floating intermediates across
each additional operation and allocation boundary.

## Validation

The final Python unittest gate ran **61 tests: 58 passed and three were
skipped** for platform or optional-tool reasons. Both structural code-generation
checks and the native Linux regressions passed. The Python bootstrap and native
self-rebuild are byte-identical at **65,307,408 bytes**.

The targeted portable matrix covers the three new fixtures and the existing
`numeric_typeflow_boxing` fixture. All **12 images** match byte-for-byte across
Python, native monolithic and native MLO compilation. All **four Linux programs**
run successfully and match the unchanged Phase 2 native baseline's output.

| Fixture or check | Coverage |
|---|---|
| `numeric_nullable_boxing.ml` | Nullable division, aliases, mixed writes, loop backedges, empty loops, a small copy of the original Mandelbrot recurrence, and RHS float/int/void behavior |
| `numeric_nullable_typeof.ml` | Observable custom guards that approve non-float Values; annotations cannot prove their own runtime tags |
| `numeric_nullable_tofloat.ml` | User-defined and rebound `toFloat` calls remain outside builtin conversion proofs |
| Existing `numeric_typeflow_boxing.ml` | Earlier precision, normalization, captured-parameter, Error/void and GC cases remain unchanged |
| Structural positive checks | 16 functions use the new guarded RHS path; the RHS guard precedes child work and raw-XMM regions contain no call |
| Structural negative checks | 20 functions retain their exclusions; none of the earlier negative assertions was weakened |
| Exact numeric boundaries | Integer cancellation above 2^53, integer RHS after signed61 wrap, and floating child normalization before its parent |
| Error and effect boundaries | Error 1200, entry-contract Error 1308, captured Error continuations under `try`, read-before-numeric-initialization and left-to-right side effects |
| Special values and GC | NaN, both infinities, signed zero, immediate and boxed subnormals, plus 64 forced-GC iterations that retain final results and collect during deeper operand evaluation |

The full portable matrix has **52 configurations and 156 compared images**.
Every configuration has identical Python, native monolithic and native MLO
bytes:

| Configuration group | Cases | Images | Execution on this Linux host |
|---|---:|---:|---|
| Linux | 27 | 81 | All 27 pass and match the unchanged Phase 2 baseline output |
| Windows and MinUX | 20 | 60 | Compile and byte-parity checks only |
| Windows with concurrent GC | 5 | 15 | Compile and byte-parity checks only |

The original fifteen-program preparation passed **294 correctness runs**,
including 30 full-size runs. The separate float preparation passed **72 oracle
checks**; all **40 untimed GC probes** preserve the corresponding checksums.

## Measurement method and limits

The two series retain the original sources, sizes, seeds, calibration and
checksum oracles. There are **462 timed runs**: 330 primary runs, comprising
eleven before/after rounds for fifteen kernels, plus 132 separate float runs,
comprising eleven rounds of six variants for two kernels. Every timed checksum
and untimed warmup checksum is valid.

Each process performs a full untimed warmup followed by its original repeat
count and the same balanced eight-seed cycle beginning at 12345. It reads
`CLOCK_MONOTONIC` inside the program. Compilation, startup and result printing
are outside the timed interval. Primary before/after pairs retain the same
MiniLang repeat count. The separate cross-language series retains each
language's original repeat count and normalizes times per kernel call.

The primary runner shuffles kernel order and alternates AB/BA order within a
round. The separate float runner rotates and reverses the six-variant order.
All timed processes are pinned to CPU 2. No other compiler or benchmark process
from this evaluation runs during timing. The shared Linux x86-64 virtual
machine has uncontrolled CPU frequency and unrelated host load; it is not an
isolated hardware benchmark.

Paired speedup is the median of within-round before/after time ratios. It need
not equal the ratio of the separate time medians. A ratio above 1 favors the
patch. Relative IQR is IQR divided by the median. Absolute times from the
primary and separate series must not be pooled, nor combined with the older
Phase 2 series as though they were simultaneous measurements.

### Original fifteen-program comparison

Times are milliseconds per call. The
[primary records](benchmarks/numeric_nullable/primary/measurements.jsonl) and
[summary](benchmarks/numeric_nullable/primary/summary.json) retain the full
precision and all paired observations.

| Kernel | n | Before ms | After ms | Paired speedup | Faster pairs | Identical image |
|---|---:|---:|---:|---:|---:|---|
| `byte_copy` | 8388608 | 13.930 | 13.681 | 0.995x | 5/11 | yes |
| `byte_search` | 8388608 | 3.375 | 3.401 | 0.990x | 4/11 | yes |
| `array_scan` | 194470 | 20.459 | 20.196 | 0.996x | 5/11 | yes |
| `array_scatter` | 225245 | 22.556 | 22.166 | 1.010x | 7/11 | yes |
| `sieve` | 1977051 | 14.157 | 14.223 | 1.000x | 6/11 | yes |
| `heapsort` | 82396 | 27.099 | 27.207 | 0.995x | 5/11 | yes |
| `escaped_nodes` | 262144 | 6.841 | 6.889 | 1.010x | 7/11 | yes |
| `int_mix` | 2097152 | 9.684 | 9.593 | 1.004x | 7/11 | yes |
| `branch_mix` | 1909761 | 18.397 | 18.340 | 1.013x | 8/11 | yes |
| `float_recurrence` | 260986 | 22.970 | 23.533 | 0.981x | 2/11 | yes |
| `mandelbrot` | 126 | 19.626 | 16.158 | 1.217x | 11/11 | no |
| `recursive_tree` | 1265 | 23.866 | 24.144 | 1.000x | 5/11 | yes |
| `ascii_parse` | 262144 | 21.810 | 22.152 | 0.996x | 5/11 | yes |
| `string_concat` | 7262 | 13.590 | 13.256 | 1.005x | 6/11 | yes |
| `string_builder` | 114195 | 22.009 | 22.100 | 0.996x | 4/11 | yes |

The fourteen byte-identical controls have paired medians from **0.981x to
1.013x**. Their variation cannot establish a generated-code improvement or
regression. In particular, the recurrence's 0.981x primary ratio describes
identical images. Relative IQR across all primary configurations ranges from
about **2.63% to 9.85%**. Mandelbrot's improvement is larger, appears in all
eleven pairs, and is reproduced by the separate ablation.

### Separate float ablation

The six variants are:

- `before`: the completed Phase 2 compiler.
- `nullable_only`: the new candidates with the box-elision hook restricted to
  literal float right operands.
- `rhs_only`: variable right operands with `number?` local facts removed from
  the extended function map.
- `after`: the full Phase 3 change, verified byte-for-byte between Python and
  the native compiler.
- `c_o3` and `cpp_o3`: the original GCC/G++ 14.2.0 C11/C++17 kernels and separate
  driver, with `-O3 -march=x86-64 -mtune=generic -ffp-contract=off -fno-fast-math`
  and no LTO.

The ablation builds disable the object cache. They isolate these features on
the specified workloads without changing benchmark source or recalibrating
repeat counts. The [diagnosis script and reproduction procedure](benchmarks/numeric_nullable/README.md)
describe the exact hooks. Medians below are milliseconds per kernel call.

| Kernel | Before | Nullable only | RHS only | Full | C -O3 | C++ -O3 |
|---|---:|---:|---:|---:|---:|---:|
| `float_recurrence` | 23.143 | 23.361 | 22.941 | 22.971 | 0.647 | 0.644 |
| `mandelbrot` | 19.625 | 19.724 | 19.876 | 16.111 | 0.579 | 0.613 |

| Kernel | Before/full paired | Nullable-only/full paired | RHS-only/full paired |
|---|---:|---:|---:|
| `float_recurrence` | 1.005x (6/11) | 1.009x (7/11) | 1.000x (5/11) |
| `mandelbrot` | 1.209x (11/11) | 1.230x (11/11) | 1.205x (11/11) |

Mandelbrot's `before`, `nullable_only` and `rhs_only` images are identical.
Both features are needed together to change this workload's emitted code.
The full change is faster in every pair against each of those three variants.
All four recurrence images are identical, so their differences are another
noise control. This phase establishes no additional recurrence speedup.
Full numerical observations are in the
[ablation records](benchmarks/numeric_nullable/float_ablation/measurements.jsonl)
and [summary](benchmarks/numeric_nullable/float_ablation/summary.json).

The remaining gap to C/C++ is substantial. Within this same separate series,
the paired full-MiniLang/C and C++ slowdowns are **28.14x and 26.51x** for
Mandelbrot, and **35.14x and 35.08x** for the recurrence. These are local kernel
comparisons, not general language rankings or C-like performance claims.

## Untimed allocation and emitted-code observations

Only Mandelbrot changes among the fifteen original before/after program images.
Its executable segment grows from **70,826 to 73,322 bytes**, an increase of
**2,496 bytes** for the additional guards and retained fallback paths. The
recurrence remains at **208,291 bytes**. The
[code summary](benchmarks/numeric_nullable/float_ablation/code_summary.json)
records the corresponding ablation observations.

The following Mandelbrot probes each perform one call with seed 12345 and no
collections. Both single-feature variants have the same counts as `before`.
Object counts are block-counter deltas; bytes are allocation-frontier growth.

| n | Checksum | Before objects | Full objects | Before bytes | Full bytes |
|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 5 | 5 | 120 | 120 |
| 3 | 177 | 1379 | 1043 | 33096 | 25032 |
| 5 | 268 | 2132 | 1646 | 51168 | 39504 |
| 17 | 5264 | 42028 | 32078 | 1008672 | 769872 |

At n=17, both allocation deltas fall by about **23.7%**. The n=1 control is
unchanged. These are observations for the specified inputs, not a universal
allocation formula.

For **eight full-size Mandelbrot calls at n=126**, collections fall from
**50 to 38**, with the same checksum, **2,227,976**. The original recurrence
remains at **59 collections** for its eight-call probe. These diagnostics are
separate untimed programs. Heap or block deltas after collection are net changes,
not cumulative allocation totals. The
[40 GC records](benchmarks/numeric_nullable/float_ablation/gc_diagnostics.json)
retain all four variants and all probe sizes.

The [Phase 3 evidence README](benchmarks/numeric_nullable/README.md) provides
the exact commands, public numeric observations and diagnosis script. It reuses
the [original benchmark sources and oracles](benchmarks/numeric_flow/suite/).
The [Phase 2 evidence](benchmarks/numeric_flow/README.md) remains a separately
versioned historical checkpoint. The allocation reduction and two consistent
timing series support the additional code-size cost for this bounded extension;
they do not establish a general MiniLang speedup.

## Reproduce the semantic checks

From `MiniLangCompilerPy`, with the matching `MiniLangCompilerML` checkout beside
it, build the current source and run the focused matrix:

```sh
sh ../MiniLangCompilerML/build.sh --compiler "$PWD/mlc_win64.py" \
  --output "$PWD/../MiniLangCompilerML/build/mlc_numeric_nullable"
sh ../MiniLangCompilerML/build.sh \
  --compiler "$PWD/../MiniLangCompilerML/build/mlc_numeric_nullable" \
  --output "$PWD/../MiniLangCompilerML/build/mlc_numeric_nullable_selfhost"
cmp ../MiniLangCompilerML/build/mlc_numeric_nullable \
  ../MiniLangCompilerML/build/mlc_numeric_nullable_selfhost

python3 tests/check_proven_check_elision.py --python-compiler mlc_win64.py \
  --native-compiler ../MiniLangCompilerML/build/mlc_numeric_nullable \
  --target linux-x64 \
  --fixture numeric_nullable_boxing --fixture numeric_nullable_typeof \
  --fixture numeric_nullable_tofloat --fixture numeric_typeflow_boxing \
  --output build/numeric_nullable_targeted.json
```

The optional `--baseline-compiler` argument compares observable output against
a separately built Phase 2 compiler. The exact historical commits are listed
in the [Phase 2 reproduction instructions](benchmarks/numeric_flow/README.md).
Omitting the argument checks the current program assertions and compiler-image
parity; it does not claim a fresh comparison with a historical binary.
