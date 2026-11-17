# Guarded float expression trees — Phase 4 checkpoint

Date: 2026-11-17. Branch: `perf/proven-check-elision`.

**Historical version scope.** This report describes the completed Phase 4
checkpoint. Its measurements, validation totals and references to the full
compiler apply to these public commits:

| Repository | Phase 4 commit |
|---|---|
| MiniLangCompilerPy | `6a953bb4f7f51947ba149fd64e2cbbdcefb17876` |
| MiniLangCompilerML | `ddc67c9c4f9c5828101e884076915f6536a3942c` |

Select both commits to reproduce this source state. The pull requests continue
with [Phase 5: guarded float loops](performance_float_loops.md). Each phase
retains its own comparison baseline and measurement series.

This fourth optimization round removes intermediate float materializations
inside bounded, pure arithmetic expressions. It also lets a comparison consume
such an expression without constructing its final numeric Value. The Python
and MiniLang backends implement the same guards, expression order and fallback
rules. The runtime Value layout, collector and numeric type inference are
unchanged by this round.

## Comparison boundary

The comparison baseline is the completed
[Phase 3 checkpoint](performance_numeric_nullable.md):

| Repository | Baseline revision |
|---|---|
| MiniLangCompilerPy | `45f63f6ef125863003cd6e2959916635f34a72ec` |
| MiniLangCompilerML | `a96f41f6396e3bbaf841643d9a174c1a39902ada` |

It already includes the earlier proven-check, numeric-flow and nullable/RHS
optimizations. The observations for this round belong to this baseline and
must be kept separate from the older measurement series. The original fifteen
benchmark programs, input sizes, repeat counts and checksum oracles are retained.

## Measured result and decision

Keep both bounded extensions. Against the completed Phase 3 compiler, the
primary series gives **2.694x paired median speedup for the float recurrence**
and **1.466x for Mandelbrot**, with **all eleven pairs faster for each kernel**.
These correspond to about **62.9% and 31.8% less elapsed time**, respectively.
The separate six-variant series confirms **2.712x and 1.484x**, again with all
eleven before/full pairs faster.

The allocation probes show the corresponding reduction in temporary objects.
The recurrence's arithmetic-only image equals the full image; comparison-only
equals its baseline. Mandelbrot benefits from both kinds of root: each partial
variant improves on the baseline in every pair, and the combined variant also
beats each partial variant in all eleven pairs. Thirteen other primary images
are byte-identical and provide noise controls rather than additional compiler
speedups. The [primary summary](benchmarks/float_trees/primary/summary.json) and
[separate summary](benchmarks/float_trees/float_ablation/summary.json) retain the
full precision and all component comparisons.

## Why the previous boundary still materialized floats

The original recurrence contains expressions such as:

```minilang
nextX = x * 0.9999991 + y * 0.0000003 + 0.0000007
accumulated = accumulated + x * 0.333333333333333 + y * 0.142857142857143
```

The preceding optimizer could avoid one child root's box when its parent had an
eligible literal or local right operand. Deeper operands retained ordinary
rooted Value evaluation. Consequently, both products in `nextX` still
materialized, and the binary right operand of the accumulated expression
remained outside that optimization.

Mandelbrot supplies two related cases:

```minilang
zi = 2.0 * zr * zi + cy
```

and the numeric part of its loop condition:

```minilang
zr2 + zi2 <= 4.0
```

The first expression can contain more than one removable intermediate. The
second has a Boolean consumer, so its numeric intermediate need not be stored
at all. These are opportunities in the unchanged benchmark source; estimates
from counting expression nodes are not measured speedups or allocation totals.

## Eligibility is deliberately bounded

The new hook runs before the preceding child-root optimization. The surrounding
emitter retains its existing constant folding and operator-overload resolution.

| Property | Accepted boundary |
|---|---|
| Arithmetic operations | `+`, `-`, `*` |
| Arithmetic root | At least two arithmetic nodes |
| Comparison root | `==`, `!=`, `<`, `<=`, `>` or `>=`, with at least one arithmetic node in its operands |
| Total arithmetic nodes | At most seven, excluding the comparison itself |
| Arithmetic depth | At most three levels; a comparison root does not add an arithmetic level |
| Simultaneously saved left operands | At most two nonleaf right-subtree evaluations |
| Literal leaves | Float literals only |
| Variable leaves | Ordinary nonboxed locals or parameters, with an existing `float`, `number` or `number?` candidate |
| Constant-only binary subtree | Rejected to preserve the existing folded Value and its normalization |

Calls, indexing, member access, global or synchronized variables, captured or
boxed bindings, optional or unknown facts, integer literals and statically
integer leaves do not enter the new path. Larger rejected trees can still
contain smaller eligible expressions reached by ordinary recursive emission.
A compiler candidate does not become a source-language type or a stronger fact
for any other optimization.

## All leaves must be actual floats

Before evaluating arithmetic, the emitted guard checks every distinct local
leaf in left-to-right source order. It accepts an immediate binary32 float or a
boxed binary64 float. An integer, void, Error or other Value takes the ordinary
expression path, even when its compile-time candidate was `number` or
`number?`.

This is stronger than accepting arbitrary numeric tags. It ensures each first
operation on the fast path has floating operands and avoids converting two
large tagged integers to doubles before their exact arithmetic is complete.
Repeated occurrences of the same local use one guard. The accepted tree has no
calls, captured cells or shared bindings that could modify those locals between
the guard and their later loads.

Float annotations are not treated as sufficient evidence by themselves.
Eligibility retains the existing proof boundaries for user-defined checking
functions, and every eligible variable is additionally checked for an actual
float at runtime.

## An intermediate may cease to be a float

MiniLang normalizes each floating arithmetic result. An exact integer can
become a tagged signed61 integer, with the existing wrap behavior; the
normalizer's unordered branch also handles NaN. Simply keeping every
intermediate as a double would change later integer/integer operations.

The new path checks the ordinary normalizer's integer decision after every
non-root arithmetic operation. It uses the same truncating conversion, reverse
conversion and unordered/equal comparison. If that branch would be taken, the
entire current expression returns to ordinary emission. This includes both
exact integer results and NaN.

A surviving intermediate is still a float. Its existing binary32 exactness
probe executes, preserving the normalizer's conversion and comparison
operations, while the value remains in an XMM register. Both the exact binary32
and boxed binary64 representations would unbox to that same value. No arithmetic
is reassociated or fused, and every operation follows the original parentheses
and left-to-right evaluation order.

This fallback is possible because the attempted tree performs no source-level
effect or allocation. Recomputing its arithmetic cannot duplicate a call, store,
indexing effect or collector event. An actual integer intermediate is handled
by the ordinary representation before another operation can consume it. This
preserves cancellation above 2^53, signed61 intermediate wrap, NaN normalization,
and the existing Error/void behavior.

## Raw values have a short, call-free lifetime

The result of each visited subtree is in XMM0. A primitive right operand loads
directly into XMM1. For a nonleaf right operand, the completed left result is
saved in XMM4 or XMM5 while the right subtree uses XMM0–XMM3. The planner rejects
any expression requiring a third saved left value. XMM6 and above are not used,
which also avoids their Windows preservation requirements.

No raw double is stored in a slot the collector scans as a tagged root. There
is no call or allocation between the first raw operation and the root consumer.
All source Values remain ordinary locals or parameters outside that interval.
At an arithmetic root, only the final result undergoes ordinary normalization
and possible materialization; all other raw results are dead before it can
allocate. This retains the established collector boundary without extending
unboxed values across statements, loop iterations or safepoints.

A comparison root instead performs the existing unordered-aware comparison
on its two operands and returns a tagged Boolean. Equality, inequality and
ordered comparisons retain their separate NaN rules. Non-root arithmetic
results must still survive the normalization guard before reaching that
comparison.

## Fallback and coexistence with previous optimizations

A missed leaf or intermediate guard uses ordinary binary-expression emission
with the new tree hook disabled at the current root. The preceding child-root
box optimization remains available there. Its own fallback disables both
root hooks, preventing compiler recursion. Ordinary recursive emission may
still optimize smaller eligible subtrees.

The same rules apply under `try`: a failed guard reaches the original
suppression context, while successful guards leave only total primitive float
arithmetic and comparisons. This round adds no division, range or nonzero
analysis and changes no return contracts or static diagnostics.

## Validation

All final gates passed. The Python unittest gate ran **61 tests: 58 passed and
three were skipped** for platform or optional-tool reasons. Both structural
code-generation checks and the native Linux regression suite passed. The Python
bootstrap and native self-rebuild are byte-identical at **65,549,104 bytes**.

The portable matrix covers **64 configurations and 192 program images**. In
each configuration, Python, native monolithic and native MLO compilation
produce identical bytes:

| Configuration group | Cases | Images | Execution on this Linux host |
|---|---:|---:|---|
| Linux | 30 | 90 | All 30 pass and match the frozen Phase 3 baseline output |
| Windows and MinUX | 26 | 78 | Compilation and byte parity only |
| Windows with concurrent GC | 8 | 24 | Compilation and byte parity only |

Three new portable fixtures accompany the implementation:

| Fixture | Coverage |
|---|---|
| `numeric_float_tree.ml` | Balanced and nested trees, the seven-node/register boundary, arithmetic and all six comparisons, normalization fallbacks, nullable candidates, numeric edge cases, effect exclusions and retained results around GC |
| `numeric_float_tree_typeof.ml` | Observable user-defined type guards that approve non-float Values |
| `numeric_float_tree_tofloat.ml` | User-defined and rebound conversion functions remain outside builtin proofs |

Reference functions materialize operations separately with untyped operands.
They compare result tags and values, and Error codes/messages where relevant.
Structural checks cover **19 positive functions and 28 excluded functions** in
the main fixture, with additional exclusions in the shadowed-builtin fixtures.
They distinguish pre-arithmetic leaf guards, intermediate normalization guards,
call-free raw regions, absence of raw stack/root stores, final materialization
and fallback paths. The seven-node case exercises XMM5; a four-level root can
only optimize eligible smaller descendants. The GC stress performs **64
iterations**, verifies that a collection actually occurred, and checks retained
heap-backed inputs, results and surrounding expression roots afterward.

The original fifteen-program preparation passed **294 correctness runs**,
including **30 full-size runs**. The separate float preparation passed **72
oracle checks**, and all **40 untimed GC probes** preserve their corresponding
checksums. The [validation summary](benchmarks/float_trees/validation_summary.json)
records the successful gates and platform-execution limits.

## Measurement and ablation

The primary comparison uses the original fifteen programs against the frozen
Phase 3 baseline. A separate float series distinguishes these variants:

| Variant | Enabled expression-tree paths |
|---|---|
| `before` | Frozen Phase 3 compiler |
| `arithmetic_only` | New arithmetic roots; new comparison roots disabled |
| `comparison_only` | New comparison roots; new arithmetic roots disabled |
| `after` | Both new root kinds |
| `c_o3` | Original C kernel and separate driver |
| `cpp_o3` | Original C++ kernel and separate driver |

A separate `tree_disabled` build turns off the new hook and checks byte identity
against the frozen baseline. It is a generated-code control, not an additional
timed language variant. The partial-feature wrappers keep all preceding
optimizations and disable the object cache. Their exact behavior is documented
by the [diagnosis script and reproduction procedure](benchmarks/float_trees/README.md).

The protocol retains `CLOCK_MONOTONIC` inside each process, a full untimed
warmup, the balanced eight-seed cycle beginning at 12345, original repeat counts
and checksum verification. Compilation, process startup and result printing
are outside the timed interval. Cross-language times are normalized per kernel
call because their original repeat counts differ.

The primary series shuffles kernel order and pairs before/after runs in AB/BA
order. The separate series rotates the six variants once per two rounds and
reverses the second round of each pair. Over eleven rounds, every variant visits
every ordinal position once or twice, and every pair appears in each relative
order five or six times. This schedule was checked before timing. Ratios are
paired within rounds and then summarized; a paired median ratio need not equal
the ratio of separate time medians.

Timed programs run pinned to CPU 2 on a shared Linux x86-64 virtual machine.
No other compiler, test or benchmark job from this evaluation runs during the
timing interval. Host load and CPU frequency are uncontrolled. The thirteen
byte-identical primary images provide controls for that variability. C/C++ use
the original GCC/G++ 14.2.0 images, C11/C++17, `-O3 -march=x86-64 -mtune=generic`,
`-ffp-contract=off -fno-fast-math`, separate translation units and no LTO.
Absolute medians from the primary, separate and historical series must not be
pooled as though they were simultaneous observations.

Allocation and collection probes run separately from timing. Collection-free
block deltas and allocation-frontier growth describe the specified calls.
After a collection, heap/block deltas are net changes rather than cumulative
allocations. Static code sites include cold fallback copies and are not dynamic
object counts. The measured implementation decision must account for the extra
guards and fallback code as well as any reduction in allocation.

## Timing results

All **462 timed runs** completed with valid measured and warmup checksums:
**330 primary runs** across fifteen kernels and **132 separate float runs**
across two kernels and six variants. Every configuration has eleven rounds.
No observations were selected or omitted because of their measured speed.

### Original fifteen-program comparison

Times are milliseconds per kernel call. Paired speedup is the median of the
within-round before/after ratios; values above one favor the patch. The
[primary records](benchmarks/float_trees/primary/measurements.jsonl) and
[summary](benchmarks/float_trees/primary/summary.json) retain every observation.

| Kernel | n | Before ms | After ms | Paired speedup | Faster pairs | Identical image |
|---|---:|---:|---:|---:|---:|---|
| `byte_copy` | 8388608 | 14.584 | 14.143 | 1.044x | 6/11 | yes |
| `byte_search` | 8388608 | 3.403 | 3.842 | 0.945x | 3/11 | yes |
| `array_scan` | 194470 | 20.543 | 20.612 | 0.985x | 4/11 | yes |
| `array_scatter` | 225245 | 23.342 | 22.620 | 1.013x | 7/11 | yes |
| `sieve` | 1977051 | 14.384 | 14.099 | 1.002x | 6/11 | yes |
| `heapsort` | 82396 | 27.659 | 27.023 | 1.009x | 6/11 | yes |
| `escaped_nodes` | 262144 | 6.782 | 6.804 | 0.998x | 5/11 | yes |
| `int_mix` | 2097152 | 9.762 | 9.736 | 1.003x | 7/11 | yes |
| `branch_mix` | 1909761 | 18.328 | 18.430 | 0.982x | 4/11 | yes |
| `float_recurrence` | 260986 | 23.820 | 8.715 | 2.694x | 11/11 | no |
| `mandelbrot` | 126 | 16.798 | 11.394 | 1.466x | 11/11 | no |
| `recursive_tree` | 1265 | 24.267 | 24.163 | 1.013x | 7/11 | yes |
| `ascii_parse` | 262144 | 22.316 | 22.314 | 1.005x | 6/11 | yes |
| `string_concat` | 7262 | 14.103 | 13.902 | 1.023x | 8/11 | yes |
| `string_builder` | 114195 | 22.755 | 22.549 | 1.011x | 7/11 | yes |

The thirteen byte-identical controls have paired median ratios from **0.945x
to 1.044x**. They cannot establish a generated-code improvement or regression.
In particular, `byte_search` has substantial variability despite identical
images. Relative IQR, defined as IQR divided by median, ranges from **3.24% to
31.36%** across the primary configurations. The recurrence's before/after
relative IQR is **6.39% / 4.88%**; Mandelbrot's is **9.58% / 6.21%**.

Every recurrence pair favors the new image, with speedups from **2.558x to
2.887x**. Every Mandelbrot pair also favors it, from **1.394x to 1.622x**.
The separate series below reproduces both improvements under a different
variant order. This supports the workload-specific conclusion despite the
shared-host variability; it does not make the machine an isolated benchmark.

### Separate arithmetic/comparison ablation

Medians are milliseconds per kernel call. The six variants use the same input
sizes as the primary series, and each retains its original per-language repeat
count. The [separate records](benchmarks/float_trees/float_ablation/measurements.jsonl)
and [summary](benchmarks/float_trees/float_ablation/summary.json) provide full
precision, dispersion and every paired ratio.

| Kernel | Before | Arithmetic only | Comparison only | Full | C -O3 | C++ -O3 |
|---|---:|---:|---:|---:|---:|---:|
| `float_recurrence` | 24.601 | 8.930 | 23.978 | 8.880 | 0.693 | 0.687 |
| `mandelbrot` | 16.692 | 14.464 | 14.305 | 11.252 | 0.625 | 0.618 |

Each cell below gives the median paired ratio, followed by the number of ratios
above one. For example, `arithmetic/full` compares the arithmetic-only image
with the full image in the same round.

| Kernel | Before/arithmetic | Before/comparison | Arithmetic/full | Comparison/full | Before/full |
|---|---:|---:|---:|---:|---:|
| `float_recurrence` | 2.720x (11/11) | 1.010x (9/11) | 0.994x (5/11) | 2.713x (11/11) | 2.712x (11/11) |
| `mandelbrot` | 1.171x (11/11) | 1.162x (11/11) | 1.279x (11/11) | 1.251x (11/11) | 1.484x (11/11) |

For the recurrence, arithmetic-only and full are byte-identical, while
comparison-only and before are byte-identical. The **0.994x arithmetic/full**
and **1.010x before/comparison** observations describe those identity controls,
not a benefit or penalty from comparison lowering. All meaningful changed-image
recurrence comparisons are faster in every pair.

For Mandelbrot, each partial change is faster than before in **11/11 pairs**.
The full combination is also faster than arithmetic-only and comparison-only
in **11/11 pairs** each. The separately measured before/full ratios, **2.712x**
for the recurrence and **1.484x** for Mandelbrot, confirm the primary result.
The primary and separate medians are not pooled, and older phase ratios are
not multiplied to claim a cumulative release-versus-current speedup.

### Remaining comparison with C and C++

Within this same separate series, the paired ratios of full MiniLang time to
C/C++ time remain:

| Kernel | Full MiniLang / C -O3 | Full MiniLang / C++ -O3 |
|---|---:|---:|
| `float_recurrence` | 12.82x | 12.91x |
| `mandelbrot` | 18.33x | 18.45x |

The new path reduces a specific source of dynamic arithmetic overhead; a
substantial gap remains. These ratios apply to the two kernels, compiler flags
and shared-VM conditions recorded here, not to arbitrary MiniLang programs or
a general ranking of the languages.

## Untimed allocation and generated-code results

Only `float_recurrence` and `mandelbrot` change among the original fifteen
program images. The other **thirteen before/after images are byte-identical**.
All fifteen new native images match the Python compiler byte-for-byte. For both
float kernels, disabling the new hook reproduces the frozen Phase 3 image
exactly. That control isolates the new emission paths from the historical
baseline without changing benchmark or import paths.

### Collection-free probes

Each row below is one kernel call with seed 12345 and no collection. Object
counts are block-counter deltas; bytes are allocation-frontier growth. Every
variant produces the listed checksum. These are actual diagnostic runs, not
estimates from expression-tree shape.

| Kernel | n | Checksum | Before objects | Arithmetic only | Comparison only | Full objects | Before bytes | Full bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `float_recurrence` | 1 | 187 | 15 | 8 | 15 | 8 | 360 | 192 |
| `float_recurrence` | 10 | 1873 | 105 | 35 | 105 | 35 | 2520 | 840 |
| `float_recurrence` | 100 | 18733 | 1005 | 305 | 1005 | 305 | 24120 | 7320 |
| `float_recurrence` | 1000 | 187433 | 10005 | 3005 | 10005 | 3005 | 240120 | 72120 |
| `mandelbrot` | 1 | 1 | 5 | 5 | 4 | 4 | 120 | 96 |
| `mandelbrot` | 3 | 177 | 1043 | 875 | 868 | 700 | 25032 | 16800 |
| `mandelbrot` | 5 | 268 | 1646 | 1403 | 1380 | 1137 | 39504 | 27288 |
| `mandelbrot` | 17 | 5264 | 32078 | 27103 | 26864 | 21889 | 769872 | 525336 |

At recurrence n=1000, the full path removes **7,000 objects and 168,000 bytes**,
about **70.0%** of the corresponding before deltas. Across these four specified
sizes, the observed counts are `10*n + 5` before and `3*n + 5` after. This local
pattern describes the recorded seed and sizes; it is not a universal allocation
formula. Arithmetic-only and full recurrence images are byte-identical, as are
comparison-only and before. The comparison path has no eligible site in this
kernel.

At Mandelbrot n=17, the full path removes **10,189 objects and 244,536 bytes**,
about **31.8%** of the before deltas. The partial variants show both contributions:
arithmetic-only removes 4,975 objects, comparison-only removes 5,214. Both
reductions appear in the combined variant. At n=1, the arithmetic-only count
stays at five while the comparison/full count is four.

### Full-size collection probes

These probes make eight calls with the original full-size input and seed 12345.
They are separate from timing and use the default collector settings.

| Kernel | n | Checksum | Before collections | Arithmetic only | Comparison only | Full collections |
|---|---:|---:|---:|---:|---:|---:|
| `float_recurrence` | 260986 | 443985351 | 59 | 17 | 59 | 17 |
| `mandelbrot` | 126 | 2227976 | 38 | 32 | 32 | 26 |

The recurrence falls from **59 to 17 collections**; Mandelbrot falls from
**38 to 26**. Heap and block deltas after these collections are net changes.
They cannot be read as total allocations or used as a substitute for the
collection-free observations. All **40 untimed records** are retained in the
[GC observations](benchmarks/float_trees/float_ablation/gc_diagnostics.json).

### Code size and fallback cost

| Kernel | Before text bytes | Arithmetic only | Comparison only | Full | Full increase |
|---|---:|---:|---:|---:|---:|
| `float_recurrence` | 208291 | 212515 | 208291 | 212515 | 4224 bytes, 2.03% |
| `mandelbrot` | 73322 | 75114 | 73802 | 75562 | 2240 bytes, 3.06% |

These are executable-segment sizes. The extra guards and retained ordinary
paths increase code size even though they reduce allocations in the recorded
probes. Static markers include smaller trees in cold fallback branches and
must not be equated with objects saved on each iteration. The
[code summary](benchmarks/float_trees/float_ablation/code_summary.json) records
the byte-identity controls and emitted sites.

## Reproduce the semantic checks

From `MiniLangCompilerPy`, with both repositories at the Phase 4 commits listed
in the historical version scope above and `MiniLangCompilerML` beside it:

```sh
sh ../MiniLangCompilerML/build.sh --compiler "$PWD/mlc_win64.py" \
  --output "$PWD/../MiniLangCompilerML/build/mlc_float_trees"
sh ../MiniLangCompilerML/build.sh \
  --compiler "$PWD/../MiniLangCompilerML/build/mlc_float_trees" \
  --output "$PWD/../MiniLangCompilerML/build/mlc_float_trees_selfhost"
cmp ../MiniLangCompilerML/build/mlc_float_trees \
  ../MiniLangCompilerML/build/mlc_float_trees_selfhost

python3 tests/check_proven_check_elision.py --python-compiler mlc_win64.py \
  --native-compiler ../MiniLangCompilerML/build/mlc_float_trees \
  --target linux-x64 \
  --fixture numeric_float_tree --fixture numeric_float_tree_typeof \
  --fixture numeric_float_tree_tofloat \
  --output build/float_tree_targeted.json
```

Use the optional `--baseline-compiler` argument for observable-output comparison
against a separate compiler built from both Phase 3 revisions above. The
[benchmark reproduction procedure](benchmarks/float_trees/README.md) supplies
those historical worktrees without changing the current source checkout.
