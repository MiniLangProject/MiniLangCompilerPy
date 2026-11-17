# Nested float loops and guarded reentry

Date: 2026-11-17. This is the sixth optimization round, compared with the
completed [Phase 5 checkpoint](performance_float_loops.md).

This extension optimizes bounded numeric loops inside ordinary control flow
and adds guarded reentry for a counted loop with an additional floating-point
exit condition. The original Mandelbrot program is the motivating case. Its
source is unchanged: it still starts each pixel with zero-valued state and
tests both an iteration limit and an escape radius. Both compiler implementations
retain MiniLang's existing numeric normalization and ordinary fallback behavior.

## Comparison boundary and result

| Repository | Before: completed Phase 5 | After: measured Phase 6 source |
|---|---|---|
| MiniLangCompilerPy | [`b1f8cc0ef85831895724ec40665a07ec74d7740b`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/b1f8cc0ef85831895724ec40665a07ec74d7740b) | [`173979dcf01bebe278b364ce9c4a673b18cac49f`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/173979dcf01bebe278b364ce9c4a673b18cac49f) |
| MiniLangCompilerML | [`b15ec01c44ebba4b27d4c079604c4554caf000ed`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/b15ec01c44ebba4b27d4c079604c4554caf000ed) | [`11dab16a271267bed9f5b6343bd70a69bcde3990`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/11dab16a271267bed9f5b6343bd70a69bcde3990) |

The source commits above contain the measured implementation and tests. The
report and evidence were added afterwards without changing that implementation.
The [reproduction guide](benchmarks/float_nested/README.md) checks out both source
pairs explicitly while using the helpers from the revision containing this report.

In the primary series, Mandelbrot moves from
**20.682 to 7.227 ms per call**.
Its **paired median speedup is 2.756x**, with
**11/11 faster pairs**. The separate four-variant series
records **2.706x** and
**11/11 faster pairs**.
The primary paired ratio corresponds to approximately
**63.7% less elapsed time** for this workload.

Mandelbrot is the only changed executable in the fifteen-case primary suite.
The other fourteen images, including the already optimized recurrence, are
byte-identical to Phase 5 and serve as timing controls. Collection-free
Mandelbrot probes at n=17 change from **21,889 to
3,025 allocation blocks**, representing a
**86.18% reduction**.
The full-size GC probe changes from **26 to
4 collections** across eight calls.

These are incremental Phase 5-to-Phase 6 measurements. Historical speedup
ratios describe different measurement series and are not multiplied into a
cumulative claim. Full-precision observations accompany the
[primary summary](benchmarks/float_nested/primary/summary.json) and
[separate comparison](benchmarks/float_nested/float_comparison/summary.json).
The Phase 5 baseline was rerun for this evaluation. Absolute times differ from
the earlier report even for unchanged images, so previous-session medians are
not substituted for the contemporaneous before measurements.

## Why Mandelbrot needs another path

Phase 5 recognized direct function-body loops of the form `counter < bound`.
Mandelbrot's inner loop is nested inside two raster loops and combines that
counter test with `zr2 + zi2 <= 4.0`. Its first arithmetic operations also
produce exact zero. MiniLang can normalize an arithmetic result to an integer
even when its operands were floats. A raw path that permanently falls back
at this first transition misses later iterations whose state consists of floats.

The new path discovers the inner loop, evaluates its bounded escape predicate
against raw committed state, and retries guarded entry after one ordinary
iteration. It does not reinterpret integer state as floating-point state.
Integer precision, signed61 wrapping and normalization remain the responsibility
of the existing ordinary lowering whenever the raw representation is unsuitable.

## Accepted loops and bounded analysis

Candidate discovery walks While, DoWhile, numeric For and foreach bodies, If
arms, and Switch arms within the current function. It does not traverse nested
function definitions, expressions or synchronized blocks. The same candidate
walker determines frame reservation and the allowed emission sites. An accepted
raw loop body contains assignments only, so two accepted regions cannot execute
inside one another. Separate nested or sibling candidates can reuse the same
maximum-sized arena safely.

The original simple counted-loop path remains. The extension additionally
accepts exactly `counter < bound and left <comparison> right`, with one of
`==`, `!=`, `<`, `<=`, `>` or `>=`. The counter and invariant bound require
existing integer proofs and actual integer entry tags. The final body statement
must be the exact unit increment, optionally with its ordinary nonoptional
integer contract. Under `counter < bound`, this increment cannot overflow the
supported signed61 range, including an upper bound at its maximum value.

The rest of the body remains a bounded sequence of untyped assignments using
pure `+`, `-`, `*` trees or aliases. Limits remain twelve statements, eight state
slots and eight fresh arithmetic definitions. Each arithmetic tree has at most
three levels and seven nodes. The escape comparison has a combined seven-node
limit, and its two operands together may require at most two saved left values.
Constant-only arithmetic subtrees retain ordinary lowering because their
already encoded folded result may have different normalization behavior.

Every state name must resolve to one ordinary, unambiguous local or parameter.
Globals, captures, boxed bindings, constants and scalarized struct bindings are
excluded. Live-ins require compatible existing numeric facts, followed by actual
float guards; a `number?` fact is only a candidate hint and does not prove a
runtime number. Body-local temporaries are distinguished from outer outputs,
and a condition cannot read a temporary before its body declaration. Calls,
indexed or member accesses, contracts on float assignments, early transfers,
changed bounds and unsupported increments remain on the existing path.

## State, condition order and rollback

The planner visits condition operands before the assignments and records an
immutable mapping to committed state slots. Each body definition then receives
its own source-order environment snapshot. A condition at the raw backedge
therefore observes the most recently completed iteration even though ordinary
tagged homes have not yet been updated. Alias assignments update the definition
mapping and do not allocate a new Value.

Entry tests the counter limit before inspecting any float input. An exhausted
counter preserves short circuit behavior even when the unused float state is
void or otherwise unsuitable. Accepted float live-ins are then loaded into the
committed bank and the successful-iteration flag resets to zero. The escape
predicate runs before any staged body assignment.

Every arithmetic node, including condition and assignment roots, uses the
existing normalizer's integer/unordered decision. A result for which ordinary
normalization selects an integer triggers fallback; this statement does not
claim that every mathematically integral double fits the normalizer's integer
conversion range. Unordered arithmetic also falls back so the existing NaN
normalization is preserved. Direct NaN leaf comparisons retain ordinary behavior:
unordered is true for `!=` and false for the other five comparisons.

The body writes fresh definitions into staged slots. Only after all guards
succeed are its outputs copied to the committed bank and the tagged counter
advanced. A miss does not expose partial assignments or advance the counter
for the failed iteration. If earlier iterations succeeded, their committed
state is materialized before ordinary replay. If none succeeded, the original
tagged homes are already the correct checkpoint and are left alone.

A false escape predicate before the first successful commit also leaves those
homes untouched. This preserves existing pointer aliases and write-only output
values and avoids reading uninitialized raw output slots. On materialization,
outputs sharing a fresh definition receive the same Value. Each alias group
is rooted immediately before another group can allocate. Float materialization
uses the force-float helper, preserving the representation already established
by the preceding arithmetic guards.

## Ordinary progress and reentry

Compound-loop fallback evaluates the complete ordinary condition. A false
condition exits, and errors or strict-void behavior use the same helpers as
ordinary While lowering. Otherwise one complete ordinary body iteration runs,
including normal lexical scope entry, cleanup and the counter update. Only
then does control return to the guarded entry.

This progress rule is essential when a condition repeatedly normalizes to an
integer. A condition such as a sum that is exactly one on every iteration must
still advance through ordinary iterations. Repeated body normalization misses
likewise cannot turn into speculative retry without progress. Subsequent entry
uses current tagged homes and resets the success flag, so raw state from an
earlier attempt is never mistaken for newly committed state.

Simple counted loops keep Phase 5's permanent ordinary-loop fallback. Reentry
is specific to the new compound path. The implementation makes no broad claim
about arbitrary control-flow graphs, mixed raw integer/float state, or reentry
across calls and side effects.

## Frame, register and GC boundaries

Raw doubles remain beyond the expression-temporary arena and outside the
published GC root prefix. They never occupy a tagged expression-root slot.
Mandelbrot uses six state slots, four fresh definition slots and one flag:
eleven eight-byte slots rounded to a **96-byte** frame area. The recurrence's
existing area remains **64 bytes**. This is frame reservation, not heap allocation.

Raw evaluation uses XMM0-XMM5; XMM4 and XMM5 hold bounded saved left operands.
The preserved XMM6-XMM11 promotion convention and tagged homes are unchanged.
There are no calls inside a speculative raw interval. Materialization can
allocate only after the transaction is complete or being abandoned, with
ordinary Value roots protecting each completed output group. Native-thread
and concurrent-GC programs retain the existing loop and safepoint behavior.
The runtime Value layout and collector are unchanged.

## Validation

All final recorded gates passed. Unittest discovery ran **61 cases: 58 passed
and 3 platform/optional-tool skips**. Structural checks and the native Linux
executable-mode, path, import and cache regressions also passed. Bootstrap and
native self-rebuild are byte-identical at **66,241,424 bytes**.

| Configuration group | Configurations | Compared images | Runtime checks here |
|---|---:|---:|---|
| Linux x64 | 36 | 108 | 36; all outputs match Phase 5 |
| Windows x64 | 19 | 57 | Not executed |
| MinUX x64 | 19 | 57 | Not executed |
| Windows x64, concurrent GC | 14 | 42 | Not executed |
| Total | **88** | **264** | **36 Linux cases** |

Every configuration compares Python, native monolithic and native MLO output
byte for byte. The runtime column counts executed configurations, not all three
identical images. The [validation summary](benchmarks/float_nested/validation_summary.json)
keeps the execution and compile-only boundaries explicit.

The new [main fixture](../tests/numeric_float_nested.ml) checks **21 positive
regions across 19 functions** and **18 negative functions**. Coverage includes
nested and sibling loops, every comparison operator, first and later rollback,
integer-to-float reentry, repeated normalized conditions, both comparison trees,
signed61 bounds, initial and later escape, aliases, write-only outputs, nullable
state and special floats. Separate [custom-type-query](../tests/numeric_float_nested_typeof.ml)
and [thread](../tests/numeric_float_nested_threads.ml) fixtures verify exclusions.
The thread fixture activates the compilation gate without starting an OS thread.

Assembly checks require call-free raw intervals, normalization before commit,
counter short circuit before float work, rollback edges, alias-group
materialization and scalar progress before reentry. **Twenty-four forced-GC
iterations** exercise sibling regions, aliases and reentry while retaining
earlier roots; collection must occur, and values are checked after a further
collection. Native compact AST handles are tested through the same parity
gates as the Python AST representation.

Implementation references are the pinned [Python lowering](https://github.com/MiniLangProject/MiniLangCompilerPy/blob/173979dcf01bebe278b364ce9c4a673b18cac49f/mlc/codegen/codegen_stmt.py) and
[MiniLang lowering](https://github.com/MiniLangProject/MiniLangCompilerML/blob/11dab16a271267bed9f5b6343bd70a69bcde3990/mlc/codegen/codegen_stmt.ml), plus
[check_proven_check_elision.py](../tests/check_proven_check_elision.py).

## Primary performance series

All fifteen programs, drivers, fixed inputs and repeat counts are unchanged.
Each case has eleven paired rounds. Mandelbrot uses a raster side length of
**126** and **16 timed calls per process**, following a full
untimed warmup. Times below are milliseconds per kernel call.

| Kernel | Before ms/call | After ms/call | Paired before/after | Identical images |
|---|---:|---:|---:|---|
| `byte_copy` | 27.712 | 28.344 | 1.019x | yes |
| `byte_search` | 6.975 | 7.462 | 0.944x | yes |
| `array_scan` | 40.774 | 40.623 | 0.986x | yes |
| `array_scatter` | 40.312 | 38.078 | 1.005x | yes |
| `sieve` | 30.767 | 28.022 | 1.020x | yes |
| `heapsort` | 50.893 | 50.373 | 1.030x | yes |
| `escaped_nodes` | 12.123 | 11.850 | 1.007x | yes |
| `int_mix` | 16.706 | 16.825 | 0.988x | yes |
| `branch_mix` | 26.692 | 25.975 | 1.024x | yes |
| `float_recurrence` | 4.690 | 4.703 | 0.992x | yes |
| `mandelbrot` | 20.682 | 7.227 | 2.756x | no |
| `recursive_tree` | 56.812 | 55.642 | 1.036x | yes |
| `ascii_parse` | 35.472 | 35.146 | 0.995x | yes |
| `string_concat` | 44.541 | 42.772 | 1.019x | yes |
| `string_builder` | 33.840 | 33.971 | 0.999x | yes |

Mandelbrot's individual paired ratios range from **2.049x to
3.130x**. Relative IQR is **6.87% before**
and **20.35% after**. Across primary configurations,
relative IQR ranges from **4.10% to 21.67%**. The fourteen
identical controls have paired medians between **0.944x and
1.036x**; these differences cannot be attributed to changed code.

The paired statistic is the median of the eleven within-round before/after
ratios. A ratio of separately computed time medians is a different statistic:
for Mandelbrot it is **2.862x**, compared with the reported
**2.756x paired median**. Both remain in the numeric evidence.

## Separate comparison with C and C++

The independent four-variant series reuses the original GCC/G++ 14.2.0 images.
The C11/C++17 kernels and driver are separate translation units, compiled with
`-O3 -march=x86-64 -mtune=generic -ffp-contract=off -fno-fast-math`, without LTO.
Their images were checked against the archived comparison before measurement.
Each language retains its original calibrated repeat count; all times are
normalized per call.

| Kernel | Before ML ms | After ML ms | C -O3 ms | C++ -O3 ms | Paired before/after |
|---|---:|---:|---:|---:|---:|
| `float_recurrence` | 4.686 | 4.806 | 0.959 | 0.971 | 1.012x |
| `mandelbrot` | 21.210 | 7.783 | 0.964 | 0.959 | 2.706x |

Current Mandelbrot MiniLang/C and MiniLang/C++ **paired runtime ratios** are
**8.018x** and
**8.310x**. For the unchanged
recurrence they are **4.928x** and
**4.908x**. These kernel-specific
ratios do not establish a universal speed difference between the languages.

All **418 timed runs** passed measured and warmup checksums: 330 primary and
88 separate runs. Preparation passed **294 primary correctness checks**, including
30 full-size checks, and **36 additional float oracle checks**. Timing uses
in-process `CLOCK_MONOTONIC`, CPU 2 affinity and a full untimed warmup. Compilation,
process startup and printing are outside that timer. The primary cases alternate
pair order; the four-variant schedule balances every pair's relative order 5/6
times, while individual positions occur 2-4 times.

No other compiler or benchmark job from this evaluation ran during timings.
The host is a shared Linux VM; unrelated host load and CPU frequency were not
controlled. The results support this bounded transformation on the recorded
workloads, with the identical controls showing the observed noise range.

## Allocation, GC and generated code

The following Mandelbrot probes use one call and base seed 12345. None collects,
so the block and frontier deltas describe the allocations within that probe.

| Raster side n | Before blocks | After blocks | Before frontier bytes | After frontier bytes |
|---:|---:|---:|---:|---:|
| 1 | 4 | 4 | 96 | 96 |
| 3 | 700 | 52 | 16,800 | 1,248 |
| 5 | 1,137 | 241 | 27,288 | 5,784 |
| 17 | 21,889 | 3,025 | 525,336 | 72,600 |

Eight full-size calls give these separate GC observations:

| Kernel | n | Before collections | After collections | Shared checksum |
|---|---:|---:|---:|---:|
| `float_recurrence` | 260986 | 0 | 0 | 443985351 |
| `mandelbrot` | 126 | 26 | 4 | 2227976 |

For full-size Mandelbrot, the before/after block deltas are
**192,474/203,546**, and frontier deltas are
**8,388,912/8,388,744 bytes**. Whenever a
probe collects, these are net heap changes rather than cumulative allocation
counts. They must not be used to infer a total allocation reduction. The
[twenty GC observations](benchmarks/float_nested/float_comparison/gc_diagnostics.json)
retain the original counters and checksums. Entry, ordinary iterations and final
materialization still allocate where required; the optimized program is not
allocation-free.

Mandelbrot's executable segment grows from **75,562 to 77,930 bytes**,
an increase of **2,368 bytes / 3.13%**. It contains one compound
raw region with **eight arithmetic normalizers**, plus **five expression-tree
normalizers in the retained scalar fallback**. The unchanged recurrence keeps
twelve raw-loop and fourteen fallback normalizers. These are static instruction
sites, not execution counts or dynamic allocation counts. The
[code summary](benchmarks/float_nested/float_comparison/code_summary.json) separates them.

The `nested_disabled` control restricts discovery to direct function-body loops
and rejects compound conditions. It reproduces the frozen Phase 5 images for
both float kernels while retaining Phase 5's recurrence optimization. Disabling
the entire loop optimizer would use an earlier baseline and is not this control.
Current Python and native benchmark images also match exactly.

## Remaining opportunities and limits

The measured reduction in allocation and runtime supports keeping this bounded
extension. Remaining work includes normalization tests, ordinary iterations
around representation changes, entry/exit materialization, and generated data
movement. This evaluation does not isolate a precise cost for any one mechanism.
An appropriate next experiment can measure those components before expanding
the accepted state model or removing guards.

General mixed numeric state, old-value output aliases, calls inside raw regions,
thread safepoints and arbitrary loop conditions remain separate correctness
problems. Their potential gains are unmeasured here. Future comparisons should
freeze this completed source pair as their baseline and retain the same checksum,
parity and byte-control discipline.
