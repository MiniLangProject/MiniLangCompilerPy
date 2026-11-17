# Guarded float loops — Phase 5 checkpoint

Date: 2026-11-17.

**Historical version scope.** This report describes the completed Phase 5
checkpoint. Its measurements, validation totals and implementation references
apply to these public commits:

| Repository | Phase 5 commit |
|---|---|
| MiniLangCompilerPy | `b1f8cc0ef85831895724ec40665a07ec74d7740b` |
| MiniLangCompilerML | `b15ec01c44ebba4b27d4c079604c4554caf000ed` |

The repositories now continue on `main` with
[Phase 6: nested float loops](performance_float_nested.md). Use the pinned
commits above to reproduce Phase 5. Its comparison boundary and observations
remain separate from the [Phase 6 evidence](benchmarks/float_nested/README.md).

This fifth round keeps eligible floating-point state unboxed across assignments
and loop iterations. It uses a private, unscanned area of the function frame,
with transactional iteration boundaries and the existing loop as its fallback.
Both compiler implementations preserve numeric normalization, Value aliases,
lexical scope, and GC rooting. This round changes code generation and frame
reservation; it does not change the runtime Value layout or collector.

## Comparison boundary and measured decision

The baseline is the completed [Phase 4 checkpoint](performance_float_trees.md):

| Repository | Baseline revision |
|---|---|
| MiniLangCompilerPy | `6a953bb4f7f51947ba149fd64e2cbbdcefb17876` |
| MiniLangCompilerML | `ddc67c9c4f9c5828101e884076915f6536a3942c` |

Keep this bounded extension. On the unchanged recurrence benchmark, the primary
series improves from **9.007 to 3.100 ms per call**,
with **2.923x paired median speedup** and **11/11 faster pairs**.
That corresponds to approximately **65.8% less elapsed time**.
The independent four-variant series confirms **2.950x**,
also with all eleven pairs faster.

Collection-free recurrence probes fall from **3,005 to 8 allocation blocks**
for n=1000, and from **72,120 to 192 allocation-frontier bytes**, a **99.73%**
reduction in those observations. Eight full-size calls fall from **17 to 0 GC
collections**, with unchanged checksums. Fourteen other primary images are
byte-identical to the baseline. Mandelbrot is one of these unchanged controls;
this phase does not extend its nested numeric loop.

The [primary data](benchmarks/float_loops/primary/summary.json),
[separate comparison](benchmarks/float_loops/float_comparison/summary.json), and
[reproduction guide](benchmarks/float_loops/README.md) retain the full precision,
inputs and protocol. These are incremental Phase 4-to-Phase 5 observations;
ratios from historical rounds must not be multiplied into a cumulative claim.

## Why expression fusion still leaves materialization work

The preceding optimization keeps eligible arithmetic expression trees unboxed, but an assignment still produces an ordinary MiniLang Value. In the coupled recurrence, `nextX`, `nextY`, and the updated accumulator each finish such an expression. Assignments from `nextX` to `x` and from `nextY` to `y` copy those Values. The body temporaries then leave scope, while `x`, `y`, and the accumulator carry the results into the next iteration. For results requiring boxed binary64 representation, these assignment boundaries therefore retain three boxes per iteration.

Removing those boxes requires carrying raw numeric state across the loop boundary. Another expression-local optimization cannot achieve that while requiring every carried value to be materialized at every backedge. The new lowering addresses a restricted counted-loop form whose state can remain private until exit or fallback.

## Eligibility and deliberate bounds

The pilot applies only to a direct, top-level `while` statement within a function, with native threading and concurrent GC absent. Its condition must be `counter < bound`. The bound is an invariant ordinary local or parameter, or an integer literal within signed61 range. Both operands must satisfy the compiler's existing integer proof, have no conflicting legacy type fact, and pass actual-integer guards at entry. The final statement must increment that counter by exactly one; a nonoptional `int` contract on this update is permitted.

Before the increment, the body must contain ordinary untyped assignments. Accepted expressions contain float literals, ordinary variable references, and `+`, `-`, or `*`; variable assignments may also express aliases. The limits are 12 body statements, 8 committed state slots, and 8 fresh arithmetic definitions. Each arithmetic tree permits at most 3 arithmetic levels, 7 arithmetic nodes, and 2 simultaneously saved left operands. Constant-only arithmetic subtrees retain ordinary lowering, preserving the existing constant folder's encoded results.

Live-in variables must have extended numeric facts of `float`, `number`, or `number?`, and must pass actual-float guards. Conflicting legacy facts are rejected, including integer or struct facts that could select different ordinary operations. The compiler requires direct builtin `typeof` resolution and conservatively excludes assignments named `typeof` inside the body. Globals, captures, boxed locals, constants, synchronized bindings, scalarized structs, ambiguous shadowing, and inline-expanded loops are excluded.

Calls, member or indexed access, branches, nested loops, early exits, and float TypeGuards are outside this shape. These restrictions make the speculative body free of source-visible effects and observable intermediate assignments.

## Committed state and staged definitions

A candidate receives a bounded private area in its function frame. One bank contains committed loop state; another contains fresh arithmetic definitions for the current tentative iteration. A small flag records whether any iteration has committed. The planner follows assignments in source order and records the latest definition for each variable. Alias assignments change this definition map without creating another numeric object.

Only use-before-definition inputs are guarded and initialized at entry. Newly introduced body locals such as `nextX` and `nextY` have no incoming value to inspect. An outer output written before its first use also needs no float entry guard: its old Value may be void or a string. Committed slots cover the union of actual inputs and outputs surviving the loop; staged slots cover arithmetic definitions.

Every operation must succeed under the float-only rules before any staged output replaces committed state. Only then does the counter advance. Because the guarded counter is below an invariant signed61 bound, adding one cannot overflow signed61, including when the bound is its maximum value. Tagged homes for the float outputs remain unchanged throughout speculation; the raw committed bank records the checkpoint needed for replay.

## Normalization and rollback

Raw arithmetic must reproduce MiniLang's normalization boundaries. Each operation, including every assignment root, performs the existing integer-result test before the iteration can commit. A result for which the existing normalizer would select the integer representation, or an unordered NaN comparison, branches to deoptimization. The existing float32 probe is retained for results continuing as floats. This preserves the distinction between normalized integers and floating-point representations; integer/integer operations, including exact arithmetic beyond binary64's integer precision, remain on ordinary lowering.

On a failed first tentative iteration, no committed progress exists, so the original tagged homes are already correct. After earlier successful iterations, the compiler materializes their committed state before entering the ordinary loop. The counter still denotes the failed iteration. The ordinary implementation then replays that iteration from its beginning, preserving source order, integer wrapping, and existing NaN, Error, void, and contract behavior. No tentative assignment is applied twice.

Materialization uses force-float encoding rather than arithmetic normalization. It represents a value already known to be a float, rather than applying another language operation. This distinction matters for integral-valued floats and representation-sensitive behavior. A successful normal exit materializes the final committed outputs once.

## Aliases and address observations

Every surviving assigned output must refer to a fresh arithmetic definition from that iteration. Outputs sharing a definition form one alias group: the compiler materializes that definition once and copies the resulting Value into every group member. Distinct definitions are not merged merely because their numeric results happen to match.

This preserves relevant alias relationships observable through `nativeRawValue`. Unchanged inputs retain their original tagged homes, and zero completed iterations preserve original output identities. The optimization does not promise identical absolute heap addresses or allocation history. Its identity requirement concerns which live variables share the same Value.

An old-value assignment such as `copy = x` followed by a fresh update of `x` is excluded when `copy` survives the loop. Its identity could depend on an earlier iteration's object and would require additional tracking. Body-local temporaries that leave scope do not require exit materialization.

## Zero trips, GC roots, and the calling convention

Entry integer guards and the range test precede float guards. A valid zero-trip loop therefore leaves all float inputs and outputs untouched and performs no loop materialization. Earlier program operations and function-entry contracts still execute normally.

The private arena sits after the maximum expression-temp area and before the GC root record. It does not extend the published root prefix. Raw double bit patterns are never stored in ordinary expression-temp slots, which are scanned as Values. During output materialization, each boxed result is written immediately into canonical root slots before another allocation can occur; remaining raw outputs survive in the private arena.

Raw expression work uses XMM0–XMM5. Existing tagged-local promotion and its preservation of nonvolatile registers remain unchanged. The speculative loop contains no calls. Frame sizing accounts for the private arena without overlapping outgoing arguments, existing save areas, or the root record.

The no-thread restriction avoids introducing unmaterialized state across cooperative GC or cancellation boundaries. The pilot also has no optimized reentry: after a normalization miss, the remaining iterations use ordinary lowering. General loop conditions, nested loops, mixed integer/float state, and reentry require separate designs; they are not implied by this implementation.

## Validation and implementation references

All final gates passed. Python unittest discovery ran **61 cases: 58 passed and
3 skipped** for platform or optional-tool requirements. The existing structural
check and native Linux executable-mode, path, import and cache regressions also
passed. The Python-built compiler and its native self-rebuild are byte-identical
at **66,098,048 bytes**.

| Configuration group | Configurations | Compared images | Runtime checks here |
|---|---:|---:|---|
| Linux x64 | 33 | 99 | 33; all outputs equal the frozen baseline |
| Windows x64 | 16 | 48 | Not executed |
| MinUX x64 | 16 | 48 | Not executed |
| Windows x64, concurrent GC | 11 | 33 | Not executed |
| Total | **76** | **228** | **33 Linux cases** |

Each configuration compares Python, native monolithic, and native MLO output
byte for byte. A runtime test executes one of those identical images; the image
count must not be confused with the number of executions. The
[validation summary](benchmarks/float_loops/validation_summary.json) records
platform counts and the compile-only boundaries.

The three new fixtures are [numeric_float_loop.ml](../tests/numeric_float_loop.ml),
[numeric_float_loop_typeof.ml](../tests/numeric_float_loop_typeof.ml), and
[numeric_float_loop_threads.ml](../tests/numeric_float_loop_threads.ml).
Seven positive loop shapes cover the recurrence, shared output aliases,
write-only outputs, first and later rollback, runtime integer inputs, signed61
counter limits, and special floats. Negative cases preserve calls and their
execution count, errors after prior assignments, contracts, globals, captures,
loop transfers, old-value aliases, changed bounds and unsupported increments.
Custom `typeof` and native-thread references are checked separately.

Assembly checks require every arithmetic normalizer before commit, exact
integer/NaN branches to rollback, a call-free raw interval, zero-trip exit before
float guards, and one materialization per alias group. The assembler may fold
`jge exit; jmp fast` to the equivalent `jl fast`; the check accepts both forms.
Twenty-four forced-GC repetitions retain three heap-backed outputs, aliased
outputs and earlier input roots, verify that collection occurred, and recheck
retained results after another collection. The Thread fixture verifies code
generation without starting an operating-system thread.

The implementation is in
[Python statement lowering](https://github.com/MiniLangProject/MiniLangCompilerPy/blob/b1f8cc0ef85831895724ec40665a07ec74d7740b/mlc/codegen/codegen_stmt.py)
and [MiniLang statement lowering](https://github.com/MiniLangProject/MiniLangCompilerML/blob/b15ec01c44ebba4b27d4c079604c4554caf000ed/mlc/codegen/codegen_stmt.ml),
with function-context fields in each `codegen_core` module. Existing expression
normalization and GC helpers are reused. The test harness is
[check_proven_check_elision.py](../tests/check_proven_check_elision.py).

## Primary measurements

The original fifteen programs, inputs, seed cycle and repeat counts are
unchanged. Each case has eleven paired rounds. The recurrence uses n=260986
and sixteen timed calls per process after a full untimed warmup.

| Kernel | Before ms/call | After ms/call | Paired before/after | Identical images |
|---|---:|---:|---:|---|
| `byte_copy` | 14.990 | 15.314 | 0.984x | yes |
| `byte_search` | 3.577 | 4.024 | 0.923x | yes |
| `array_scan` | 22.085 | 21.737 | 1.029x | yes |
| `array_scatter` | 24.113 | 24.416 | 0.986x | yes |
| `sieve` | 14.872 | 15.694 | 0.977x | yes |
| `heapsort` | 29.580 | 28.886 | 0.989x | yes |
| `escaped_nodes` | 7.088 | 7.127 | 0.985x | yes |
| `int_mix` | 10.386 | 10.204 | 0.986x | yes |
| `branch_mix` | 19.254 | 19.263 | 0.997x | yes |
| `float_recurrence` | 9.007 | 3.100 | 2.923x | no |
| `mandelbrot` | 11.771 | 11.795 | 1.007x | yes |
| `recursive_tree` | 25.442 | 25.217 | 0.997x | yes |
| `ascii_parse` | 23.113 | 22.984 | 1.006x | yes |
| `string_concat` | 15.043 | 14.518 | 1.007x | yes |
| `string_builder` | 23.366 | 23.807 | 1.001x | yes |

The fourteen identical controls have paired medians from **0.923x to 1.029x**;
their timing differences cannot be attributed to changed code. Relative IQR
across primary configurations ranges from **2.49% to 16.30%**. For recurrence it
is **16.30% before and 5.03% after**, and every individual pair improves by
**2.653x to 3.403x**. This remains a shared-VM observation rather than a precise
forecast for other hardware or workloads.

## Separate C and C++ comparison

A separate eleven-round series uses the preceding compiler, the current
compiler, and the original GCC/G++ 14.2.0 images. The C11/C++17 kernels and driver
are separate translation units, with `-O3 -march=x86-64 -mtune=generic`,
`-ffp-contract=off -fno-fast-math`, and no LTO. Their images were verified against
the archived comparison images before this series. Each language retains its
original calibrated repeat count; measurements are normalized per kernel call.

| Kernel | Before ML ms | After ML ms | C -O3 ms | C++ -O3 ms | Paired before/after |
|---|---:|---:|---:|---:|---:|
| `float_recurrence` | 9.125 | 3.060 | 0.689 | 0.697 | 2.950x |
| `mandelbrot` | 11.537 | 11.847 | 0.631 | 0.645 | 0.989x |

For recurrence, the current MiniLang/C and MiniLang/C++ **paired time ratios**
are **4.538x and 4.529x**. MiniLang therefore remains around 4.5 times the runtime
of those C/C++ kernels here. For unchanged Mandelbrot the ratios are **18.907x
and 18.825x**. The ratio of separate time medians need not equal the median of
within-round ratios, which is the statistic reported for these comparisons.
These two kernels do not establish a universal language-performance ratio.

All **418 timed runs** passed their measured and warmup checksums: 330 primary
and 88 separate runs. Preparation also passed **294 primary correctness checks**,
including 30 full-size checks, and **36 separate float oracle checks**. Timing
uses in-process `CLOCK_MONOTONIC`, an untimed full warmup, CPU 2 affinity, and
paired ordering. No other compiler or benchmark process from this evaluation
ran during the timing series. CPU frequency and unrelated host load were not
controlled. The four-variant schedule visits every position and balances each
pair's relative order 5/6 times; positions themselves occur 2–4 times.

## Allocation, GC and code-size observations

The following collection-free recurrence probes use one call and base seed 12345:

| n | Before blocks | After blocks | Before frontier bytes | After frontier bytes |
|---:|---:|---:|---:|---:|
| 1 | 8 | 8 | 192 | 192 |
| 10 | 35 | 8 | 840 | 192 |
| 100 | 305 | 8 | 7,320 | 192 |
| 1000 | 3,005 | 8 | 72,120 | 192 |

The earlier 3*n+5 pattern in these probes becomes eight blocks for the tested
positive sizes: setup and final materialization remain. This is not a claim
that every input takes the raw loop or that the whole program allocates nothing.
A normalization miss switches to ordinary looping for the remaining iterations.

Across eight full-size recurrence calls, the new probe reports **64 blocks and
1,536 frontier bytes with zero collections**, versus **17 collections** in the
baseline. The baseline's post-collection heap/block deltas are net changes and
are not cumulative allocation counts. Mandelbrot's collection-free counters are
unchanged, including **21,889 blocks / 525,336 bytes** at n=17; its eight full-size
calls retain **26 collections**. All twenty separate GC observations and their
checksums are in [gc_diagnostics.json](benchmarks/float_loops/float_comparison/gc_diagnostics.json).

Recurrence's executable segment grows from **212,515 to 214,947 bytes**:
**2,432 bytes / 1.14%** for entry guards, the raw loop, materialization and the
retained ordinary loop. Its private raw arena is **64 bytes**. Mandelbrot's
segment stays **75,562 bytes**. The
[code summary](benchmarks/float_loops/float_comparison/code_summary.json)
records one new recurrence loop and twelve raw-loop normalizers, separately
from normalizers in the retained fallback. These are static sites, not dynamic
allocation counts.

Disabling both new hooks, including arena reservation, reproduces the frozen
baseline images exactly for both float kernels. Current Python and native
images are also identical. This control isolates the new loop transformation
from the earlier expression-tree optimization.

## Remaining scope

The observed gain justifies the bounded path. The remaining recurrence gap to
C/C++ includes dynamic numeric normalization, twelve guarded arithmetic
boundaries in its raw loop, and the generated control/data movement. Those
mechanisms preserve MiniLang behavior; this study does not isolate a precise
cost for each one.

A later extension could investigate nested loops and conditional exits, or
reentry after integer state has returned to floats. Mandelbrot needs those
additional proofs: its inner condition combines a counter and numeric test,
and early results frequently normalize to integer zero. General mixed numeric
state, thread safepoints, and old-value alias retention remain separate work.
No performance gain for these extensions is claimed here.
