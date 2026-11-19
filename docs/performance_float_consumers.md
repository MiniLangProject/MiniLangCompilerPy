# Canonical numeric consumers in float loops

Date: 2026-11-19. This eighth optimization round compares with the completed
[Phase 7 checkpoint](performance_float_cache.md). Both compiler implementations
retain the existing accepted loop shapes, strict output roots, committed state
and bounded register-cache policy.

## Exact measured source boundary

| Repository | Before: completed Phase 7 | After: measured Phase 8 source |
| --- | --- | --- |
| MiniLangCompilerPy | [`d67b64bac4cc8abe2ced18d10a6188c610d2bd30`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/d67b64bac4cc8abe2ced18d10a6188c610d2bd30) | [`f53fdace586b3d1bacf6726d9bf0850f890dd91f`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/f53fdace586b3d1bacf6726d9bf0850f890dd91f) |
| MiniLangCompilerML | [`65d62add8bf7cc6d3c0439a0ba1d1e7e3690ad8d`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/65d62add8bf7cc6d3c0439a0ba1d1e7e3690ad8d) | [`f4f89844372d397348b6d93a950285148c1122b3`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/f4f89844372d397348b6d93a950285148c1122b3) |

Implementation and regression commits precede this report and its evidence.
The subsequent documentation commit does not change measured compiler sources.

## Measured outcome

| Kernel | Primary paired ratio | Faster pairs | Separate paired ratio | Faster pairs |
| --- | --- | --- | --- | --- |
| `float_recurrence` | 0.999x | 4/11 | 1.056x | 7/11 |
| `mandelbrot` | 1.231x | 9/11 | 1.212x | 10/11 |

The two full timing series compare the complete Phase 7 baseline and the combined
Phase 8 candidate. They are separate from the earlier seven-round ablation.
Benchmark sources and workloads are unchanged, and all benchmark images were
freshly rebuilt. The baseline compiler is the previously validated Phase 7 native
artifact, reused after its recorded hash was verified. The Phase 8 compiler was
freshly bootstrapped and self-rebuilt. The reproduction guide rebuilds both
compilers from the exact source boundary above. Values above one favor Phase 8. These paired
statistics describe the recorded inputs and shared host, not a universal language
speedup. The detailed tables retain dispersion and every observed pair.

The combined change is retained for its Mandelbrot improvement: the two final
paired medians correspond to approximately
18.73% and
17.47% less elapsed time by the paired statistic.
The earlier combined ablation also favors it in all seven pairs at
1.196x. The normalization-only
ablation supports the main mechanism. Literal decoding alone has no established
independent timing gain; its bounded removal of unreachable dispatch also makes
both images smaller. **Recurrence has no established runtime benefit**: its
primary, separate and component results disagree, and do not establish a
consistent regression either.

**This evaluation is noisy.** Thirteen byte-identical controls range from
0.895x to
1.051x. Primary Mandelbrot relative
IQR is 27.99% before and
32.27% after, and individual ratios range from
0.724x to 1.670x. Repeated direction across the three
series and the transition/GC evidence support retaining the change, but its
precise size on controlled hardware remains uncertain. No performance reruns or
outlier exclusions were used to improve the result.

## Baseline sampling: locating work before changing it

Linux software user-CPU-clock sampling was performed on unchanged Phase 7
executables. Labels and ELF offsets were checked against exact normalizer bytes.
The final profile preserves the original sixteen calls per process and full
warmup: 48 processes per kernel, divided over three nearby sampling periods
(997,003, 1,000,003 and 1,009,003 ns). All 96 processes passed result and warmup
checksums, with no lost samples. The seed cycle and original inputs were retained.

| Kernel | Samples | Raw-normalizer IP share | Range across sampling periods | Ordinary-path IP share | Other executable-function IP share |
| --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 3,670 | 69.86% | 69.12% / 70.64% | 0.00% | 0.03% |
| `mandelbrot` | 5,467 | 37.92% | 36.81% / 39.42% | 17.91% | 22.59% |

These are **approximate sampled user-time shares attributed to instruction
pointer ranges**. Software-clock interrupts have arbitrary skid and samples can
be correlated. The records include startup, warmup and printing. Samples inside
runtime functions remain separate: leaf PCs provide no causal caller attribution.
Hardware-cycle sampling was unavailable. A large sampled normalizer share does
not mean that the same fraction of runtime can be removed, and it does not give
the exclusive cost of an individual conversion instruction.

A preceding pilot used 256 calls per process. Its records remain separate; the
table above uses only the original sixteen-call cadence. Neither profiled elapsed
times nor instrumented counter builds enter the performance tables below.
[Original-cadence records](benchmarks/float_consumers/profiles/original_processes/summary.json)
and the [extended-repeat pilot](benchmarks/float_consumers/profiles/extended_repeat_pilot/summary.json)
are retained separately.

## Canonical numeric consumers without loop rollback

The previous loop path required every arithmetic result to remain a float under
ordinary MiniLang normalization. An exact integer or unordered result restarted
ordinary evaluation from the committed state. This is necessary for assignment
roots and integer/integer parent operations, but some intermediate values have
an immediate consumer whose other operand is known to be an actual float.

The new predicate accepts only primitive `Var` or float `Num` siblings inside an
already accepted loop. Entry guards establish actual floats for committed leaves;
strict assignment-root normalization establishes floats for fresh definitions.
An arithmetic sibling does not establish that property. The next operation with
the accepted sibling therefore uses double arithmetic even if its other child
normalizes to an integer. The same proof applies to a comparison operand when
the opposite operand is a primitive actual-float leaf.

At such a child, the original normalizer still emits its integer conversion,
roundtrip comparison, conditional branch and float32 probe. Its integer branch
now targets a local out-of-line stub. The stub uses the still-live conversion
result in RAX, reproduces ordinary tagged signed61 wrapping, converts the result
to XMM0 and resumes immediately after the normalizer. The ordinary unordered/equal
branch is retained, including its existing NaN behavior. The float path keeps
the existing probe and its floating-point status effects; no extra jump is added
to that common path.

Assignment roots remain strict. Children with an arithmetic sibling, and both
arithmetic roots of a comparison, keep their previous bailout where the float
proof is absent. This prevents a pair of normalized integers from silently
changing to floating arithmetic. Evaluation order and parentheses are unchanged.

The deferred blocks are emitted after the normal-exit jump and before the deopt
entry. They modify RAX and XMM0, never the committed state, saved operands or
cached definitions in XMM4/XMM5. Subsequent arithmetic/condition comparisons
establish the flags they consume. No raw value crosses a call or safepoint; no
new frame fields, GC roots or runtime layout are introduced. A later strict-root
miss still discards tentative values and materializes the previous checkpoint.

Condition-only canonicalization would often move an initial Mandelbrot bailout
into its zero-valued body products. Allowing the bounded child transitions as
well permits those values to reach their proven-float consumers; final output
definitions must still remain floats before commit.

## Decode already-known float literals directly

The second change retains the original literal emission and representation.
An exact immediate float32 uses the same payload extraction and `CVTSS2SD` as
before. A boxed literal uses the same double payload in its original read-only
object. The compiler omits only unreachable integer/tag/object dispatch for
these already-proven literals. It does not replace float32 decoding with a
pre-expanded double, because that could omit floating-point status effects.

The two changes can be disabled independently in the Python compiler:

```python
Codegen._opt_float_loop_double_consumer = lambda self, other: False
Codegen._opt_emit_float_loop_literal = lambda self, expr, target: False
```

Disabling both must reproduce the pinned Phase 7 images exactly. The separate
four-variant ablation measures baseline, normalization only, literal decoding
only and the combined candidate with identical sources, inputs and checksums.

## Separate component ablation

| Kernel | Variant | ms/call | Paired baseline/variant | Faster pairs | Paired min / max | Relative IQR |
| --- | --- | --- | --- | --- | --- | --- |
| `float_recurrence` | normalization_only | 4.241 | 0.996x | 2/7 | 0.962x / 1.007x | 3.41% |
| `float_recurrence` | literal_only | 4.384 | 0.975x | 2/7 | 0.814x / 1.014x | 7.23% |
| `float_recurrence` | after | 4.257 | 0.989x | 2/7 | 0.914x / 1.041x | 2.47% |
| `mandelbrot` | normalization_only | 5.637 | 1.167x | 7/7 | 1.089x / 1.415x | 6.50% |
| `mandelbrot` | literal_only | 6.326 | 1.009x | 5/7 | 0.894x / 1.342x | 2.55% |
| `mandelbrot` | after | 5.447 | 1.196x | 7/7 | 1.126x / 1.454x | 6.62% |

This preset series contains 56 runs: two kernels, four variants
and seven rounds. The variants disable only the two Phase 8 hooks; all earlier
loop, normalization and cache optimizations remain active. Before/after relative
orders occur three or four times for each pair. All inputs, repeats and seed
cycles match the primary series, and all checksums and warmups pass.

For Mandelbrot, the normalization-only variant favors the candidate in all seven
pairs. Literal decoding alone has a much smaller, less consistent result. The
combined variant favors the candidate in all seven pairs. These observations
support targeting the avoidable replay/reentry path; they do not assign exact
fractions of elapsed time to individual instructions. Recurrence has no gain
established by this component series. Do not add or multiply component ratios.
[Raw observations and all pair comparisons](benchmarks/float_consumers/ablation/summary.json)
include the controls and outliers.

## Untimed transition diagnostics

Twenty-four before/after pairs cover both kernels, four sizes and three seeds
(0, 12345 and 2147483647). Separate counter programs retain the original kernel
and append a one-call driver. Every instrumented result matches an independent
oracle and its uninstrumented control. Counters preserve arithmetic flags and
live registers, make no calls and allocate no heap memory. They are non-atomic
and restricted to the accepted single-threaded loops. Their elapsed times are
never used as performance measurements.

For one full-size call with seed 12345:

| Kernel | n | Raw commits before / after | Ordinary iterations before / after | Raw deopts before / after | After integer rejoins: condition / body | Total iterations, unchanged |
| --- | --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 260,986 | 260,986 / 260,986 | 0 / 0 | 0 / 0 | 0 / 0 | 260,986 |
| `mandelbrot` | 126 | 254,399 / 269,897 | 24,195 / 8,697 | 15,498 / 0 | 15,498 / 46,494 | 278,594 |

Mandelbrot performs the same 278,594 body iterations.
The after version retains 8,697 ordinary
iterations because entry guards still exclude states that are not actual floats.
The zero deopts in this particular full-size probe do not imply that all programs
or seeds avoid fallback: strict roots and guard failures remain supported and
tested. Recurrence's recorded event counts remain unchanged.

`normalizer_passes` counts the float path only. The difference between attempts
and float passes is now divided into local integer rejoins and real normalization
bailouts. Therefore a normalization branch is no longer synonymous with a loop
deoptimization. Static normalizer sites remain unchanged; the runtime path changes.

Materialized output-value groups in this Mandelbrot probe increase from
57,396 to 61,992, because
more iterations complete in raw mode and more outputs reach normal exits. Raw
frame-memory traffic can also rise when work moves from the ordinary path into
the raw path. These counters do not claim that all materialization or all memory
traffic decreases. The separate GC observations below capture reduced allocation
work, while uninstrumented timing measures elapsed time. Frequencies are not
CPU-time shares. [Complete paired diagnostics](benchmarks/float_consumers/residual_costs/comparison.json)
retain all seeds, including remaining fallback cases.

## Allocation, GC and code size

Twenty separate untimed GC probes record allocation and collection counters.
Representative observations are:

| Kernel | n | Calls | GC collections before / after | Net block delta before / after | Net frontier bytes before / after |
| --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 1000 | 1 | 0 / 0 | 8 / 8 | 192 / 192 |
| `float_recurrence` | 260986 | 8 | 0 / 0 | 64 / 64 | 1,536 / 1,536 |
| `mandelbrot` | 17 | 1 | 0 / 0 | 3,025 / 2,015 | 72,600 / 48,360 |
| `mandelbrot` | 126 | 8 | 4 / 3 | 203,546 / 99,391 | 8,388,744 / 3,870,960 |

The n=17 Mandelbrot run performs no collection, so its smaller block/frontier
deltas show less allocation over that probe. Once collections occur, these
deltas are **net heap changes**, not cumulative allocation counts. The eight-call
full-size probe collects four times before and three times after. Recurrence's
observed GC/allocation counters remain unchanged. No collector implementation
or collection policy is changed by this optimization.

| Kernel | Executable segment before | After | Byte delta | Rejoin stubs | Direct literals: immediate / boxed | Raw / fallback normalizers, unchanged |
| --- | --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 214,947 | 214,307 | -640 | 3 | 0 / 8 | 12 / 14 |
| `mandelbrot` | 77,898 | 77,802 | -96 | 4 | 2 / 0 | 8 / 5 |

The existing 64-byte recurrence and 96-byte Mandelbrot raw frame areas are
unchanged, as are the selected XMM4/XMM5 caches. Normalization checks were not
removed: selected branches now canonicalize and rejoin. Direct literal decoding
reduces code despite the additional deferred blocks. Python label listings are
used only after complete executable equality with native output is verified.
[Code and exact-ablation evidence](benchmarks/float_consumers/float_comparison/code_summary.json)
and [all GC observations](benchmarks/float_consumers/float_comparison/gc_diagnostics.json)
retain their hashes and checksums.

## Primary performance series

| Kernel | n | Calls per process | Before ms/call | After ms/call | Paired before/after | Faster pairs | Identical images |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `byte_copy` | 8,388,608 | 24 | 25.516 | 27.053 | 0.974x | 5/11 | yes |
| `byte_search` | 8,388,608 | 56 | 6.934 | 7.677 | 0.895x | 3/11 | yes |
| `array_scan` | 194,470 | 16 | 40.832 | 41.324 | 0.975x | 4/11 | yes |
| `array_scatter` | 225,245 | 16 | 40.182 | 42.667 | 1.014x | 6/11 | yes |
| `sieve` | 1,977,051 | 16 | 30.338 | 27.658 | 1.051x | 6/11 | yes |
| `heapsort` | 82,396 | 16 | 49.210 | 51.223 | 0.966x | 2/11 | yes |
| `escaped_nodes` | 262,144 | 40 | 11.897 | 12.318 | 0.946x | 4/11 | yes |
| `int_mix` | 2,097,152 | 32 | 16.495 | 16.483 | 1.000x | 5/11 | yes |
| `branch_mix` | 1,909,761 | 16 | 25.041 | 25.827 | 0.994x | 4/11 | yes |
| `float_recurrence` | 260,986 | 16 | 4.363 | 4.304 | 0.999x | 4/11 | no |
| `mandelbrot` | 126 | 16 | 7.515 | 6.481 | 1.231x | 9/11 | no |
| `recursive_tree` | 1,265 | 16 | 54.215 | 55.498 | 1.032x | 6/11 | yes |
| `ascii_parse` | 262,144 | 16 | 40.197 | 36.193 | 1.003x | 6/11 | yes |
| `string_concat` | 7,262 | 24 | 42.357 | 40.672 | 1.017x | 6/11 | yes |
| `string_builder` | 114,195 | 16 | 34.673 | 35.781 | 0.970x | 4/11 | yes |

The statistic is the median of within-round before/after ratios; values above
one favor the new compiler. It need not equal the ratio of separate time medians.
All original programs, inputs, repeat counts, seed cycles and checksum oracles
are retained. The 13 byte-identical controls have paired medians
from 0.895x to
1.051x; those differences cannot
come from changed executable bytes.

Measurements use internal `CLOCK_MONOTONIC` timing, a full warmup and fixed CPU
affinity. Compilation, diagnostics and sampling finish before timing. The shared
VM's unrelated load and frequency are uncontrolled. Every observation remains
in the data; historical phase ratios are not multiplied into a cumulative gain.
Full-precision [summary](benchmarks/float_consumers/primary/summary.json) and
[records](benchmarks/float_consumers/primary/measurements.jsonl) retain all runs.

## Separate C and C++ comparison and dispersion

C/C++ references were freshly reconstructed from the checked-in original kernel
and driver sources; they are not reused historical binary artifacts. Recorded
toolchains: `g++ (Debian 14.2.0-19) 14.2.0`; `gcc (Debian 14.2.0-19) 14.2.0`. Flags include
`-O3 -march=x86-64 -mtune=generic -ffp-contract=off -fno-fast-math`,
C11/C++17, separate translation units and no
LTO. Thirty-six C/C++ correctness observations pass before timing.

| Kernel | n | MiniLang calls | C calls | C++ calls |
| --- | --- | --- | --- | --- |
| `float_recurrence` | 260986 | 16 | 416 | 408 |
| `mandelbrot` | 126 | 16 | 440 | 432 |

`n` is the recurrence iteration count and the Mandelbrot raster side length.
Each language retains its original calibrated repeat count; times are normalized
per kernel call. The four-variant schedule balances relative pair order five/six
times across eleven rounds. Each process performs a full warmup. Repeated calls
cycle through seeds 12345-12352, and the warmup seed is 77881.

| Kernel | Before ML ms | After ML ms | C -O3 ms | C++ -O3 ms | After ML / C, paired | After ML / C++, paired |
| --- | --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 4.684 | 4.321 | 0.866 | 0.870 | 4.986x | 5.005x |
| `mandelbrot` | 6.971 | 5.576 | 0.849 | 0.815 | 6.635x | 7.137x |

| Kernel | Primary pair min / max | Primary IQR before / after | Separate pair min / max | Separate IQR before / after | C / C++ IQR |
| --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 0.945x / 1.029x | 7.67% / 6.57% | 0.972x / 1.293x | 20.66% / 5.70% | 5.00% / 6.22% |
| `mandelbrot` | 0.724x / 1.670x | 27.99% / 32.27% | 0.939x / 1.364x | 15.87% / 3.98% | 5.17% / 5.94% |

Relative IQR is interquartile range divided by median. Pair min/max includes all
observed pairs. These current ratios describe only the two kernels, inputs and
settings. They do not establish a universal MiniLang/C/C++ ratio. The separate
series has its own schedule; its absolute times should not replace values in
the primary table. [Full separate summary](benchmarks/float_consumers/float_comparison/summary.json)
and [fresh-reference provenance](benchmarks/float_consumers/float_comparison/c_reference_builds.json)
retain full precision, commands and hashes.

## Correctness, floating-point status and platform boundary

Python unittest discovery ran 61 tests: 58
passed and 3 platform/optional-tool skips. Structural checks,
native Linux executable/path/import/cache regressions and the final gates pass.
Bootstrap and native self-rebuild are byte-identical at
**66,393,008 bytes**, SHA-256
`3b308c32aed932fe1633800467a6c0ad14f33201cf06cf2df217025ff9551712`.

| Configuration group | Configurations | Compared images | Runtime coverage here |
| --- | --- | --- | --- |
| Linux x64 | 38 | 114 | 38 output comparisons with Phase 7 |
| Windows x64 | 21 | 63 | Compile-only |
| MinUX x64 | 21 | 63 | Compile-only |
| Windows x64, concurrent GC | 16 | 48 | Compile-only |
| Total | 96 | 288 | 38 Linux cases |

Each configuration compares Python, native monolithic and native MLO images
byte for byte. Linux executes one representative of each identical trio and
compares its output to Phase 7. Windows/MinUX and concurrent-GC coverage is
explicitly compile-only. The concurrent cases retain the existing raw-loop
exclusion; they do not establish threaded raw-loop execution.

A final removal of one redundant fixture EOF newline was separately recompiled
and executed. Its three images match the original Linux matrix exactly; that
followup is excluded from the unique configuration/image totals above.

The new [consumer fixture](../tests/numeric_float_consumer.ml) contains fifteen
optimized functions. It covers both child positions, chained canonicalization,
fresh cached siblings, alias fanout, strict output roots, both-arithmetic-child
boundaries, all six comparisons, zero/false-first conditions, repeated late
rollback, signed61 wrapping, exact integer precision above 2^53, NaN, infinities,
negative zero, subnormals and both literal representations. Existing cache and
nested-loop forced-GC tests remain in the matrix; this fixture adds no new
forced-GC iteration count.

A separate native Linux MXCSR comparison covers 17 probes under
16 control modes: four rounding modes crossed with default,
DAZ, FTZ and DAZ+FTZ. All **272 before/after pairs** agree
on control bits, sticky exception flags, result tags and iteration counts.
Inputs include signaling/quiet NaNs and an exact float32 subnormal literal.
Exceptions are masked. This check does not compare exact numeric result bits
and makes no claim about trap/signal behavior; the semantic fixture separately
checks numerical results. An earlier diagnostic driver failed while formatting
infinity in the baseline. The final bundled driver prints flags/tags/counts and
retains every probe/mode pair. [MXCSR observations](benchmarks/float_consumers/mxcsr/consumer_mxcsr.json)
include the exact sources and reproduction method.

Preparation passes 294 primary correctness cases (including thirty full-size
cases), eighty ablation cases, thirty-six separate MiniLang cases and thirty-six
C/C++ cases. All 474 timed
runs (330 primary, 88 separate, 56
ablation) pass measured and warmup checksums. The 24 transition pairs, twenty GC
observations, sampling processes and MXCSR observations are separate totals.
[Validation summary](benchmarks/float_consumers/validation_summary.json)
records the tested boundary.

Remaining work includes controlled-hardware measurements, real application
workloads, Windows/MinUX runtime checks and platform release packaging. The
accepted syntactic loop forms and state/root exclusions remain unchanged.
Broader mixed-state loops, calls and thread safepoints require separate
correctness work. Future comparisons should freeze this completed source pair
and preserve checksum, parity, exact ablation and timing-control discipline.
