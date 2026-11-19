# Float normalization: remove a dead representation comparison

## Outcome and scope

This change removes one unused comparison from the bounded raw numeric normalizer
in both MiniLang compilers. Each affected normalization site retains the integer
guard and both conversion instructions in the float32 probe. Its encoded sequence shrinks from
32 to 28 bytes. Arithmetic order, integer canonicalization, float representations,
rollback, entry guards and supported loop shapes are unchanged.

Both final series favor the candidate. Recurrence's paired ratios correspond to approximately 9.7–10.2% less elapsed time; Mandelbrot's correspond to 5.6–6.7% less. The repeated direction supports this bounded change. The size of the Mandelbrot gain remains less certain because its run-to-run spread and unchanged-control variation are substantial. No application-wide speedup is inferred.

| Series | Kernel | Before ms/call | After ms/call | Paired speedup | Faster pairs | Paired min / max | Relative IQR before / after |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Primary, 15 cases | `float_recurrence` | 4.252 | 3.852 | 1.113x | 10/11 | 0.974 / 1.357 | 2.33% / 9.87% |
| Primary, 15 cases | `mandelbrot` | 5.611 | 5.392 | 1.059x | 11/11 | 1.009 / 1.175 | 21.35% / 16.02% |
| Separate C/C++ series | `float_recurrence` | 4.366 | 3.883 | 1.107x | 11/11 | 1.040 / 1.213 | 5.12% / 2.45% |
| Separate C/C++ series | `mandelbrot` | 5.633 | 5.173 | 1.072x | 10/11 | 0.859 / 1.243 | 16.20% / 13.50% |

The independent confirmation contains 330 primary runs (15 cases, two variants,
eleven rounds) and 88 separate float/C/C++ runs (two cases, four variants, eleven
rounds). Every checksum and warmup is valid. Timing used CPU 2 on the shared Linux
x86-64 VM, with other project builds, tests and sampling suspended.

The table separates the independent fifteen-case confirmation from the separate
four-variant float/C/C++ series. A paired speedup divides the before time by the
after time within each round, then takes the median. The ratio of the two separate
time medians is a different statistic. Faster-pair counts, complete pair ranges
and relative interquartile ranges are retained so that the shared-host variation
remains visible. These results describe the measured kernels and this source
boundary; earlier phase ratios must not be multiplied into a cumulative claim.

13 of the fifteen primary benchmark images are byte-identical. Their paired ratios range from 0.949x to 1.070x. These unchanged programs expose host/timing variation; their ratios are not compiler gains or regressions.

## Frozen source and artifact boundary

| Compiler | Before: completed Phase 8 | After: measured source |
| --- | --- | --- |
| MiniLangCompilerPy | [`6bdcab1eaf91c117fc5a5295ed4345c81d78509e`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/6bdcab1eaf91c117fc5a5295ed4345c81d78509e) | [`1da8b8bced4ca7f356b57c4c57e656b11e35e359`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/1da8b8bced4ca7f356b57c4c57e656b11e35e359) |
| MiniLangCompilerML | [`c92a678308d408c4f566f007c8ab16fcb5298ca2`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/c92a678308d408c4f566f007c8ab16fcb5298ca2) | [`0c0726f272a157cc13a7b82d7b076799cd60bfb0`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/0c0726f272a157cc13a7b82d7b076799cd60bfb0) |

The measured baseline native compiler is the verified Phase-8 artifact, reused
with SHA-256 `3b308c32aed932fe1633800467a6c0ad14f33201cf06cf2df217025ff9551712`
and size 66,393,008 bytes. It was not rebuilt for this experiment. Its exact source
pair is pinned above. New benchmark programs and C/C++ references were built for
this round. The after-source commits include implementation and regression
changes; this report and its evidence are published afterwards without changing
the measured compiler sources. Source fingerprints and image hashes are retained
in [the evidence directory](benchmarks/float_probe/README.md).

## Current profiling chose the next target

The earlier profile preceded Phase 8. This round first sampled the completed
Phase-8 programs, using unchanged native executable bytes and byte-identical
Python images for their label maps. Each kernel retained its original sixteen
calls per process and full warmup. Three software user-CPU-clock periods
(997,003, 1,000,003 and 1,009,003 ns), sixteen processes per period, produced
96 checksum-valid processes, 8,245 samples and no lost samples.

| Kernel | Samples | Raw normalizer share | Integer guard | f32 probe | Ordinary path | Integer rejoin |
| --- | --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 3,640 | 76.90% | 38.87% | 38.02% | 0.00% | 0.00% |
| `mandelbrot` | 4,605 | 47.97% | 30.73% | 17.24% | 6.28% | 1.04% |

These are approximate sampled instruction-pointer shares, including startup,
warmup and printing. Software-clock interrupts have skid and samples may be
correlated. Runtime-function samples have no causal caller attribution. Hardware
cycle events were unavailable. A large normalizer share does not mean that the
same fraction of runtime can be removed, and it does not isolate the cost of the
last comparison instruction.

The current profile supports investigating normalization before extending mixed
integer/float loop eligibility. Phase 8's remaining 8,697 ordinary Mandelbrot
iterations were an event count in one full-size probe, not a measured time share.
The new sampling adds a time-oriented observation without treating either metric
as a universal characterization. [Baseline profile](benchmarks/float_probe/profiles/summary.json)

## A rejected idea remains in the record

The first preselected experiment cleared scratch XMM destinations before legacy
scalar conversions to investigate possible preserved-upper-lane dependencies.
It tested unchanged code, XMM1 only, XMM2 only, XMM3 only, XMM2+XMM3 and all three.
Seven balanced rounds on both original kernels produced 84 valid timed runs,
after 120 correctness observations.

| Kernel | All scratch registers: paired speedup | Faster pairs |
| --- | --- | --- |
| `float_recurrence` | 0.991x | 3/7 |
| `mandelbrot` | 0.939x | 1/7 |

No tested subset established a useful gain; combined clearing was slower for
Mandelbrot in this pilot. None of those XOR instructions was added to the
compilers. This is a result on the measured AMD EPYC 9V74 VM, not a claim that
dependency breaking is ineffective on every processor. All raw rows and all
variants are retained in [the rejected experiment](benchmarks/float_probe/experiments/scratch_zero/summary.json).

The next, separately prescribed trial removed only the trailing comparison.
Its two variants, eleven balanced rounds and two kernels produced 44 valid
timings after 40 correctness observations:

| Kernel | Before ms/call | After ms/call | Paired speedup | Faster pairs |
| --- | --- | --- | --- | --- |
| `float_recurrence` | 4.182 | 3.723 | 1.128x | 11/11 |
| `mandelbrot` | 5.487 | 5.226 | 1.044x | 10/11 |

This exploratory result selected the candidate. The independent confirmation at
the start of this report was run after implementation in both compilers. The
pilot was not pooled into that confirmation, and no slow observations were
silently removed or repeated. [Candidate-selection pilot](benchmarks/float_probe/experiments/dead_compare/summary.json)

## Why the comparison is redundant

The original raw normalizer first truncates XMM0 to a 64-bit integer, converts
that integer back to double, and compares it with XMM0. Its equality/unordered
branch is required: exact integers and NaNs retain the existing replay or local
integer-canonicalization behavior, including signed-61-bit wrapping. That complete
guard is unchanged.

On the other path, `CVTSD2SS XMM2,XMM0` and `CVTSS2SD XMM3,XMM2` probe the float32
representation. Materialization would use a following comparison to choose
immediate float32 or boxed float64. A raw consumer needs the original double in
XMM0 in either case. In this bounded emitter, none of its callers consumes the
probe comparison's EFLAGS: arithmetic normalization, comparison roots and loop
counter conditions establish their own flags before branching.

Removing an unused comparison still requires checking floating-point status.
The [Intel SDM UCOMISD definition](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf#page=717)
lists signaling-NaN invalid and denormal exceptions. Applying those rules to the
current control flow gives the following proof. NaNs leave at the retained first
comparison. A non-NaN float32 widened to double is zero, a normal double, or
infinity, never a double subnormal. Any denormal XMM0 has already encountered the
retained first comparison under the same MXCSR controls; no intervening operation
clears status. The removed comparison therefore adds no new sticky exception bit.

Both conversion instructions remain. They can contribute precision, overflow,
underflow or denormal status and cannot simply be dropped under the same argument.
The optimization introduces no new arithmetic instruction, reassociation, fused
operation, ISA requirement, allocation, object-layout change or GC policy. It
does not broaden raw loops to calls, thread safepoints or additional mixed states.

## Exact ablation and emitted code

The existing Python `_opt_emit_float_tree_normalize` method is the inverse
ablation point: a wrapper calls the new method and appends the original
`UCOMISD XMM0,XMM3`. It adds no labels or other instructions. Rebuilt disabled
images must match the frozen baseline byte for byte, while current Python and
native images must match each other.

| Kernel | Executable segment before / after | Segment bytes removed | Raw / fallback sites | Instruction bytes removed |
| --- | --- | --- | --- | --- |
| `float_recurrence` | 214,307 / 214,179 | 128 | 12 / 14 | 104 |
| `mandelbrot` | 77,802 / 77,770 | 32 | 8 / 5 | 52 |

All affected sites in these images belong to the benchmark function: 26 for
recurrence and 13 for Mandelbrot. The fallback counts denote raw-tree normalizers
inside the retained general loop path. Removing four bytes per site deletes
104 and 52 instruction bytes respectively. The existing 16-byte user-function and
32-byte runtime alignment makes the complete text-segment deltas 128 and 32
bytes. Segment-size differences must not be divided by four to infer site counts.
[Complete byte and alignment audit](benchmarks/float_probe/float_comparison/whole_image_normalizers.json)

The unchanged branch decisions also mean that this change is not presented as another reduction
in integer rejoins, allocations or collections. All twenty separate untimed GC
observations have equal before/after allocation and collection counters. Full-size
Mandelbrot with eight repeats collects three times in both variants; recurrence
collects zero times. Counter deltas after a collection are not cumulative
allocation totals. [Static code and exact controls](benchmarks/float_probe/float_comparison/code_summary.json)

## Real application workloads

This round adds the shipped compiler and formatter as actual MiniLang
applications. Each native compiler compiles the frozen `tools/mlfmt.ml` with the
same standard library, monolithic emission and incremental compilation disabled.
Each resulting formatter processes the same real `mlc/codegen/codegen_stmt.ml`
into a separate output file. The input is 488,825 bytes and 12,155 lines; no
repository source is formatted in place. Every formatted output must be exactly
equal, and each compiler's generated formatter must be stable across runs.

| Workload | Before seconds | After seconds | Paired wall speedup | Faster pairs | Paired min / max | Relative IQR before / after |
| --- | --- | --- | --- | --- | --- | --- |
| Compile the shipped formatter | 2.339 | 2.327 | 0.965x | 3/7 | 0.869 / 1.097 | 8.06% / 17.71% |
| Format compiler source | 0.158 | 0.145 | 0.996x | 3/7 | 0.639 / 1.606 | 42.23% / 70.59% |

Neither application workload establishes a speedup. The compilation workload's paired point estimate is 0.965x, with the candidate faster in 3/7 pairs; the slightly lower separately computed after median is not a paired gain. The produced formatters are byte-identical (1,704,512 bytes), yet their paired timing ratios span 0.639–1.606x. This real-tool control demonstrates substantial host variation. The data extend application coverage without demonstrating a benefit from this numeric change in these two tools.

Seven paired rounds produce 28 measured processes after four separate warmups.
These are complete process wall times, including startup and cached filesystem
I/O. They are not the numeric benchmarks' internal time per kernel call. The
runner also records user/system CPU time and Linux peak RSS. Median compiler
process peak RSS was 181,700 KiB before and 187,716 KiB after; both formatter
variants recorded 16,128 KiB. These whole-process high-water observations do not
measure allocation volume or managed heap size, and establish no causal
allocation/GC effect of this change. Pair order and workload order alternate,
all rows are kept, and input/output hashes are rechecked.

A byte-identical formatter is an application control: any timing difference in
that case cannot come from changed formatter code. Compilation and formatting
primarily exercise different work from floating-point kernels. Their results
must not be generalized to games, databases or all MiniLang applications.
[Application evidence](benchmarks/float_probe/application/applications.json)

## Remaining distance to strict C and C++

| Kernel | MiniLang after ms/call | C ms/call | C++ ms/call | Paired after/C | Paired after/C++ |
| --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 3.883 | 0.880 | 0.867 | 4.454x | 4.516x |
| `mandelbrot` | 5.173 | 0.834 | 0.881 | 6.378x | 6.081x |

The separate reference builds retain the original C11/C++17 kernels and drivers,
separate translation units, no LTO, `-O3 -march=x86-64 -mtune=generic`,
`-ffp-contract=off` and `-fno-fast-math`. Original calibrated repetitions, inputs,
seed cycles, checksum oracles and full warmups remain fixed. Each language's
elapsed time is normalized per kernel call. These are comparisons of specific
programs and their numeric models, not an intrinsic language-speed constant.

## Correctness and platform boundary

The completed matrix has **96 configurations, 288 compared images and 38 Linux runtime cases**. Each configuration requires byte equality between Python, native monolithic and native MLO output. Linux outputs are compared with the frozen Phase-8 compiler. Windows/MinUX and Windows concurrent-GC configurations are compile-only; they establish no target-runtime or threaded execution result.

Bootstrap and self-hosted native compilers are byte-identical: 66,393,008 bytes, SHA-256 `2911090e0beaf289a289fee361ee8fc4d6d771765785cef71e3cb925a32256ff`. The full validation summary retains unit-test, structural, path/import/cache, semantic, exact-ablation and floating-point-status results without merging their different counts. Python unit tests report 61 tests: 58 passed and 3 skipped.

The original consumer MXCSR driver checks 17 probes under sixteen combinations
of rounding, DAZ and FTZ, with exceptions masked. The additional targeted driver
checks 36 raw-tree/raw-loop cases under the same sixteen control combinations:
576 before/after pairs and 1,728 total observations including the Python-built
variant. It compares exact float32/float64 payload bits, full signed-61 integer
values, boolean representations, iteration counts, sticky flags and control bits.
Its byte inspection checks seventeen complete 28-byte normalizers across eight
functions and rejects a retained trailing comparison. Neither driver establishes
general trap delivery or instruction-address equivalence.
[Targeted floating-point evidence](benchmarks/float_probe/mxcsr/results.json) Semantic fixtures also retain NaNs, infinities,
negative zero, signed-61 wrapping, integer transitions, comparisons, zero trips,
late replay, aliases and existing GC-root cases. Updated structural checks
require both f32 converters and the retained first comparison/branch. Exact
image controls separately verify the inverse ablation of the removed comparison.

[Validation summary](benchmarks/float_probe/validation_summary.json) records the
separate totals and limits. Sampling, untimed observations, warmups, exploratory
timings, primary timings and application processes are not combined into one
misleading test count.

## Next boundary

Controlled-hardware measurements remain useful for estimating gain size beyond
this shared VM. Wider application coverage, Windows/MinUX runtime checks and
platform release packages remain open. Broader numeric-state eligibility or
f32-probe elimination needs a separate proof and experiment. This source pair
provides the fixed baseline for that next decision.
