# Bounded register caching for float-loop definitions

Date: 2026-11-19. This seventh optimization round compares with the completed
[Phase 6 checkpoint](performance_float_nested.md). It preserves accepted loop
shapes and numeric semantics while reducing data movement inside existing
call-free raw intervals. Both compiler implementations are updated.

## Source boundary and measured result

| Repository | Before: completed Phase 6 | After: measured Phase 7 source |
| --- | --- | --- |
| MiniLangCompilerPy | [`c6c71076121111a687b61386ef2735f12c73164f`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/c6c71076121111a687b61386ef2735f12c73164f) | [`f5297ba9df6112aa53e5652c1011811d05a28fc4`](https://github.com/MiniLangProject/MiniLangCompilerPy/commit/f5297ba9df6112aa53e5652c1011811d05a28fc4) |
| MiniLangCompilerML | [`2c7c2637cebc8d0edcbc480cbfe1cb02a8523f1e`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/2c7c2637cebc8d0edcbc480cbfe1cb02a8523f1e) | [`30a7325cdfe5ca82a770a3dd8f5ba305d1148dcf`](https://github.com/MiniLangProject/MiniLangCompilerML/commit/30a7325cdfe5ca82a770a3dd8f5ba305d1148dcf) |

These source commits contain the implementation and regression coverage. This
report, measurement records and reproduction helpers are added afterwards
without changing that measured source. The [reproduction guide](benchmarks/float_cache/README.md)
uses the report revision's helpers with these exact compiler source pairs.

| Kernel | Primary before ms | Primary after ms | Primary paired ratio | Faster pairs | Separate paired ratio | Faster pairs |
| --- | --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 4.302 | 4.167 | 1.002x | 6/11 | 1.001x | 6/11 |
| `mandelbrot` | 6.654 | 6.415 | 1.043x | 10/11 | 1.053x | 10/11 |

The change is retained for a **modest Mandelbrot improvement**: the two
series' paired ratios are 1.043x and
1.053x, with 10 of 11
pairs favoring the cache in each. These correspond to about
4.12% and
5.05%
less elapsed time by the paired statistic. **Recurrence has no established
runtime benefit**: its paired medians are close to one and only 6 of 11 pairs
favor the cache in each series, despite a verified reduction in memory
instructions. The result is bounded to these inputs and this shared host.

The statistic is the median of eleven within-round before/after ratios; values
above one favor the cache. It is not the ratio of the separately reported time
medians. The primary suite contains fifteen unchanged source programs. Only
recurrence and Mandelbrot images change; thirteen byte-identical images remain
as timing controls. This is a new Phase 6-to-Phase 7 comparison with the baseline
rerun in the same evaluation. Historical ratios are not multiplied into a
cumulative speedup.

## What the untimed diagnostics establish

Separate diagnostic builds retain the original benchmark function and use a
one-call driver. Counter increments are `PUSHFQ; INC qword [RIP+counter]; POPFQ`:
they preserve arithmetic flags, GPRs, XMM registers and MXCSR, restore RSP before
the original instruction, allocate nothing and make no calls. Counters are
non-atomic and restricted to accepted single-threaded raw loops. These images
are never used for runtime measurements.

Twenty-four before/after probe pairs cover both kernels, sizes 1, 17, 67 and
their full-size inputs, and seeds 0, 12345 and 2147483647. Every instrumented
checksum agrees with its uninstrumented diagnostic program and an independent
oracle. Guard, normalization, raw/ordinary iteration, exit, reentry and
materialization event counts agree between compiler versions in every pair.
The changed counters are exactly the expected body loads/stores, commit loads
and register copies. [Probe data](benchmarks/float_cache/residual_costs/comparison.json)
records the comparison and invariant counter set.

For one full-size call with seed 12345, counts across entry, raw evaluation,
commit and materialization are:

| Kernel | n | Raw commits | Ordinary iterations | Loads before | Loads after | Stores before | Stores after | Removed memory instructions |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 260,986 | 260,986 | 0 | 2,609,863 | 2,087,891 | 1,565,919 | 1,304,933 | 782,958 |
| `mandelbrot` | 126 | 254,399 | 24,195 | 4,184,452 | 2,658,058 | 2,221,168 | 1,712,370 | 2,035,192 |

The full-size recurrence stays in the raw path for every iteration. Mandelbrot
performs 254,399 raw commits and
24,195 ordinary iterations in both versions.
Its condition has 15,498 normalization misses; the raw
body has no normalization misses in these recorded original-kernel probes.
Thus the change does not skip guards or execute different iterations. Remaining
condition/ordinary work is still visible.

These are instruction and event frequencies, **not CPU-time shares**. Removing
a third of a region's memory instructions does not imply a third less elapsed
time. The separate uninstrumented paired series measures the resulting runtime.

## Bounded register plan

The raw arithmetic normalizer uses XMM0-XMM3. Expression evaluation saves a
left operand in XMM4 or XMM5 when its right operand is another arithmetic tree.
The new planner computes maximum saved-left pressure across every body
definition and both escape-comparison operands. It includes the comparison's
own saved left operand while evaluating a right-hand tree.

| Maximum saved-left pressure | Registers available for fresh definitions |
| --- | --- |
| 0 | XMM4 and XMM5 |
| 1 | XMM5 |
| 2 | None; retain the previous emission |

At most two fresh definitions are selected. Their score is the number of reads
through immutable definition environments, plus their final output commits.
Higher scores win; ties use source-definition order. Zero-use definitions are
not selected. Registers are reserved for the entire raw iteration; this bounded
plan does not attempt cross-iteration allocation or general live-range reuse.

After a selected definition's unchanged normalization succeeds, its result is
copied from XMM0 to its register instead of a staged stack slot. Later fresh-value
reads copy from that register. Commit writes directly to the existing committed
slot. Unselected definitions use the previous staged-memory path. Alias
references share their definition's register; output groups retain their existing
materialization behavior.

For the original kernels, a successful iteration has these static raw-arena
memory instructions, including its condition when applicable:

| Kernel | Raw loads before / after | Raw stores before / after | Total reduction | Extra register copies | Raw normalizers, unchanged |
| --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 10 / 8 | 6 / 5 | 18.75% | 2 | 12 |
| `mandelbrot` | 16 / 10 | 8 / 6 | 33.33% | 6 | 8 |

The [before sites](benchmarks/float_cache/residual_costs/before/sites.json) and
[after sites](benchmarks/float_cache/residual_costs/after/sites.json) retain these
static instruction counts and raw-arena sizes.

Register copies partly replace memory instructions; not every removed memory
instruction disappears from the instruction stream. Dynamic counts agree with
three removed raw-memory instructions per recurrence commit and eight per
Mandelbrot commit. Recurrence selects one definition in XMM5; Mandelbrot selects
two in XMM4/XMM5.

## Preserved semantics, ABI and GC boundaries

The committed memory bank remains the authoritative checkpoint. Cached fresh
values are tentative until all arithmetic checks for the iteration succeed.
A bailout materializes only the last fully committed state, never tentative
register contents. The counter advances only at the existing commit point.
Zero trips, false first conditions, write-only outputs and alias identity retain
their previous handling. Compound-loop replay still runs one ordinary iteration
before guarded reentry; simple counted loops retain their permanent fallback.

Every arithmetic node keeps the exact integer/NaN normalization decision and
binary32 roundtrip probe. Their order and floating-point status effects are
unchanged. Arithmetic is not reassociated or fused. Integer precision, signed61
wrapping, signed zero, NaN, infinities and error behavior remain subject to the
existing checks and fallback paths.

XMM0-XMM3 remain scratch, while XMM6-XMM11 and existing promoted integer homes
are untouched. Cached XMM4/XMM5 values cross no call or safepoint. Normalization,
accepted literal loads and debug-line updates do not overwrite the reserved
registers. Register and memory moves preserve arithmetic flags and MXCSR. No additional
function-state fields, frame slots, GC roots, runtime layouts or collector
changes are introduced.

Accepted-loop limits remain those of Phase 6: pure bounded assignments,
supported counted/compound conditions and existing binding/type guards. Calls,
index/member access, old-value output aliases, mixed raw integer/float state,
native-thread/concurrent-GC programs and unsupported control flow keep their
existing lowering. This round does not broaden that acceptance boundary.

## Primary performance series

All original inputs, language-specific repeat counts, eight-seed cycles and
checksum oracles are retained. Times are milliseconds per kernel call. Each
process performs a full untimed warmup. The base seed is 12345; repeated calls
cycle through seeds 12345-12352, and the warmup uses seed 77881 (12345 + 65536).
Internal `CLOCK_MONOTONIC` timing excludes compilation, process startup and
printing. No observations are discarded as outliers and no additional timing
series is selected to improve the result.

| Kernel | n | Calls per process | Before ms/call | After ms/call | Paired before/after | Identical images |
| --- | --- | --- | --- | --- | --- | --- |
| `byte_copy` | 8,388,608 | 24 | 22.101 | 22.522 | 0.985x | yes |
| `byte_search` | 8,388,608 | 56 | 5.987 | 6.099 | 0.976x | yes |
| `array_scan` | 194,470 | 16 | 34.459 | 34.914 | 0.968x | yes |
| `array_scatter` | 225,245 | 16 | 34.049 | 35.085 | 0.991x | yes |
| `sieve` | 1,977,051 | 16 | 24.528 | 24.470 | 0.998x | yes |
| `heapsort` | 82,396 | 16 | 43.859 | 45.022 | 0.961x | yes |
| `escaped_nodes` | 262,144 | 40 | 10.547 | 10.474 | 1.001x | yes |
| `int_mix` | 2,097,152 | 32 | 14.817 | 14.416 | 1.009x | yes |
| `branch_mix` | 1,909,761 | 16 | 23.743 | 23.693 | 1.007x | yes |
| `float_recurrence` | 260,986 | 16 | 4.302 | 4.167 | 1.002x | no |
| `mandelbrot` | 126 | 16 | 6.654 | 6.415 | 1.043x | no |
| `recursive_tree` | 1,265 | 16 | 51.295 | 51.348 | 1.004x | yes |
| `ascii_parse` | 262,144 | 16 | 32.529 | 33.977 | 0.976x | yes |
| `string_concat` | 7,262 | 24 | 34.319 | 35.481 | 0.987x | yes |
| `string_builder` | 114,195 | 16 | 29.726 | 29.962 | 1.011x | yes |

The thirteen identical controls have paired medians from
0.961x to
1.011x; their differences
cannot result from changed program bytes. Across primary cases, relative IQR
ranges from 2.19%
to 15.88%.
Relative IQR is the interquartile range divided by the median. The pair ranges
below include every observed pair, including the slow outliers.

| Kernel | Primary paired min / max | Primary relative IQR before / after | Separate paired min / max | Separate relative IQR before / after |
| --- | --- | --- | --- | --- |
| `float_recurrence` | 0.942x / 1.179x | 2.87% / 5.81% | 0.849x / 1.043x | 3.09% / 3.27% |
| `mandelbrot` | 0.976x / 1.303x | 3.90% / 3.63% | 0.967x / 1.644x | 11.96% / 6.74% |

Primary rounds shuffle cases and alternate before/after order. Timed children
run on CPU 2 in a shared Linux x86-64 VM. No other compiler,
regression or benchmark job from this evaluation runs during either timing
series, but unrelated host load and CPU frequency are uncontrolled. Small
differences must be interpreted alongside controls and dispersion. Full-precision
[summary](benchmarks/float_cache/primary/summary.json) and
[records](benchmarks/float_cache/primary/measurements.jsonl) are provided.

## Separate C and C++ comparison

C and C++ references were **freshly reconstructed** from the checked-in original
kernel and driver sources. They are not claimed to be the binary files used in
earlier rounds. Recorded toolchain versions are
`g++ (Debian 14.2.0-19) 14.2.0`; `gcc (Debian 14.2.0-19) 14.2.0`.
Both use `-O3 -march=x86-64 -mtune=generic -ffp-contract=off -fno-fast-math`, C11
or C++17, separate translation units and no LTO. Commands and source/binary
hashes are in [reference-build provenance](benchmarks/float_cache/float_comparison/c_reference_builds.json).
Thirty-six additional C/C++ checksum cases passed before measurement.

| Kernel | n | MiniLang calls | C calls | C++ calls |
| --- | --- | --- | --- | --- |
| `float_recurrence` | 260,986 | 16 | 416 | 408 |
| `mandelbrot` | 126 | 16 | 440 | 432 |

Here `n` is the recurrence iteration count and the Mandelbrot raster side
length (126 by 126 at the recorded full size).

Each variant keeps its original calibrated count; times are normalized per
call. The separate schedule rotates and reverses four variants: each pair runs
in each relative order five or six times across eleven rounds; individual
positions occur two to four times. This series runs separately from the primary
series; its absolute times should not be substituted into the primary table.

| Kernel | Before ML ms | After ML ms | C -O3 ms | C++ -O3 ms | After ML / C | After ML / C++ |
| --- | --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 4.220 | 4.215 | 0.865 | 0.864 | 4.945x | 4.827x |
| `mandelbrot` | 6.693 | 6.341 | 0.832 | 0.857 | 7.451x | 7.509x |

| Kernel | C / C++ relative IQR | After ML / C paired min / max | After ML / C++ paired min / max |
| --- | --- | --- | --- |
| `float_recurrence` | 3.50% / 1.66% | 4.745x / 5.872x | 4.513x / 5.773x |
| `mandelbrot` | 5.81% / 6.90% | 7.064x / 8.564x | 6.866x / 8.461x |

These current within-round MiniLang/C and MiniLang/C++ ratios describe only
these kernels and settings. They do not establish a universal language ratio.
The [separate summary](benchmarks/float_cache/float_comparison/summary.json)
retains full precision and paired ratio ranges.

## Allocation, GC and code size

This change removes intermediate stack traffic, not additional heap boxing.
The twenty GC probes retain their recorded allocation/collection counters.
At n=1000 one recurrence call still adds 8 blocks / 192 frontier bytes without
collection. At n=17 one Mandelbrot call still adds 3,025 blocks / 72,600 frontier
bytes without collection. Eight full-size recurrence calls collect zero times;
eight full-size Mandelbrot calls collect four times in both versions. After
collection, block/frontier deltas are net heap changes, not cumulative allocation
counts. [GC records](benchmarks/float_cache/float_comparison/gc_diagnostics.json)
retain the original counters and checksums.

| Kernel | Executable segment before | After | Difference | Cached definitions / registers | Raw frame area |
| --- | --- | --- | --- | --- | --- |
| `float_recurrence` | 214,947 | 214,947 | +0 bytes | 1 / xmm5 | 64 bytes |
| `mandelbrot` | 77,930 | 77,898 | -32 bytes | 2 / xmm4, xmm5 | 96 bytes |

The frame areas remain 64/96 bytes and are not heap allocations. Static
normalizers remain twelve raw / fourteen fallback for recurrence and eight raw /
five fallback for Mandelbrot. Static sites are distinct from dynamic executions.
Code summaries use Python label dumps whose complete images are byte-identical
to the native variants.

Disabling only `_opt_float_loop_registers` reproduces frozen Phase 6 images for
both kernels, including frame layout. Disabling nested discovery or the entire
loop optimizer would use an earlier transformation boundary and is not this
ablation. [Code evidence](benchmarks/float_cache/float_comparison/code_summary.json)
records both exact controls.

## Validation and limits

The final gates passed. Unittest discovery ran 61 cases: 58 passed and three
platform/optional-tool skips. Structural checks and native Linux executable-mode,
path, import and cache regressions passed. Bootstrap and native self-rebuild
are byte-identical at **66,323,360 bytes**.

| Configuration group | Configurations | Compared images | Runtime checks here |
| --- | --- | --- | --- |
| Linux x64 | 37 | 111 | 37, with Phase 6 output comparison |
| Windows x64 | 20 | 60 | Not executed |
| MinUX x64 | 20 | 60 | Not executed |
| Windows x64, concurrent GC | 15 | 45 | Not executed |
| Total | **92** | **276** | **37 Linux cases** |

Each configuration compares Python, native monolithic and native MLO output
byte for byte. Runtime counts configurations, not three executions of each
identical image. Windows/MinUX and concurrent-GC coverage is explicitly
compile-only. The [validation summary](benchmarks/float_cache/validation_summary.json)
records that boundary.

The new [cache fixture](../tests/numeric_float_cache.ml) has nine candidate
functions covering repeated definitions, alias fan-out, late rollback, tied
scores, body/condition saved-left pressure zero through two, zero trips, special
floats and coexistence with all six promoted integer homes XMM6-XMM11. Structural
checks require permitted cache registers, one marker per selected definition,
the expected staged stores and unchanged normalization/commit/alias boundaries.
Twelve forced-GC iterations retain output groups and aliases across observed
collection, followed by explicit post-collection verification. Existing loop,
reentry, normalization and exclusion tests remain in the matrix.

Preparation passed 294 primary correctness checks, including 30 full-size
checks, 36 separate MiniLang float checks and 36 fresh C/C++ reference checks.
All 418 timed runs (330 primary and 88 separate) passed measured and warmup
checksums. The 24 paired untimed instrumentation probes are separate from these
timing and correctness totals.

Remaining work includes controlled-hardware measurements, Windows/MinUX runtime
tests and larger real application workloads. Normalization and representation
transition counts motivate further experiments but do not identify a dominant
CPU cost. Broader loop forms, mixed state, calls and thread safepoints remain
separate correctness work. Future comparisons should freeze this completed
source pair and retain checksum, parity, ablation and timing-control discipline.
