# Local code-generation optimizations — 30 September 2026

Evaluation of development work after v1.2.13, included in release 1.2.14.
No language or std API change. Measurements and image hashes below describe
the pre-version-stamp builds; see [release notes](../../RELEASE_NOTES_1.2.14.md)
for the separately verified, release-stamped compiler hashes.

## Implementation and limits

Both native backends implement the same instruction selection:

- Proven integer floor division by a positive constant below 2^60: retain the
  existing power-of-two shifts; use reciprocal multiplication with a quotient
  correction for other positive constants. Dynamic, negative, zero and wrapped
  nonpositive divisors retain their checked fallback. The ordinary / operator
  is unchanged.
- Integer decimal formatting: exact unsigned multiplication by
  0xCCCCCCCCCCCCCCCD followed by a high-product shift replaces division by ten,
  both in str/value conversion and the print helper. Reciprocals are hoisted
  outside digit loops and reloaded after allocation.
- Expression-local common-subexpression elimination (CSE): identical trees of
  local unboxed integers, integer literals and +, -, *, &, |, ^ are evaluated
  once. Only pairs of compound expressions trigger the comparison; trivial
  leaf pairs do not pay for the analysis. It is bounded to depth three, needs no persistent map and
  does not cross statements or control-flow boundaries. Globals, captures,
  calls, heap reads, floats and fallible operations are excluded.
- Redundant expression-temporary stores: the completed right operand moves
  directly from RAX to R11 instead of being stored and immediately reloaded.
  A literal integer right operand is loaded directly into R11; the left operand
  can remain in R10. General right expressions retain the left operand's rooted
  stack home and original evaluation order.

This is **not** a general dead-local-store pass, global value numbering or a
function-wide register allocator. It delivers conservative parts of those
ideas without introducing a whole-program IR or new retained analysis state.
It does not implement scalar replacement, PGO or automatic vectorization.

## Division argument

Let B = 2^60, d > 1 and 0 <= u < B. With m = ceil(B/d), the estimate
floor(u*m/B) is the exact quotient or one too large. Comparing estimate*d
against u and decrementing when necessary makes it exact. The correction
product is below 2B, so it fits in a native 64-bit register.

For a negative decoded dividend n, use u = ~n and complement the final
quotient: floor(n/d) = ~floor((~n)/d). This covers n = -2^60 without negating
an out-of-domain MiniLang integer. The compiler calculates m as
((B-1) div d)+1, which also fits its own signed-61-bit integer representation.
The generated MUL retains both halves of its 128-bit product.

## Verification

- Python suite: 155 passed, zero failed/skipped.
- ML suite: 136 core tests passed; complete outer runner passed, including
  Windows/Linux runtime, GC, concurrency, FFI and object-pipeline checks.
- Added dense signed division comparisons, 1,024 deterministic wraparound
  samples, extreme divisors, integer-to-string roundtrips, and call-side-effect
  checks to the shared runtime fixture.
- Python instruction-selection tests interpret the emitted reciprocal sequence
  over boundary/random inputs, verify MUL opcode bytes and test CSE exclusions.
- The updated runtime fixture is byte-identical across Python, native ML and
  ML object pipelines on each target:
  - Windows: BA0CE03999FFAC191C0EE04041673EDB161822C8F3A6D0B8F544726BA4244567
  - Linux: 32C0A07414703D450F11887264BAC5ECD1A09F0DB609624D5017B2C4DAF08FFB
- Windows selfhosting: Python bootstrap and ML selfbuild are byte-identical:
  36AA0DD7950515D3E76AC46937D73FCD673A09AE30A2E8668E8F5715FE07884A.
- Python, Windows-hosted ML and the complete Linux-native selfbuild produce
  the same Linux compiler:
  42926C4192809AA88A60343DF7A739F3C5A51C38E0760F0B13D93CD3BE3F28E4.
- Linux-hosted compilation of the runtime regression fixture matches the
  Linux hash above and the executable passes. The measured benchmark images
  also match Python/native-ML output on both targets (image hashes are in the
  raw runtime reports below).
- ML compiler API documentation regenerated with MiniDoc: 37 source files,
  3,283 symbols and zero warnings.

The historical native cstr-return lowering exception remains; these checks do
not claim universal output identity for that unrelated path.

## Evaluation

Measurements compare the preserved v1.2.13 compiler against this development
revision, using identical benchmark sources and options on a Ryzen 9 9900X.
Windows and Linux/WSL each use eleven alternating fresh-process samples per
case after warmup; medians below exclude process startup. All checksums agree.
Our other compiler builds were paused during these runtime measurements.
This is an active desktop, not a noise-free laboratory or a full application
benchmark; do not extrapolate the gains to MiniSQL, MiniQuake or HollowKeep.

| Workload | Windows ms, before → after | Time change | Linux ms, before → after | Time change |
| --- | ---: | ---: | ---: | ---: |
| division | 91.347 → 60.741 | -33.5% | 96.360 → 63.330 | -34.3% |
| division-constants | 54.030 → 24.666 | -54.3% | 44.305 → 25.991 | -41.3% |
| division-wide | 94.957 → 55.252 | -41.8% | 96.120 → 56.497 | -41.2% |
| local-cse | 21.548 → 7.274 | -66.2% | 21.959 → 7.011 | -68.1% |
| integer-format | 58.889 → 27.099 | -54.0% | 65.135 → 30.472 | -53.2% |
| integer-format-small | 9.684 → 9.296 | -4.0% | 10.729 → 9.649 | -10.1% |
| repeat | 4.516 → 4.473 | -0.9% | 8.109 → 8.002 | -1.3% |
| repeat-one | 0.071 → 0.077 | 8.3% | 0.066 → 0.065 | -0.6% |
| concat-empty | 0.106 → 0.100 | -5.8% | 0.094 → 0.083 | -11.7% |
| join-one | 0.088 → 0.084 | -4.4% | 0.077 → 0.075 | -2.0% |
| concat-control | 8.047 → 8.124 | 1.0% | 13.556 → 13.617 | 0.5% |
| concat-small-control | 12.820 → 12.648 | -1.3% | 12.030 → 12.443 | 3.4% |
| repeat-two-control | 10.152 → 10.284 | 1.3% | 10.562 → 10.479 | -0.8% |
| repeat-two-multi-control | 12.521 → 12.348 | -1.4% | 11.948 → 12.320 | 3.1% |
| join-control | 3.215 → 3.218 | 0.1% | 3.072 → 3.145 | 2.4% |

Raw samples, image hashes, wall times and allocation counts:
[Windows](LOCAL_CODEGEN_WINDOWS_2026-09-30.json) and
[Linux](LOCAL_CODEGEN_LINUX_2026-09-30.json).

The substantial arithmetic and large-integer-formatting improvements reproduce
on both targets. Unrelated string controls are mixed, with up to 3.4% more time
on Linux; Windows repeat-one rises by only 0.006 ms. These are reported rather
than treated as universal speedups or conclusively dismissed as noise.

### Memory and generated image size

Managed allocation counts are unchanged in every workload. Explicit benchmark
options (`--heap-reserve 1g --heap-commit 128m --gc-limit 512m`) keep these
workloads below the GC trigger, making heap deltas comparable. This round
reduces temporary stack traffic and code size, not string payload allocations.
The benchmark Windows image shrinks from 152,576 to 148,480 bytes (2.7%).
For identical current compiler sources, the old backend emits 65,566,720 bytes
and the new backend 64,587,264 bytes (1.5% smaller).

### Compiler performance

A separate three-run, alternating Windows comparison compiles
`tests/runtests.ml` with the monolithic pipeline. The OS peak working set
covers the full compiler process, not merely an object-pipeline coordinator.

| Metric | Before | After |
| --- | ---: | ---: |
| Median compile time | 2.294 s | 2.216 s |
| Peak working set | 228,782,080 bytes | 226,070,528 bytes |
| Generated image | 3,264,000 bytes | 3,151,360 bytes |

This is 3.4% less compile time and 1.2% less peak working set for this fixture,
not a claim of a major general-purpose heap reduction.
[Raw compiler samples](LOCAL_CODEGEN_COMPILER_2026-09-30.json).

Full Windows selfbuild timing also exposed the cost of the build wrapper's
previously automatic `--mem-probe` diagnostics. They are now explicitly opt-in
with `-BootstrapProbe`; `-NoBootstrapProbe` still overrides that switch and
Python bootstraps never receive it. The final normal build took 76.845 s.
A separate matched, profiled pair without memory probes took 80.875 s before
and 70.047 s after (function emission 56.304 → 47.443 s; serialization
16.411 → 15.161 s). This is a single pair, not a repeated median, and timings
with memory probes must not be compared as though only generated code changed.
The diagnostic policy does not change compiler output bytes.

The Linux-native full selfbuild also completed, passed the build wrapper's
direct/MLO/project smoke tests, and reproduced the regression fixture above.
Its wall-clock duration was 1,354 seconds, including approximately one minute
of deliberate suspension for the runtime benchmarks. No matched old-compiler
Linux selfbuild was measured, so this is neither a speedup claim nor evidence
that this patch introduced a slowdown. Linux full-selfbuild performance remains
a separate investigation candidate; cross-host timings are not comparable.
