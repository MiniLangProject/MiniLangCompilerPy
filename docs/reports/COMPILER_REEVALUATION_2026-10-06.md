# Compiler reevaluation — 6 October 2026

Independent rerun of the unreleased memory-lifecycle changes. This evaluates the
current Python and self-hosted compilers against the preserved 1.2.17 native
release. No production compiler or standard-library sources were changed during
this reevaluation; diagnostic files live under ignored `build/reevaluation-2026-10-06/`.
No commit, push, version bump or release was performed.

## Verdict

The fixes retain their intended memory/lifecycle benefits, and the executed
correctness and self-hosting checks pass. This is **not** an unconditional
performance or universal byte-parity sign-off. Pure graph marking regresses;
several Linux string controls are reproducibly slower on two tested logical CPUs. Three reproducible
CLI/tooling gaps were found, alongside the already documented native-`cstr`
byte-parity exception.

## Fresh correctness checks

- Python full suite: 164 passed, 0 failed, 0 skipped.
- Self-hosted core suite: 136 passed, 0 failed; the complete PowerShell integration
  runner also completed successfully (formatter, std.test/mltest, diagnostics,
  native runtime and assembly-listing checks included).
- Memory runtime matrices using the Python and Windows-native compilers:
  passed for Windows and Linux, including normal/object-pipeline parity.
- 192 generated images: 16 fixture/option combinations × two targets × three
  compiler hosts × two CLI pipeline modes. Each six-image target/case group
  is byte-identical. Python accepts the object flag for CLI parity but does
  not provide an independent MLO backend.
- 106 repeated stress executions: on each target, ten runs each of Thread
  lifetime, handoff lifetime, back-to-back safepoints, TLAB/shared-heap shrink
  and metadata shrink/regrow, plus three runs of the lifecycle-race fixture.
  All returned zero and their expected success marker. These are stress
  repetitions, not a proof that every possible interleaving is safe.
- All 53 `.ml` standard-library sources match byte-for-byte between the repositories.
- Fresh Python bootstrap and Windows-native selfbuild reproduce the production
  Windows compiler. A fresh Linux-native selfbuild reproduces the production
  Linux compiler. Build timings from these concurrent correctness runs are
  deliberately not used as performance results.

## Evaluated artifacts

The working trees retain uncommitted changes above Python `3a2ef59494177b751eec1e77bcd7ee83b3260f48`
and ML `c4bcbc57f562ec19198b1b3b9d97824de909d8c4`. Both current compilers still report `1.2.17`;
these are development builds, not a newly published release.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Python bootstrap = Windows selfbuild = current Windows compiler | 55,367,168 | `C04EC7312CE8A9B3877F15590AB02263F6877D1A276AF8526C8488769F790E16` |
| Linux native selfbuild = current Linux compiler | 55,365,616 | `EB8A70566220F3E72B28B4B6C4DC41BFBE34CBFBAAA51CA8FEE64D3A9B6C4920` |

The raw evidence also records hashes of preserved release compilers, benchmark
images, differing FFI images and completed test logs. The two native compiler
images are about 0.64% larger than their release counterparts.

## Reproducible findings

### P2 — Heap size syntax differs between the two CLIs

Python accepts `40mb`, `40mib`, `40_000_000` and `1t`; ML rejects them,
although both accept `40m`. The Python parser strips underscores and implements
multi-character suffixes; ML handles only a final k/m/g character.

Locations: Python `mlc/compiler.py:52`; ML `mlc/compiler.ml:2353–2397`.
This parser difference already exists at the released Git revisions; it is
not introduced by the lifecycle fix.

### P3 — Oversized growth settings can silently lose their intended policy

With a 40-MiB reservation and 32-MiB initial commit,
`--heap-grow 1152921504606846975` compiles in both compilers. Python's image
passes `memory_heap_ceiling.ml full-reserve`; ML's exits 4, meaning that it did
not commit the expected full reservation. For `18446744073709551615`, Python
accepts the option but its image also exits 4; ML rejects the option.

The parsers lack a common checked upper bound. ML's 61-bit integer page-rounding
and Python's subsequent 64-bit machine-immediate encoding can overflow.
Relevant code: ML `mlc/codegen/codegen_memory.ml:2670–2672`,
`mlc/tools.ml:1016`; Python `mlc/codegen/codegen_memory.py:3111–3122`.

These deliberately extreme growth preferences do not request an exabyte-sized
allocation: the probe reserves only 40 MiB. Normal tested growth values, including
4 GiB, pass. No memory corruption was observed in these probes; this is an
input-validation/policy and parity defect, not evidence of a demonstrated exploit.

### P2 — ML silently omits Linux assembly listings

A Linux compile with `--asm --asm-out <file>` succeeds and writes the ELF,
but the ML compiler does not create the requested listing. The Python compiler
creates it for the same source and target. ML's Windows listing works.

The two ELF output paths finish without calling the listing writer:
`mlc/compiler.ml:6247` and `:6771`. The helper is called only by PE paths
(at `:6511` and `:7358`). This omission also predates the lifecycle changes.
Either implement the advertised output or reject unsupported combinations
explicitly; a success exit without the requested artifact is misleading.

### Known exception — Native cstr return images are not byte-identical

Fresh builds of `tests/linux_ffi.ml` pass the cstr-return, strlen and cos checks
with both compilers, but their ELF hashes differ. This is the existing helper
versus inline-conversion exception in `COMPILER_PARITY.md:145–148`, not a new
semantic regression. The 192-image result must not be generalized to all programs.

## Fresh performance evaluation

Machine: AMD Ryzen 9 9900X, 12 cores / 24 logical CPUs, Windows 11 build 26200;
Linux measurements use Ubuntu under WSL2, kernel 6.6.87.2. Benchmark suites
ran sequentially after correctness builds/stress completed. The compiler-time
measurement also ran separately; the targeted control repeat followed it.

Before = preserved released 1.2.17; after = current fixed build. Source, target
and options match within each A/B comparison. The general/runtime images were
rebuilt for this evaluation. Frozen thread/lifecycle/fragmentation/metadata
images were rerun, then all eight current images were freshly rebuilt and
verified byte-identical to those measured images.

Method:

- General memory workloads: 21 alternating process pairs, one warm-up per image
  per case; runner and children pinned to logical CPU 0.
- General code-generation screen: 20 cases, 11 pairs each, CPU 0.
- Suspicious controls: eight cases repeated with 31 pairs on Windows CPU 0,
  Linux CPU 0 and Linux CPU 2. The second CPU is on the same machine, not an
  independent hardware architecture.
- Parallel allocation: 11 pairs each with 1/2/4/8/12/24 workers, no CPU pinning.
- Lifecycle/fragmentation/metadata: seven pairs per case.
- Explicit pauses: seven processes per version, 100 pauses each. These samples
  are clustered by process, not 700 independent process experiments.
- Compiler build: one warm-up per version, then three alternating process pairs.
  Monolithic compilation captures the complete compiler peak working set.

Tables report the change in median measured workload time; negative is better.
Native workload timers exclude startup. Raw data keeps process wall time and
peak RSS/working set separately. All benchmark checksums agree. Paired median
bootstrap intervals (5,000 resamples) are included as run-to-run diagnostics,
not proof of portability; no multiple-comparison-adjusted universal claim is made.

### General memory workloads

| Workload | Windows before → after (ms) | Change | Linux before → after (ms) | Change |
| --- | ---: | ---: | ---: | ---: |
| Small-object churn | 67.606 → 67.341 | -0.39% | 65.453 → 64.184 | -1.94% |
| Allocation with a large live graph | 239.011 → 237.229 | -0.75% | 239.719 → 236.902 | -1.18% |
| Leaf marking | 16.276 → 16.216 | -0.37% | 16.003 → 16.622 | +3.87% |
| Graph marking | 47.767 → 48.811 | +2.19% | 45.041 → 47.847 | +6.23% |
| General fragmentation control | 3.617 → 3.432 | -5.11% | 5.971 → 5.930 | -0.68% |
| Arithmetic control | 13.421 → 13.384 | -0.28% | 12.940 → 12.937 | -0.02% |

**Graph marking is a reproducible regression**, not a blanket improvement:
20/21 Windows pairs and 21/21 Linux pairs are slower. The paired-median 95%
bootstrap intervals are approximately +1.84…+2.53% and +6.01…+7.03%.
Linux leaf marking is also slower. The noisy general fragmentation control
must not be confused with the targeted successful-hole search below.

Managed commitment is unchanged (32 MiB in most cases, 96 MiB for large-live,
48 MiB in the general fragmentation case). Linux median peak RSS is identical
at the measurement resolution; Windows differences are at most 8 KiB here.

### GC pause distribution

These are explicit collections over a retained 100,000-node graph, not
safepoint-wait latency for a contended server.

| Target | Version | p50 (ms) | p95 (ms) | Max (ms) |
| --- | --- | ---: | ---: | ---: |
| windows | before | 1.1087 | 1.1377 | 1.7042 |
| windows | after | 1.1355 | 1.1912 | 1.7088 |
| linux | before | 1.1125 | 1.2847 | 1.9000 |
| linux | after | 1.1859 | 1.3478 | 1.8949 |

### Diagnostic-only layout experiment

Eight images insert 0/8/16/24/32/40/48/56 unreachable padding bytes immediately
before the GC function label. The collector algorithm is unchanged; following
code and branch locations move. Zero-padding images match the current benchmark
byte-for-byte. Nine rounds rotate/reverse image order, with CPU 0 pinning.

| Target | Release graph-mark (ms) | Current / 0 padding (ms) | Range across all eight layouts (ms) |
| --- | ---: | ---: | ---: |
| windows | 47.501 | 48.478 | 46.746…48.827 |
| linux | 45.970 | 47.909 | 45.469…48.432 |

Some layouts remove the graph-mark regression without changing the algorithm.
This is evidence of layout sensitivity, **not** a hardware-profiled explanation
of a specific cache or branch-predictor event and not justification to hard-code
the best padding. No diagnostic padding was applied to production sources.
The string regression below has not been isolated by this GC experiment.

### Wider generated-code screen and confirmed Linux string regressions

Most arithmetic/index controls are close to baseline. Initial apparent changes
in Linux struct projection/inline-literal and Windows multi-character repetition
did not reproduce consistently in the longer repeats; they are not treated as
confirmed regressions.

The following longer-running string cases **do** reproduce on Linux:

| Workload | Windows repeat (change) | Linux CPU 0 before → after (ms) | Change | Linux CPU 2 change |
| --- | ---: | ---: | ---: | ---: |
| concat-small-control | -7.09% | 8.3016 → 9.0379 | +8.87% | +7.13% |
| repeat-two-control | -1.20% | 7.0798 → 7.6828 | +8.52% | +8.05% |
| repeat-two-multi-control | -1.54% | 8.4645 → 9.0012 | +6.34% | +7.40% |
| join-control | -5.80% | 2.4621 → 2.6899 | +9.25% | +8.86% |

Small concatenation and join are slower in all 31 Linux CPU-0 pairs; the two
repetition cases are slower in 29/31 pairs. Their paired-median intervals exclude
zero on both tested Linux CPUs. Workload checksums and measured heap deltas
match; Linux peak RSS is unchanged. This is a performance issue, not an observed
semantic failure.

The very short Linux `repeat-one` and `concat-empty` cases also show roughly
8–12% regressions in repeats, but each entire timed workload is below 0.11 ms:
the absolute change is only several microseconds. Raw results are retained,
without pretending these percentages equal whole-application slowdowns.

Windows small concatenation/join improve instead. Allocator fast-path
bookkeeping and emitted layout are investigation candidates; the exact cause
of the string regressions remains unresolved. Preserve these A/B cases when
optimizing rather than assuming the GC-only layout result explains them.

### Parallel allocation

| Workers | Windows before → after (ms) | Change | Linux before → after (ms) | Change |
| --- | ---: | ---: | ---: | ---: |
| 1 | 16.62 → 16.38 | -1.42% | 18.59 → 18.60 | +0.05% |
| 2 | 23.27 → 22.76 | -2.21% | 24.19 → 24.17 | -0.10% |
| 4 | 43.04 → 33.04 | -23.22% | 47.31 → 34.29 | -27.51% |
| 8 | 71.66 → 61.41 | -14.31% | 77.35 → 66.87 | -13.56% |
| 12 | 104.48 → 90.08 | -13.78% | 114.03 → 100.00 | -12.31% |
| 24 | 226.10 → 211.25 | -6.57% | 266.84 → 248.82 | -6.75% |

The four-worker benefit is reproduced (23% Windows / 28% Linux), with no slower
after-run in those 11 paired samples. One/two-worker differences are small and
noisy. All finish with 32 MiB managed commitment; this is not a claim of the
same gain for MiniSQL or another application.

### Lifecycle, retention and fragmentation fixes

- After 100,000 abandoned never-started Thread objects, the old Windows runtime
  adds about 19.92 MiB private commit; the new one stays flat. Fifty explicit GCs
  at that point take 54.630 → 0.0077 ms on Windows and
  61.049 → 0.0185 ms on Linux.
  This is private commit, not a claim that resident RAM falls by 19.92 MiB.
- With 2,000 actual Start/Join/Close cycles, the new Windows commit stays flat;
  the old runtime still accumulates context storage.
- Sixteen abandoned 1-MiB logical IDs and the dropped-graph handoff probe return
  to their pre-test live baseline. The old images retain about 16 MiB.
- The successful 4,000-hole allocation probe drops from 8,002,000 to 7,999
  free-list probes: 7.6185 → 0.6154 ms Windows,
  9.2812 → 0.6001 ms Linux.
- With `--heap-shrink --heap-shrink-min 1m`, the worklist returns from 2 MiB
  to 64 KiB after the broad graph is dropped and hysteresis expires. The old
  runtime retains 2 MiB. The separate stress fixture verifies repeated regrowth.

### Self-hosted compiler time and memory

Fixture: `tests/compiler_qualification_cache.ml`, which imports substantial
compiler code. Windows-native compilers, `--no-object-pipeline`, three measured
pairs after warm-up; this is **not a complete compiler selfbuild time**.

| Metric | Released baseline | Current |
| --- | ---: | ---: |
| Median compile time | 50.651 s | 49.366 s |
| Peak working set | 1,232,797,696 bytes | 1,232,994,304 bytes |
| Generated image | 37,075,456 bytes | 37,075,456 bytes |

Time changes -2.54%;
peak working set changes only +192 KiB (+0.016%), remaining about 1.15 GiB.
All three current compiles are faster than their paired baseline compile.
Output is deterministic within each version; old/new hashes differ as expected.

## Evidence and reproduction

[Complete raw data, samples, hashes and paired analysis](COMPILER_REEVALUATION_2026-10-06.json)
is mirrored with this report in both compiler repositories. All figures above
come from this rerun, not copied measurements from the earlier
[implementation report](MEMORY_LIFECYCLE_2026-10-06.md).

From the Python repository:

```powershell
python tests/run_tests.py
python tests/check_memory_runtime.py mlc_win64.py
python tests/check_memory_runtime.py ../MiniLangCompilerML/build/mlc_win64.exe
python tests/check_memory_compiler_parity.py mlc_win64.py ../MiniLangCompilerML/build/mlc_win64.exe ../MiniLangCompilerML/build/mlc_linux_x64 --output build/parity.json
```

From the ML repository:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_tests.ps1 -Compiler build/mlc_win64.exe
python benchmarks/compare_memory_management.py BEFORE AFTER --runs 21 --cpu 0 --output build/memory.json
python benchmarks/compare_runtime_codegen.py BEFORE AFTER --runs 11 --cpu 0 --output build/runtime.json
python benchmarks/compare_memory_threads.py BEFORE AFTER --runs 11 --output build/threads.json
python benchmarks/compare_memory_pauses.py BEFORE AFTER --runs 7 --output build/pauses.json
python benchmarks/compare_compiler_codegen.py OLD_COMPILER NEW_COMPILER tests/compiler_qualification_cache.ml --include . --runs 3 --output build/compiler.json
```

BEFORE/AFTER are the corresponding images of the same benchmark built with
the recorded compilers; run Linux harnesses inside WSL using the ELF images.
For the lifecycle harness, use `compare_memory_lifecycle.py` with its six named
before/after image options and seven runs; metadata images add the shrink flags.

The ignored evaluation directory retains `repeat_stress.py`,
`check_boundaries.py`, `repeat_controls.py`, `layout_probe.py`,
`measure_layout.py` and `summarize.py`. The control repeat is the normal runtime
harness restricted to the eight cases named in the raw data and run with
`--runs 31 --cpu 0` or `--cpu 2`.

Minimal size-policy reproduction:

```powershell
build/mlc_win64.exe tests/memory_heap_ceiling.ml build/ceiling.exe --heap-reserve 40m --heap-commit 32m --heap-grow 1152921504606846975
build/ceiling.exe full-reserve
```

Expected policy-check exit: 0; observed ML exit: 4. Replace the native compiler
with `python ../MiniLangCompilerPy/mlc_win64.py` for the passing comparison.
Replacing the growth value with `40mb` reproduces the syntax difference.

Linux listing reproduction:

```powershell
build/mlc_win64.exe benchmarks/memory_management.ml build/listing.elf --target linux-x64 --asm --asm-out build/listing.asm
```

The ELF is written successfully but the requested new listing is absent.

## Recommended next work

1. Resolve the reproducible graph/leaf-mark and Linux string performance
   regressions, retaining the successful leak/lifecycle and fragmentation fixes.
   Use profiling and layout-aware A/B tests; do not blindly select one padding.
2. Unify size parsing and reject values that cannot be safely scaled, rounded
   and encoded by both compilers. Add malformed/boundary CLI parity tests.
3. Implement ELF listings or explicitly reject unsupported output flags.
4. If universal executable byte identity is required, remove the documented
   native-`cstr` emitter divergence and add that path to parity qualification.

## Evaluation limits

- Windows x64 and Ubuntu under WSL on one machine, not native Linux hardware
  or a cross-machine population.
- Unit/integration and targeted runtime probes, not a new MiniSQL, MiniQuake
  or HollowKeep application benchmark.
- No exhaustive race proof, native fault-injection campaign, or security guarantee.
- GC remains stop-the-world and non-compacting. Default high-water capacity
  retention is policy, not by itself a leak; opt-in shrinking has tradeoffs.
- Existing uncommitted fixes were preserved. The findings above are recorded,
  not silently fixed as part of this evaluation-only request.
