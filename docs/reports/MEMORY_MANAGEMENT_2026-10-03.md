# Memory management review and evaluation — 3 October 2026

## Verdict and scope

The shared-heap design remains a reasonable baseline: explicit shadow roots,
stop-the-world mark/sweep, coalescing reuse and per-thread allocation buffers.
The implementation was improved in both backends without introducing manual
free, changing shared-object lifetime, or weakening thread synchronization.

This is **not an across-the-board speedup**. In the final A/B sample, fragmented
failed-fit allocation improves by 75–83%, retained-live allocation by 44–46%,
and leaf marking by 16–18%. Small single-thread churn regresses by 2.4% on
Windows and 6.8% under WSL; reference-graph marking regresses by about 3%.
Linux threaded cases regress by 0.6–5.5%. The numerical results below are kept
rather than selecting only favorable intermediate runs.

Windows commit charge drops by approximately 64 MiB for the small control
program, but this is **not** 64 MiB less resident RAM. Linux can now discard
interior free pages with heap shrinking enabled. Adaptive collection trades
more temporary heap for less repeated traversal on a large retained graph.

This evaluation measured development work after 1.2.15, before the 1.2.16
version stamp. Its raw samples and development-image hashes are preserved.
The subsequent [1.2.16 release notes](../../RELEASE_NOTES_1.2.16.md) record
release-stamped checksums and the final packaging/validation scope; changing
the version stamp was not treated as a new performance measurement.

## Changes and safety constraints

1. **Diagnostics:** `gc_stat(index)` returns one allocation-free scalar sample;
   invalid indices/types return `void`. The README specifies all 15 indices.
   Naturally aligned counters can be read by other threads, but several reads
   are not a coherent snapshot. Central requests include prepaid TLAB ranges,
   not individual fast-path objects; reclaimed bytes exclude existing holes.
   Hot allocation/probe and detailed mark/reclaim instrumentation is omitted
   if emitted application code never references `gc_stat`. First-class-only
   references retain it and have a dedicated regression.
2. **Bounded adaptive defaults:** after collection, overall pressure becomes
   `clamp(liveBlockBytes / 2, 64 MiB, 256 MiB)`; small-object pressure becomes
   `clamp(liveBlockBytes / 4, 8 MiB, 64 MiB)`. Explicit `--gc-limit`,
   `--no-gc-periodic` or any `gc_set_limit()` call preserves fixed/disabled
   behavior. Allocation-failure collection remains available. Both thresholds
   still trigger full GC: this is not generational collection.
3. **Allocator:** a single-thread small-object bump path avoids the slow frame
   when no reusable free block exists. A negative-fit cache avoids repeating
   known-unsatisfiable free-list searches. Collection and explicit TLAB-tail
   retirement invalidate it; removing/splitting holes cannot invalidate a
   negative answer. Metadata remains serialized in threaded programs.
   This is **not a segregated size-class allocator**: successful first-fit
   searches can still be linear and are a worthwhile follow-up hotspot.
4. **Marking:** reference-free leaves are marked without worklist traffic.
   Pointer-bearing arrays, structs, closures, environments and boxes retain
   traversal and existing plausibility/size guards. The worklist reserves its
   existing 64-MiB maximum outside the managed heap, initially commits 64 KiB
   and doubles on demand without recursive managed allocation. GC peak/live
   statistics are accumulated in registers where possible. The necessary
   worklist-base pointer remains in BSS, preserving a valid nonempty PE BSS.
5. **Page return:** with `--heap-shrink`, full payload pages in dead holes are
   discarded when the aligned range is at least 4 MiB. Headers, free-list links
   and neighboring live objects are excluded. Windows uses `MEM_RESET`;
   Linux uses `MADV_DONTNEED`, keeping access permissions. Reuse requires
   initialized object contents, not recommitting the interior. Top decommit
   updates `heap_end` only on OS success; Linux now propagates decommit failure.
   `--heap-shrink-min` controls the retained top-commit floor, not this threshold.

An unused infinitely self-recursive ML `_configured_gc_limits` helper was
removed. Stale fixed-heap/refcount/worklist comments were corrected. The
canonical embedded Linux adapter was regenerated; tests now also reject
out-of-order label offsets that would corrupt slice-based emission.

No moving/compacting/concurrent/generational collector, separate large-object
heap or automatic worklist shrinking was introduced. There are no runtime
pause-time or safepoint-wait counters; the pause benchmark below measures
explicit collections externally.

## Correctness and binary compatibility

- Python full suite: **158 passed, 0 failed, 0 skipped**.
- Windows ML full suite: **136 core cases passed**, plus all outer checks.
- Supplemental runtime matrix: eight configurations, both targets and both
  pipelines; Python/Windows ML execute both targets, Linux ML executes ELF
  and cross-compiles PE. All pass.
- Three-host parity: **96 compiled images**, eight configurations × two targets
  × Python/Windows ML/Linux ML × normal/object pipeline. Each target/configuration
  has six byte-identical outputs.
- Windows full Python bootstrap/native selfbuild are byte-identical.
- Linux full Python bootstrap/native selfbuild with the same build options are
  byte-identical. A different heap configuration intentionally changes bytes.
- Structural codegen checks pass for both backends.
- All **53 standard-library modules** remain byte-identical and unchanged.
- Linux adapter: **2058 bytes, 66 labels, 3 external relocations**, canonical.
- Regenerated ML MiniDoc: **37 files, 3287 symbols, 0 warnings**.
- Existing native `cstr` return-lowering parity exception is unchanged; the
  matrix is not a claim of universal parity for every possible program.

Coverage includes broad graphs exceeding the initial worklist capacity,
retention after repeated GC, default/fixed/disabled policy, first-class-only
statistics, invalid indices and allocation-free reads, fragmented failed-fit
reuse, shared-heap/TLAB lifetimes, back-to-back safepoints, interior discard,
live neighbors, reinitialization of reused payloads, top trim and recommit.
OS allocation/decommit failure paths were reviewed; exhaustion/fault injection
was not added.

| Final compiler | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows Python bootstrap = native selfbuild | 55,015,936 | `40752EAAC61CF8E59FD08BBD1A4D39EE14C603CD516D25B348C150771BDE2EC9` |
| Linux Python bootstrap = native selfbuild | 55,017,456 | `A9D95C882D7AC415E2329819542C46861DC2DED3CA90EA476981FE9DA4BD87A8` |

The full compiler grows approximately 1% relative to the release. The memory
benchmark grows from 150016 to 151552
bytes on Windows and 157392 to 157504
on Linux. Worklist reservation/commit savings are not on-disk size savings:
the previous large worklist already lived in BSS.

## Measurement method

Hardware: AMD Ryzen 9 9900X, 12 cores / 24 logical processors.
Windows: `Windows-10-10.0.26200-SP0`.
Linux: Ubuntu under WSL2, `Linux-6.6.87.2-microsoft-standard-WSL2-x86_64-with-glibc2.39`.
These are same-platform A/B comparisons, not Windows-versus-bare-metal-Linux
rankings.

The baseline is the preserved 1.2.15 native compiler, SHA-256
`4357346D79C3C3D9E3A2D8FB20CAE974C5B94D0A66830B95762B15EBC65AFBBA`,
from Python source commit `a738c5d00f5034b14e1b5e98d1acfe2335e19369`
and ML source commit `c6f3297ab154f1136c7c071f1ab1a0870e2a2514`.
The final benchmark sources were compiled unchanged with old and new backends.

Each throughput case has warmups and **11 alternating A/B process pairs**;
tables show medians. Sequential cases pin the runner/children to logical CPU 0.
Threaded cases do not pin workers. QPC/clock_gettime measure only the workload;
raw data also records process wall time and peak working set/RSS. Checksums
must match. The small/retained-live cases use **five million allocations** to
reduce the influence of very short samples. Threads use one million iterations
and two objects per iteration per worker.

No owned CPU-heavy build/test/doc job ran concurrently with these samples.
The still-running Linux selfbuild emitter was temporarily suspended and then
resumed in a `finally` block; its memory remained resident. This was not a
machine-wide exclusive benchmark environment. Compiler bootstrap/selfbuild
logs include parallel work and this pause and are **not compiler-speed
benchmarks**. In particular, the configured Linux selfbuild was much longer
than Windows; these observations do not establish a same-settings A/B change
in compiler build time.

Intermediate experiments used shorter churn samples and earlier counter
instrumentation. They are not mixed into these final medians. Removing hot
counter updates reduced diagnostic overhead; it did not eliminate every
small-allocation/marking regression.

## Runtime throughput

Lower is better; percentages are changes in elapsed time, not throughput.

| Target | Workload | Before ms | After ms | Time change |
| --- | --- | ---: | ---: | ---: |
| windows | small-churn | 66.71 | 68.31 | +2.39% |
| windows | large-live | 436.73 | 236.80 | -45.78% |
| windows | leaf-mark | 19.27 | 16.18 | -16.02% |
| windows | graph-mark | 46.17 | 47.73 | +3.38% |
| windows | fragmented | 21.75 | 3.59 | -83.48% |
| windows | control | 13.44 | 13.31 | -0.97% |
| linux | small-churn | 65.20 | 69.61 | +6.77% |
| linux | large-live | 445.21 | 247.60 | -44.39% |
| linux | leaf-mark | 20.26 | 16.52 | -18.45% |
| linux | graph-mark | 47.76 | 49.18 | +2.98% |
| linux | fragmented | 25.45 | 6.41 | -74.83% |
| linux | control | 13.45 | 13.53 | +0.60% |

The retained-live result is partly a collection-frequency trade-off, not solely
faster traversal. Its final committed heap rises **80 → 96 MiB**, with about
**10 MiB** higher peak resident memory. Other sampled committed heap values
remain unchanged.

| Target | Workload | Before peak MiB | After peak MiB | Final committed heap MiB |
| --- | --- | ---: | ---: | ---: |
| windows | small-churn | 15.35 | 15.36 | 32.00 → 32.00 |
| windows | large-live | 89.65 | 99.35 | 80.00 → 96.00 |
| windows | leaf-mark | 16.48 | 15.72 | 32.00 → 32.00 |
| windows | graph-mark | 14.86 | 14.91 | 32.00 → 32.00 |
| windows | fragmented | 40.21 | 40.18 | 48.00 → 48.00 |
| windows | control | 7.09 | 7.10 | 32.00 → 32.00 |
| linux | small-churn | 9.38 | 9.38 | 32.00 → 32.00 |
| linux | large-live | 83.63 | 93.38 | 80.00 → 96.00 |
| linux | leaf-mark | 10.50 | 9.75 | 32.00 → 32.00 |
| linux | graph-mark | 8.81 | 8.81 | 32.00 → 32.00 |
| linux | fragmented | 34.31 | 34.31 | 48.00 → 48.00 |
| linux | control | 1.13 | 1.13 | 32.00 → 32.00 |

## Parallel allocation

The TLAB ownership/safepoint design is preserved, not replaced. All results
and checksums pass. This round does not demonstrate a parallel throughput win.

| Target | Workers | Before ms | After ms | Time change |
| --- | ---: | ---: | ---: | ---: |
| windows | 1 | 16.70 | 16.81 | +0.66% |
| windows | 2 | 23.17 | 23.53 | +1.55% |
| windows | 4 | 43.04 | 43.20 | +0.38% |
| windows | 8 | 70.78 | 71.51 | +1.02% |
| windows | 12 | 103.88 | 104.82 | +0.91% |
| windows | 24 | 226.17 | 226.69 | +0.23% |
| linux | 1 | 18.67 | 19.70 | +5.53% |
| linux | 2 | 24.18 | 25.25 | +4.40% |
| linux | 4 | 45.65 | 47.33 | +3.69% |
| linux | 8 | 76.62 | 77.13 | +0.65% |
| linux | 12 | 112.60 | 113.24 | +0.57% |
| linux | 24 | 256.69 | 263.70 | +2.73% |

All cases finish with 32 MiB committed managed heap. Peak working-set/RSS
differences are small; exact values are in the raw samples.

## Explicit collection pauses

Five alternating process pairs, each collecting the same retained 100,000-node
graph 100 times: **500 samples per version and OS**. Setup and printing are
outside each pause interval. These unpinned samples include OS scheduling
effects; maximum values are observations, not worst-case guarantees. They
do not measure another thread's safepoint wait separately.

| Target | Version | p50 ms | p95 ms | Maximum ms |
| --- | --- | ---: | ---: | ---: |
| windows | before | 1.1050 | 1.2050 | 1.7788 |
| windows | after | 1.1732 | 1.2403 | 1.8037 |
| linux | before | 1.1098 | 1.3538 | 1.7519 |
| linux | after | 1.1232 | 1.3766 | 1.7633 |

No GC-pause reduction is claimed for this reference-rich graph.

## Commit charge and interior residency

The Windows control probe's median peak commit charge changes
**97.81 → 33.75 MiB**.
Peak working set is almost unchanged:
**7.12 → 7.13 MiB**.
The old 64-MiB worklist was committed image BSS but mostly not resident.

The interior-hole test holds live objects on both sides of a dead 64-MiB
buffer. With `--heap-shrink --heap-shrink-min 1m`, current process residency
after collection is:

- Linux: **66.00 → 2.06 MiB**.
- Windows: **71.51 → 71.51 MiB**; essentially unchanged, as allowed for `MEM_RESET`.
- Windows commit charge in that test is lower by approximately 64 MiB due to
  the worklist change, not due to the interior discard hint.

Platform semantics:
[Microsoft VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc),
[Linux madvise](https://man7.org/linux/man-pages/man2/madvise.2.html).

## Reproduction and follow-up

Build old/new benchmark sources with matching `--target windows-x64` or
`--target linux-x64`. Only the residency fixture needs the shrink flags.
See [benchmark instructions](../../benchmarks/README.md#memory-management)
for runners. Focused correctness checks:

```text
python tests/check_memory_runtime.py COMPILER
python tests/check_memory_compiler_parity.py PYTHON_COMPILER WINDOWS_ML LINUX_ML --output parity.json
python tests/check_codegen_structure.py COMPILER
python scripts/check_linux_runtime_blob.py
```

The three-host parity runner uses Windows plus WSL Ubuntu. The runtime runner
also works inside Linux; PE images there are compiled/compared, not executed.
Build Windows self-hosting through `build.ps1`. Linux self-hosting through
`build.sh` uses matching `--heap-reserve 8g --heap-commit 512m --heap-shrink
--heap-shrink-min 16m --gc-limit 1536m --object-pipeline`.

Before claiming a universal performance improvement, the next targeted work is
successful free-list reuse/small-object overhead and reference-rich mark cost.
A segregated allocator or a carefully bounded free-head fast path deserves a
separate A/B experiment; the present negative-fit cache does not solve every
linear search. Adaptive thresholds should also be profiled on long-running
MiniSQL/HollowKeep workloads before changing their explicit production limits.
Those application-specific performance checks were not repeated here.

## Raw evidence

- [windows samples](MEMORY_WINDOWS_2026-10-03.json)
- [linux samples](MEMORY_LINUX_2026-10-03.json)
- [threads-windows samples](MEMORY_THREADS_WINDOWS_2026-10-03.json)
- [threads-linux samples](MEMORY_THREADS_LINUX_2026-10-03.json)
- [pauses-windows samples](MEMORY_PAUSES_WINDOWS_2026-10-03.json)
- [pauses-linux samples](MEMORY_PAUSES_LINUX_2026-10-03.json)
- [commit samples](MEMORY_COMMIT_WINDOWS_2026-10-03.json)
- [residency-windows samples](MEMORY_RESIDENCY_WINDOWS_2026-10-03.json)
- [residency-linux samples](MEMORY_RESIDENCY_LINUX_2026-10-03.json)
- [96-image parity manifest](MEMORY_PARITY_2026-10-03.json)
