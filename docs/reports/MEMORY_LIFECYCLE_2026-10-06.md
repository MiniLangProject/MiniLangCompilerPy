# Memory lifecycle audit and evaluation — 6 October 2026

## Scope and status

This is an unreleased source change after 1.2.17, implemented in both compiler
backends. Version strings and published release checksums remain unchanged.
The audit covers the generated allocator, GC, native thread adapters and the
standard-library thread-pool lifetime. It is not a proof that arbitrary native
FFI code or every application is leak-free.

The reproduced retention bugs and false out-of-memory failures are fixed.
Thread-history GC cost no longer grows indefinitely, fragmented repeated-size
allocation improves by 92–94% at 4,000 requests, and parallel allocation improves
in the tested cases. Pure marking controls still show regressions of up to 7%;
the tables below explicitly include them.

## Findings and fixes

| Finding | Fix and regression coverage |
| --- | --- |
| A 34-MiB allocation failed with 40 MiB reserved / 32 MiB committed because the preferred growth step exceeded the reservation. | Clamp preferred growth to the reservation after checking the actual request. Also page-round custom growth and compare quanta above signed-32-bit range correctly. Test default, 128m, 4g and 5001-byte growth; requests exceeding the reservation must still fail. |
| Never-started and completed Thread records were permanent registry entries, retaining logical ids and growing native arenas and future GC work. | Allocate control records on the managed heap and make inactive registry links weak. Trace reachable Thread payloads, retain active workers and their native epilogues, prune unreachable inactive records before sweep and close terminated abandoned handles. Cover cycles, aliases, active unreferenced workers, results, construction under GC pressure and repeated disposal. |
| Close could not release a never-started Thread's payload. | Atomically consume Created -> Stopped. Clear payload roots, reject subsequent Start/SetLogicalId and make repeat Close return false. Exercise concurrent Start versus Close repeatedly. |
| Four recent-allocation handoffs could retain a dropped multi-megabyte graph indefinitely. | Clear them only at compiler-proven precise-root publication boundaries: requested safepoints, direct/first-class GC, sleep and user extern transitions. Clear worker scratch roots on exit; preserve runtime-helper construction roots. |
| An idle thread-pool worker retained its previous completed job in a local. | Explicitly clear the local before waiting. The regression drops the job while keeping only native cleanup wrappers; it does not mask retention by clearing the result first. |
| Repeated successful first-fit searches rescanned an ever-longer undersized prefix. | Cache the predecessor for an exact request size. Consult it only after a failed head probe; invalidate on collection, TLAB retirement and head allocation. Test splits, changing sizes, repeated GC and surviving payload contents. |
| Worklist and mark-bitmap commitments stayed at their high-water marks. | With --heap-shrink, decommit surplus bitmap coverage and shrink the worklist after eight low-usage collections. Keep safe coverage and regrow on demand. Default retention remains an intentional throughput policy. |
| First-class gc_collect lacked the native call frame; Linux thread wait overwrote nonvolatile RDI/RSI. | Supply aligned shadow space and preserve the adapter registers. Direct/indirect GC, native joins, shared-heap stress and Linux execution cover these paths. |

### Ownership and concurrency invariants

- The heap remains shared, non-moving and collected with cooperative stop-the-world
  mark/sweep. Only the context registry link is weak; ordinary managed references
  retain their usual semantics.
- An inactive publication is **not** enough to free a worker: native termination
  must have completed. OS-wait or close failure conservatively retains the context.
- A reachable Thread still owns its result and logical id. Closing it releases
  those roots without invalidating values published elsewhere. Unreachable cycles
  involving Thread objects are collectible.
- Constructors initialize all recycled context fields and root their logical-id
  argument before allocating. Native handles, stack links and registry links are
  not scanned as tagged object fields.
- Runtime helpers retain temporary construction handoffs. Clearing every handoff
  inside the allocator or collector itself would be unsafe and was not adopted.
- Worklist trimming retains at least 64 KiB and twice the latest observed peak,
  rounded to its power-of-two growth policy. Bitmap trimming retains coverage for
  the entire committed heap. Capacity/end metadata changes only after successful
  decommit.

## Correctness and compiler parity

- Python full suite: **164 passed, 0 failed, 0 skipped**.
- Native Windows ML full suite: **136 core cases passed**, plus all outer checks.
- Final memory matrix: 16 configurations × two targets × two pipelines = **64
  successful runtime executions per Python/Windows-ML host**, plus 16 expected
  reserve-exhaustion failures per host. The Linux-hosted compiler independently
  executes all 32 ELF cases and eight expected failures, and cross-compiles PE.
- Cross-host parity: **192 images** (16 configurations × two targets × three
  compiler hosts × two pipelines), with six identical outputs per target/configuration.
- Full Windows Python bootstrap and native selfbuild are byte-identical.
  Full Linux Python bootstrap, Windows-ML crossbuild and Linux-native selfbuild
  are also byte-identical. All ten final benchmark images match between backends.
- All **53 standard-library source modules** and **351 generated std reference
  files** match between repositories. MiniDoc reports 1930 std symbols and zero
  warnings; the compiler reference reports 37 files, 3286 symbols and zero warnings.
- Canonical Linux adapter: **2062 bytes, 66 labels, 3 external relocations**.
- Source syntax checks and whitespace checks pass. README, changelog and
  generated references describe the new lifetime and memory policies.

The final suites include five new fixtures:
`memory_heap_ceiling.ml`, `gc_thread_lifetime.ml`,
`gc_handoff_lifetime.ml`, `memory_gc_metadata.ml` and
`memory_fragmentation_cursor.ml`. Their dedicated matrices additionally check
custom growth options, negative exhaustion, both pipelines and all compiler hosts.
This scoped matrix does not remove the pre-existing native `cstr` return-lowering
parity exception documented in [COMPILER_PARITY.md](../../COMPILER_PARITY.md).

| Development compiler | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows Python bootstrap = native selfbuild | 55,367,168 | `C04EC7312CE8A9B3877F15590AB02263F6877D1A276AF8526C8488769F790E16` |
| Linux Python bootstrap = Windows ML crossbuild = Linux ML selfbuild | 55,365,616 | `EB8A70566220F3E72B28B4B6C4DC41BFBE34CBFBAAA51CA8FEE64D3A9B6C4920` |

These development binaries are about 0.64% larger than the 1.2.17 compiler
binaries. Local `MiniLangCompilerML/build/mlc_win64.exe` and
`build/mlc_linux_x64` were updated after verification; the previous release
binaries are retained under `build/gc-audit-2026-10-06/*1.2.17-baseline*`.
No GitHub release or version stamp was changed.

## Evaluation method

Baseline: unchanged 1.2.17 compiler artifacts from the starting checkout
(Python commit 3a2ef59, ML commit c4bcbc5). The old and new compilers build the same
benchmark sources and options. Both backends' final benchmark images are checked
for exact byte equality.

Hardware: AMD Ryzen 9 9900X, 12 cores / 24 logical processors. Windows x64 and
Ubuntu under WSL2 are measured separately; these are same-platform A/B comparisons,
not bare-metal Windows-versus-Linux conclusions.

Each final comparison warms both images and alternates A/B order across seven
measured runs. Tables use medians. General single-thread workloads are pinned to
logical CPU 0; parallel allocation uses normal scheduling. Builds and test suites
finish before timing begins. Timed regions exclude process startup unless a raw
field explicitly says wall time. Checksums, data checks and exit codes are verified.

Private commit, peak RSS, managed commitment and live block bytes are different
measurements. The lifecycle fixture reports private commit only on Windows; its
Linux zero means unavailable, not zero memory usage. Native GC metadata is outside
the managed-heap counters.

An initial eager cursor implementation slowed small-object churn by 4–7%.
It was replaced by the failed-head-only lookup before final validation; the
final results below use that revised implementation.

## Final measured results

### Thread registry and retained graphs

50 explicit collections after constructing and discarding Thread objects:

| Platform | Objects constructed so far | Before (ms / 50 GCs) | After (ms / 50 GCs) |
| --- | ---: | ---: | ---: |
| windows | 0 | 0.0088 | 0.0080 |
| windows | 50000 | 25.9864 | 0.0079 |
| windows | 100000 | 55.6136 | 0.0079 |
| linux | 0 | 0.0191 | 0.0182 |
| linux | 50000 | 28.1895 | 0.0179 |
| linux | 100000 | 58.4898 | 0.0178 |

The old registry adds **19.91 MiB of
Windows private commit** after 100,000 discarded, never-started Thread objects;
the new version adds **0.00 MiB** in this
probe. Managed commitment remains 32 MiB in both. This is native commit charge,
not a claim of the same reduction in resident RAM. With 2,000 actual
Start/Join/Close cycles, the old registry still adds 448 KiB; the new probe has
no continuing commit growth.

On both targets, sixteen abandoned 1-MiB logical ids previously left about
16 MiB reachable after GC; the new collector returns to the pre-test live
baseline. The dropped-graph handoff probe likewise retains about 16 MiB before,
and returns to baseline immediately after explicit collection with the fix.
The already-cleared-id control also remains at baseline.

### Successful fragmented allocation

These requests fit existing holes; previously every split introduced another
small prefix block to scan. The new measurements include the initial head probe.

| Platform | Requests | Before probes | After probes | Before (ms) | After (ms) | Time change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| windows | 1000 | 500500 | 1999 | 0.5919 | 0.1283 | -78.32% |
| windows | 2000 | 2001000 | 3999 | 1.9218 | 0.2626 | -86.34% |
| windows | 4000 | 8002000 | 7999 | 7.4191 | 0.6200 | -91.64% |
| linux | 1000 | 500500 | 1999 | 0.6450 | 0.0443 | -93.14% |
| linux | 2000 | 2001000 | 3999 | 2.1972 | 0.1164 | -94.70% |
| linux | 4000 | 8002000 | 7999 | 9.8503 | 0.6014 | -93.89% |

The 4,000-request case drops from 8,002,000 to 7,999 probes, demonstrating
linear work in this repeated-size pattern rather than relying only on timing.

### Worklist high-water release

With `--heap-shrink --heap-shrink-min 1m`, a 200,000-node graph grows the worklist
from 64 KiB to 2 MiB on both targets. After dropping it and the low-usage
hysteresis period, the old runtime retains 2 MiB; the new one returns to
64 KiB (**96.875% less committed worklist storage**). The separate metadata
regression repeats growth/shrink/regrowth three times and checks live contents.
Without `--heap-shrink`, high-water capacity is intentionally retained.

### General allocation and marking controls

| Platform | Workload | Before (ms) | After (ms) | Time change |
| --- | --- | ---: | ---: | ---: |
| windows | small-churn | 67.63 | 67.08 | -0.81% |
| windows | large-live | 234.31 | 233.89 | -0.18% |
| windows | leaf-mark | 16.07 | 16.10 | +0.21% |
| windows | graph-mark | 47.34 | 48.41 | +2.25% |
| windows | fragmented | 3.23 | 3.16 | -2.25% |
| windows | control | 13.32 | 12.99 | -2.47% |
| linux | small-churn | 70.26 | 70.90 | +0.91% |
| linux | large-live | 253.27 | 256.40 | +1.24% |
| linux | leaf-mark | 15.85 | 16.47 | +3.92% |
| linux | graph-mark | 44.44 | 47.55 | +6.98% |
| linux | fragmented | 5.94 | 6.00 | +1.01% |
| linux | control | 12.91 | 12.85 | -0.51% |

**This is not an across-the-board speedup.** Ordinary small-object churn is
approximately unchanged in the final sample (-0.8% Windows / +0.9% Linux).
Pure graph marking is +2.3% / +7.0% slower, and Linux leaf marking is +3.9%.
Those regressions are retained in the results, not hidden by the larger
lifecycle/fragmentation improvements. The general control suite's median peak
RSS and managed commitment are unchanged in every workload.

### Concurrent allocation

One million iterations per worker, two managed objects per iteration:

| Platform | Workers | Before (ms) | After (ms) | Time change |
| --- | ---: | ---: | ---: | ---: |
| windows | 1 | 16.78 | 16.38 | -2.41% |
| windows | 2 | 23.47 | 22.98 | -2.06% |
| windows | 4 | 43.28 | 32.42 | -25.08% |
| windows | 8 | 71.06 | 59.84 | -15.79% |
| windows | 12 | 103.91 | 90.69 | -12.72% |
| windows | 24 | 224.46 | 214.11 | -4.61% |
| linux | 1 | 19.42 | 19.07 | -1.78% |
| linux | 2 | 24.75 | 24.62 | -0.53% |
| linux | 4 | 46.35 | 35.99 | -22.36% |
| linux | 8 | 77.65 | 67.83 | -12.64% |
| linux | 12 | 116.50 | 98.98 | -15.05% |
| linux | 24 | 264.26 | 251.66 | -4.77% |

All checksums and worker-result checks match. The final parallel workloads use
32 MiB managed commitment in both versions. Linux median peak RSS is unchanged
at the reported resolution; Windows varies slightly (at 24 workers,
17.39
→ 17.54 MiB).
The largest time gains are in the four-worker cases (22–25%); this does not imply
the same gain for a whole server or game.

## Reproduction and raw evidence

From the Python repository:

```powershell
python tests/run_tests.py
python tests/check_memory_runtime.py mlc_win64.py
python tests/check_memory_runtime.py ../MiniLangCompilerML/build/mlc_win64.exe
python tests/check_memory_compiler_parity.py mlc_win64.py ../MiniLangCompilerML/build/mlc_win64.exe ../MiniLangCompilerML/build/mlc_linux_x64 --output build/memory-parity.json
```

From the ML repository:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_tests.ps1 -Compiler build/mlc_win64.exe
wsl -d Ubuntu -- python3 tests/check_memory_runtime.py build/mlc_linux_x64
python scripts/check_linux_runtime_blob.py
```

Compile the same `benchmarks/memory_lifecycle.ml`,
`memory_fragmentation.ml`, `memory_management.ml` and
`thread_allocation_churn.ml` with preserved before/after compilers and matching
target/options. The metadata image uses `memory_lifecycle.ml` with
`--heap-shrink --heap-shrink-min 1m`. Run the checked-in
`compare_memory_lifecycle.py`, `compare_memory_management.py` and
`compare_memory_threads.py` harnesses natively inside each target OS.
Use `--runs 7`; only the general harness uses `--cpu 0`.
Raw files preserve per-run samples, image sizes/hashes, platform and medians:

- [lifecycle windows](MEMORY_LIFECYCLE_WINDOWS_2026-10-06.json)
- [general windows](MEMORY_GENERAL_WINDOWS_2026-10-06.json)
- [threads windows](MEMORY_THREADS_WINDOWS_2026-10-06.json)
- [lifecycle linux](MEMORY_LIFECYCLE_LINUX_2026-10-06.json)
- [general linux](MEMORY_GENERAL_LINUX_2026-10-06.json)
- [threads linux](MEMORY_THREADS_LINUX_2026-10-06.json)
- [192-image compiler parity](MEMORY_PARITY_2026-10-06.json)

## Remaining limits

- This is not a size-class allocator: changing request sizes can still incur
  linear free-list searches. The new cache specifically removes repeated
  exact-size prefix rescans.
- GC is still stop-the-world and non-compacting. Fragmentation, retained roots
  and long managed stretches between safepoints can still affect memory/latency.
- Default retained heap/worklist capacity is not a leak. Opt-in shrinking can
  incur later page faults and recommit work; no universal RSS decrease is promised.
- Explicit Close remains recommended for prompt native resource release.
  Files, locks and arbitrary external handles do not gain generic finalizers.
- Native allocation/decommit/close error paths were reviewed and preserve
  conservative state. Reserve-exhaustion tests exist; arbitrary OS-failure
  injection and application-level MiniSQL/MiniQuake performance runs are not
  part of this evaluation.
