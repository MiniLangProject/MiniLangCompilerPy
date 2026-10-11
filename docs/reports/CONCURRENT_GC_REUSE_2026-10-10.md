# Concurrent GC: preserve free-range reuse during collection

Date: 10 October 2026. Status: unreleased development change after 1.2.19.

## Cause and fix

The optional Windows background collector cleared the central free-list head at
each snapshot. It reclaimed dead objects, but temporarily hid *all* previously
free blocks from allocating threads. Short-lived allocations made during each
cycle therefore advanced the heap frontier even when ample reusable memory
already existed. At publication those holes returned, only to be hidden again
by the next collection. This explains growth with a nearly unchanged live set;
it is not evidence that all additional committed bytes contain leaked objects.

Both compiler backends now build an immutable bitmap of snapshot-free ranges
during the initial stop-the-world handshake. These ranges stay allocatable.
Objects allocated there are excluded from the current snapshot, just like new
objects above its frontier, and become ordinary traceable objects next cycle.

The implementation preserves these invariants:

- Marking, both sweep passes and overflow retention check the exclusion bitmap
  before reading a protected block header. Mutators may split or initialize
  those headers concurrently.
- SATB deletion logging does not enqueue references to newly allocated objects
  in protected ranges. Existing snapshot references still use the normal barrier.
- The weak Thread registry treats new below-frontier contexts as live for this
  cycle. Created threads remain usable after collection.
- Adjacent central free entries coalesce at snapshot time, without sorting or
  scanning live objects. Newly dead blocks stay private to the collector until
  publication; the final merge and allocator-cache invalidation hold the heap
  monitor. A boundary between old and newly freed ranges coalesces next cycle.
- Bitmap words cover eight heap bytes per bit. A cleared sentinel word makes a
  free run ending at an exact bitmap-page boundary safe to scan. Helpers use
  baseline x64 instructions, not a new CPU-feature requirement.
- Metadata allocation failure disables bitmap reads for that cycle and falls
  back to the old frozen-list policy. It must not use stale bits or read beyond
  the retained allocation.

The default Windows collector and the Linux collector are unchanged. Linux can
host the compiler and generate Windows concurrent-GC programs, but the Linux
target still rejects `--gc-concurrent`.

## Memory and latency trade-offs

The additional bitmap is native process memory, outside the managed heap:
approximately one byte per 64 bytes of used heap frontier (1.56%), with page
rounding, a sentinel word and geometrically retained capacity. Growing it briefly
holds old and new allocations; the old allocation is then released. Building
the bitmap and coalescing old free entries add work to the initial handshake.

This change does **not** decommit managed heap pages or compact live objects.
`--gc-concurrent --heap-shrink` remains invalid. Commitment may still increase
when the application needs more live memory, allocation outruns collection, or
no sufficiently large contiguous free block exists. A retained high-water mark
is not the same as unbounded growth. Snapshot live-byte counters also exclude
objects born during that cycle, including allocations into reused ranges.

## Evaluation

### Isolated fixed-live-set benchmark

Five measured old/new pairs, after warming both executables, alternating order.
The game and unrelated builds were idle during these measurements. Both images
use `--gc-concurrent --heap-reserve 512m --heap-commit 16m` and the same source.
All ten overlap runs observed allocations during all 64 background cycles.
The live set remained 57,600,064 bytes in both variants.

| Measurement (median) | 1.2.19 release | Fixed development build |
| --- | ---: | ---: |
| Committed-heap growth across 64 cycles | +64 MiB | **0 MiB** |
| Final committed heap | 247.043 MiB | 183.043 MiB |
| Peak process working set | 264.516 MiB | 202.418 MiB |
| Wall time, allocation during collection | 1.070 s | 1.087 s |
| Wall time, wait-before-allocation control | 1.044 s | 1.075 s |
| Peak working set, wait control | 199.555 MiB | 202.418 MiB |

Both wait controls have zero heap growth. The overlap case saves about 23.5%
peak RSS at about 1.6% additional wall time; the wait control costs about 3.0%
wall time and exposes the approximately 2.86 MiB bitmap overhead. These are
small synthetic workloads, not universal speed or memory claims.

The retained-graph pause benchmark, also five warmed samples per image, reports
0.405 s median wall time for both old and fixed concurrent collectors. Median
maximum polling intervals are 0.381 and 0.378 ms respectively. The unchanged
synchronous control takes 0.233 s with a 13.852 ms median maximum interval.
Thus background collection still trades total work for shorter pauses.

### Hollowkeep: two complete ten-minute runs

The preserved A/B pair uses identical game sources, flags, assets and native
DLLs, plus separate copies of the recorded save. Each run completes 600 gameplay
seconds on floor 9: 51 waves, 408 new kills, 658 successful casts and 20 autosaves.
Both exit normally with no logged errors or SATB overflow. The actual user's
save is hash-checked unchanged; only isolated benchmark saves are written.

Memory endpoints are the first and last logged samples after 100 seconds with
the obsolete village textures retired. Each interval spans approximately 510
seconds. This matches the earlier report's method, but uses a fresh native A/B
pair rather than comparing different game revisions.

| Measurement | 1.2.19 release | Fixed development build |
| --- | ---: | ---: |
| Private process memory, first -> last | 2,838.0 -> 4,235.1 MiB | 2,631.5 -> 2,795.1 MiB |
| Private process memory, last | 4.14 GiB | **2.73 GiB** |
| Committed MiniLang heap, first -> last | 1,669.4 -> 3,061.4 MiB | 1,492.0 -> 1,636.0 MiB |
| Committed-heap growth | +1,392 MiB | **+144 MiB** |
| Live managed bytes, first -> last | 824.774 -> 825.283 MiB | 824.780 -> 825.285 MiB |
| Warm average FPS | 301.2 | 310.9 |
| Reported warm P99 upper bucket | 6.77 ms | 6.87 ms |
| Reported warm P99.9 upper bucket | 9.2 ms | 13.4 ms |
| Warm frames >=16 ms | 14 | 29 |
| Accumulated GC handshake pauses | 647.4 ms | 8,176.1 ms |
| Maximum measured GC handshake | 28.56 ms | 34.18 ms |

The measured heap-growth reduction is **89.7%**, and final private memory is
34.0% lower. However, **144 MiB of residual heap growth remains**. The test does
not establish permanent memory stability or identify the remaining growth's
cause. Fragmentation and transient allocation headroom are possible mechanisms,
not proven diagnoses. A further allocator/free-range profile is needed before
claiming the entire application memory issue is eliminated.

There is a material latency cost: snapshot/free-list work increases accumulated
GC pauses, and the game's measured frame tail is worse despite higher average
FPS. Only one game run per variant was made, and the early baseline overlapped
other compiler work. Do not attribute the FPS increase or individual outliers
solely to this fix. The isolated repeated benchmarks above are the controlled
timing comparison. No allocator-wait policy or synchronous collection on ordinary
allocation misses was introduced to obtain the memory reduction.

The game working tree changed externally after the native pair was staged.
The later Python game build is therefore not used as application byte-parity
evidence. Self-hosting and the shared-fixture parity checks below remain valid.
Sanitized measurements, sample timings, validation results and image hashes are
in [the evaluation data](concurrent-gc-reuse-evaluation-2026-10-10.json). Full logs
and isolated game fixtures remain in ignored `build/gc-reuse-*` directories;
no proprietary game sources, assets or saves are added to either repository.

## Correctness and binary parity

- Python suite: **169 passed, zero failed or skipped**.
- ML suite: **136 core tests and 208 outer integration checks passed**.
- **100 stress executions**: twenty each of fixed-live-set reuse, fragmented
  multi-mutator reuse, ordinary SATB transfers, forced SATB overflow, and
  constrained-heap allocation pressure; all passed.
- Four Python emitter tests passed, including native execution of snapshot,
  membership and range-end helpers against an independent bitmap/range model.
  Cases cover shuffled adjacent free entries, partial words, page boundaries,
  a free range above a 2 GiB heap offset, whole-heap/empty lists, repeated cycles,
  growth, reduced used prefixes, and first/later metadata allocation failures.
- Nine assembler tests passed; optional external NASM verification was not
  enabled (one skip).
- Two-host CLI size/listing/bitmap/native-cstr contracts passed for both targets
  and both pipeline settings.
- **342 generated images** in the completed memory/concurrent parity subsets
  matched by target, fixture and options across Python, Windows ML and Linux ML.
  This is 192 default-collector images plus 150 concurrent/fallback/capacity
  images. Concurrent runtime fixtures execute, not merely compile.
- Twelve additional qualified-type/global-member images execute and match
  across the same three hosts and two pipelines for Windows and Linux.
- Eight pre-fix/fixed default-collector fixture pairs remain byte-identical
  across Windows and Linux. All **53 std modules** and **351 generated std
  reference files** remain identical between repositories.

### Verification limitation: Defender

The complete extended matrices were attempted, but Windows Defender blocked
generated `memory_policy.ml` and concurrent `gc_float_call_roots.ml` images with
the heuristic detection `Trojan:Win32/Wacatac.C!ml`. Windows reported that the
files could not be opened; Python surfaced some reads as `OSError: Invalid
argument`. No protection, policy or exclusion was changed.

The subsequent matrix runs explicitly exclude those fixtures and print
`[PARTIAL OK]`, with the exclusions recorded in their JSON outputs. Excluding
`memory_policy.ml` also omits its Linux groups from that parity run. Thus these
subsets are **not** a claim that the entire original matrix passed. The ordinary
suites and the newly added reuse regressions passed separately.

### Self-hosted artifacts

These development binaries still report 1.2.19; published release artifacts and
release checksums are not replaced by this change.

The verified local outputs are `MiniLangCompilerML/build/gc-reuse-final.exe`
and `MiniLangCompilerML/build/gc-reuse-linux`. The normal `build/mlc_win64.exe`
was in use by other compilation processes at handoff, so neither standard
installed compiler path was overwritten. Use the explicit development paths
for follow-up application builds until the normal artifacts are updated.

| Target | Bytes | Matching builds | SHA-256 |
| --- | ---: | --- | --- |
| Windows x64 | 56,737,792 | Python bootstrap, Windows ML object-pipeline selfbuild | `11A428DBFB817FC81E166D2605261DFDE910EB8F7C191171E667302C5E7843B1` |
| Linux x64 | 56,742,160 | Python crossbuild, Linux-native ML monolithic selfbuild | `D08D0A8C7DC7B6936D6C5FEFD0970BF15B8EDF9E1D170650D0F8C59D973C9206` |

An additional Python bootstrap after the frontend fixes below reproduces the
same Windows hash. PE and ELF images are compared within their own target, not
against one another.

## Additional parity fixes found during application validation

Python's `is` parser looked for an operator token where the lexer emits `DOT`.
It now accepts qualified type names such as `value is module.Type`, matching ML.
Python member assignment now also resolves an implicit package/namespace global
before deciding that `object.field = value` denotes a namespace-qualified global
write. The ML backend already handled that case. Both repositories' type tests
cover imported aliases, nested names, positive/negative struct and enum checks,
and mutation of a namespaced global object.

## Reproduce

The plateau regression is part of both regular suites. The focused concurrent
matrix also checks both pipeline modes and can compare all three compiler hosts:

```powershell
python tests/check_concurrent_gc.py ../MiniLangCompilerPy/mlc_win64.py --reference build/gc-reuse-final.exe --linux-reference build/gc-reuse-linux --output build/gc-reuse-matrix.json
python ../MiniLangCompilerPy/tests/test_concurrent_gc_codegen.py
```

The default invocation excludes nothing. Only when a local environment prevents
a fixture from running should an explicit `--exclude-fixture <filename>` be
used; retain the partial-run status and explain it in any results.

Build `benchmarks/concurrent_gc_reuse.ml` with preserved before/after compilers,
using `--gc-concurrent --heap-reserve 512m --heap-commit 16m`. Then run:

```powershell
python benchmarks/compare_concurrent_gc_reuse.py build/gc-reuse-before.exe build/gc-reuse-after.exe --runs 5 --output build/gc-reuse-comparison.json
python benchmarks/compare_concurrent_gc_reuse.py build/gc-reuse-before.exe build/gc-reuse-after.exe --runs 5 --wait --output build/gc-reuse-control.json
```

`wait` allocates only after collection finishes and isolates the overlap effect.
The benchmark retains raw checkpoints and does not reject the deliberately
regressing old binary. The strict bounded-growth assertion belongs to the
regression fixture. Run timing comparisons with unrelated builds and games idle.
