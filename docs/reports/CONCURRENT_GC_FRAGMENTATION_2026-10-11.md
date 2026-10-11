# Concurrent GC fragmentation and TLAB reuse

Date: 11 October 2026. Unreleased development change after 1.2.19.

This report preserves the allocator checkpoint measurements. The later
[full-game parity and native memory follow-up](HOLLOWKEEP_PARITY_AND_NATIVE_MEMORY_2026-10-11.md)
resolves the code-generation differences and records the current compiler
hashes, broader tests and investigation of native process-memory fluctuations.

The remaining Hollowkeep heap growth came from fragmentation, not from the
collector withholding its old free blocks. Size-segregated allocation and
partial thread-local allocation buffer (TLAB) refills eliminate the measured
warm heap growth in two complete ten-minute runs, one from each compiler.
This does not prove that all process memory or every workload is leak-free.

## Evidence and allocator changes

A fresh baseline includes the previous
[free-range reuse fix](CONCURRENT_GC_REUSE_2026-10-10.md).
At all eleven warm heap expansions, the background collector was idle.
The allocator had 538–701 MiB free, but no single available block was large
enough for the requested approximately 5.1 MB or 8 MiB buffer. This is direct
free-list census evidence of fragmentation rather than an allocation merely
outrunning the collector.

Keeping one globally address-ordered first-fit list was insufficient: that
candidate passed a small regression but increased warm committed growth from
176 to 368 MiB in the game. It was rejected. The final allocator instead:

- Places free ranges in 64 power-of-two size classes. Ordinary allocations
  search the smallest suitable class before larger ones; within a class they
  still use first-fit, not an exact best-fit search.
- Lets TLABs consume existing 4–64 KiB ranges rather than requiring a full
  64 KiB refill and cutting large holes into pieces. Ordinary 64 KiB objects
  cannot receive smaller blocks. Allocation-pressure and requested-byte counters
  charge the actual capacity.
- Coalesces adjacent snapshot-free ranges by scanning the compact immutable
  bitmap and redistributes them into bins. Newly reclaimed ranges remain
  private until publication under the heap monitor.
- Counts all bins in free-memory diagnostics, including more than 200,000 valid
  entries and sizes above 4 GiB. Invalid pointers, wrapped header addresses and
  cycles produce bounded, zero-valued diagnostics instead of unsafe reads.
- Preserves snapshot exclusion, SATB barriers, weak Thread handling and the
  conservative metadata-allocation-failure fallback. That fallback withholds
  every size class, including entries from a previous successful snapshot.

This adds 512 bytes of bin heads to concurrent images. The prior exclusion
bitmap still costs approximately 1.56% of the used frontier, plus retained
capacity and rounding. Small refills increase central allocator visits, so
reducing fragmentation does not automatically imply higher throughput.

Only optional Windows `--gc-concurrent` allocation changes. Default Windows
and Linux collectors are unchanged. Linux-hosted compilers can generate the
Windows mode, but the Linux target still rejects it. There is no compaction or
managed-page decommit; `--gc-concurrent --heap-shrink` remains invalid.

## Hollowkeep measurements

All variants use frozen source files with SHA-256
`0ee4e048f8e15ae38397590eaca41679b026ce549fccf275f0a85a42881ee909`,
the same flags, DLLs, assets and recorded save. Each run completes 600 gameplay
seconds on floor 9, 51 waves, 408 new kills, 658 successful casts and 20 autosaves.
All 13 validation checks pass for every run: normal exit, expected gameplay,
no logged errors or SATB overflow, and the actual user save remains unchanged.

The warm interval is the first and last memory sample after 100 seconds with
obsolete village textures retired, spanning approximately 510 seconds.

| Measurement | Previous reuse fix, Python | Size classes and partial TLABs, Python | Size classes and partial TLABs, ML |
| --- | ---: | ---: | ---: |
| Committed heap, first → last | 1,450.64 → 1,626.64 MiB | 1,163.61 → 1,163.61 MiB | 1,173.88 → 1,173.88 MiB |
| Warm committed-heap growth | +176 MiB | **0 MiB** | **0 MiB** |
| Private process memory, first → last | 2,603.00 → 2,819.16 MiB | 2,301.48 → 2,323.64 MiB | 2,291.10 → 2,312.58 MiB |
| Private process growth | +216.16 MiB | +22.15 MiB | +21.48 MiB |
| Live managed bytes, first → last | 824.781 → 825.288 MiB | 824.779 → 825.290 MiB | 824.783 → 825.289 MiB |
| Total measured GC handshake pauses | 7,635.14 ms | 8,954.11 ms | 9,003.75 ms |
| Maximum measured GC handshake | 24.09 ms | 26.14 ms | 26.72 ms |

The Python diagnostic ring records zero warm heap expansions after the fix.
Its last expansion occurs during loading. Final private memory is 17.6% below
the fresh previous-fix baseline, while live managed memory is essentially equal.

About 21–22 MiB of private process growth remains despite constant managed
commitment. Texture payload increases by about 1.8 MiB; these samples do not
attribute the rest to specific native allocations. Do not describe all remaining
process growth as fixed or assume it is necessarily a leak. The test establishes
a heap plateau for this workload and duration, not an unlimited-time guarantee.

The game runs overlap compiler verification and other local benchmark activity.
Their average FPS values (258.3, 232.2 and 209.4) and frame tails are recorded in
the evaluation data, but are **not an isolated speed comparison**. In particular,
this change does not establish unchanged game latency or a game speedup.
The previous-fix, address-order and final Python runs use identical diagnostic
census instrumentation; the ML run uses an ordinary uninstrumented image.
The last defensive invalid-pointer check was added after the game images were
built; the final native helper tests and compiler matrices verify that guard.

### Isolated repeated timing comparison

The fixed-live-set `concurrent_gc_reuse.ml` benchmark compares the previous
reuse fix with the final size-class allocator. Both images are warmed, then
measured five times in alternating order. Compiler builds, documentation
generation and the observed local game benchmarks have finished before timing.
Each sample executes 64 collection cycles and validates unchanged live bytes
between its own first and last checkpoint.

| Median | Previous reuse fix | Size classes and partial TLABs |
| --- | ---: | ---: |
| Allocate during collection | 1.10895 s | 1.11528 s |
| Wait-before-allocation control | 1.04629 s | 1.05837 s |
| Heap/frontier growth, either case | 0 bytes | 0 bytes |

These are increases of **0.57%** and **1.15%** respectively, not a measured
speedup. Peak RSS is essentially unchanged at about 202.4 MiB. The reuse-only
baseline already handles this simple hole pattern without growth; the game's
fragmentation reduction is measured separately above. Five short samples do
not establish a universal overhead bound or unchanged game frame tails.

## Correctness and parity

The final Python suite passes **171 tests**, with zero failures or skips.
The ML suite passes **136 core tests and 212 outer integration checks**.
All four native emitter tests pass. The complete concurrent-GC matrix passes
without exclusions: **180 generated images**, including ordinary/fallback and
capacity-clamp variants, match within each configuration across Python,
Windows-hosted ML and Linux-hosted ML, with both pipeline settings. Runtime
fixtures execute; this is not only a compilation check.

Two mirrored regressions reproduce the allocation failure mode without game
sources: allocating a small buffer must preserve a suitable larger hole, and
100,000 retained small arrays must use almost-64-KiB holes without consuming a
16 MiB buffer hole. Both fail against the previous reuse allocator and pass
with zero frontier growth against the new allocator.

Native emitted-helper tests compare bitmap and bin behavior with independent
models. They cover randomized lists and allocations, partial refills, ordinary
64 KiB allocations, repeated snapshots, empty/whole heaps, page boundaries,
offsets above 2 GiB, sizes above 4 GiB using sparse virtual reservations, metadata
OOM, corrupted diagnostics and 200,001 valid free blocks. Code pages are RX and
test data pages are RW; sparse reservations and native allocations are released.

Final Windows Python bootstrap and Windows ML object-pipeline selfbuild match:
`C3335D4A31606697BC5034D0B3072B3441D5BB0A9A0434D575C9A4F3311E3C79`
(57,180,672 bytes). Windows ML Linux crossbuild and Linux-native monolithic
selfbuild also match:
`4871EC23116942F9414208411E4DE9805B3B4FB20B895BCB6B1F72E3B28096B3`
(57,180,480 bytes).

Eight before/after default-collector fixture pairs remain byte-identical across
Windows and Linux. All 140 repeated stress executions pass: twenty each of
fixed-live-set reuse, fragmented multi-mutator reuse, SATB transfer, forced
SATB overflow, constrained heap pressure and the two new regressions.
All 53 std modules and 351 generated std reference files remain identical.

### Full game parity at the allocator checkpoint

The allocator-checkpoint Hollowkeep Python and ML images were not byte-identical.
The comparison already differs before size classes were introduced: 46 user
function lengths and the global/data layout differ. Frozen source inputs
eliminate the earlier uncertainty about an externally changing game checkout.
Successful self-hosting and shared-fixture parity must not be presented as
proof of full-game byte parity. Both game images pass the complete runtime
fixture. The later code-generation follow-up linked above resolves this finding:
the complete game now has the same SHA-256 with both compilers.
An additional monolithic full-game comparison was stopped after a ten-minute
diagnostic bound without producing its output; it supplies no parity result.

## Reproduction and artifacts

Run the usual Python and ML suites, plus:

```powershell
python -m unittest discover -s tests -p test_concurrent_gc_codegen.py -v
python tests/check_concurrent_gc.py ..\MiniLangCompilerPy\mlc_win64.py --reference build/gc-growth-2026-10-11/compiler-final.exe --linux-reference build/gc-growth-2026-10-11/compiler-final-linux --output build/concurrent-final-parity.json
```

Compile `tests/gc_concurrent_order.ml` and `tests/gc_concurrent_bins.ml` with
`--gc-concurrent`; both print an `[OK]` marker and exit zero.

Sanitized measurements and hashes are in
[the evaluation data](concurrent-gc-fragmentation-evaluation-2026-10-11.json).
Diagnostic scripts, complete logs, candidate builds, isolated runtime folders
and copied save fixtures remain under ignored
`MiniLangCompilerML/build/gc-growth-2026-10-11/`. No game source, asset or save
is added to either compiler repository. Development binaries still report
1.2.19; no commit, push or published release replacement is part of this change.

The normal local ML paths `build/mlc_win64.exe` and `build/mlc_linux_x64`
contain the verified development outputs. Their previous installed images are
preserved in `build/gc-growth-2026-10-11/previous-installed/`; published release
packages and release checksum manifests are unchanged.
