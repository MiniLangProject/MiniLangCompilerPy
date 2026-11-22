# Allocation and garbage collection audit, 2026-11-22

## Scope and conclusion

This audit exercised the generated Windows x64 and Linux x64 runtimes from the
Python and self-hosted compilers. It reviewed the allocator, TLAB retirement,
mark/sweep rebuild, heap trimming, native metadata retention and thread-context
lifecycle. The tested workloads showed no progressive managed-heap or Windows
private-commit leak. This is bounded evidence, not a proof for every FFI or
application ownership pattern.

The main performance trade-off is `--heap-shrink`: it returns committed top
pages promptly, but repeated growth and decommit substantially slows a hot
allocation workload. The default collector is preferable while throughput
matters. `--gc-concurrent` is a pause-latency option for threaded programs;
it also costs memory and single-thread throughput. It cannot be combined with
`--heap-shrink`.

## Long-running allocation and reclamation

The new [24-cycle regression](../../tests/memory_long_churn.ml) repeatedly
creates short-lived arrays and 96-byte, 8-KiB and 4-MiB byte buffers, with a
bounded live ring. Each cycle allocates and reclaims about 29 MB. The test
records post-GC reachable bytes, reclaimed bytes, heap commitment, frontier,
free-list bytes and, on Windows, process private commit. The
[memory matrix](../../tests/check_memory_runtime.py) checks every collection
for reclamation, a stable live set, and a trimmed heap; it runs in both object
pipelines and on both target systems.

| Mode | Post-GC live | Committed heap after warmup | Windows private commit after warmup | Trend through cycle 24 |
| --- | ---: | ---: | ---: | --- |
| Windows, `--heap-shrink` | 112 B | 1 MiB | 2,338,816 B | Flat |
| Windows, default synchronous GC | 112 B | 32 MiB | 35,418,112 B | Flat |
| Windows, `--gc-concurrent` | 112 B | 32 MiB | 44,302,336 B | Flat |
| Linux, `--heap-shrink` | 112 B | 1 MiB | Not sampled | Flat |

Without shrinking, committed pages and free ranges are retained for reuse;
their persistence does not by itself indicate live objects. In the concurrent
case, the frontier settled near 33 MiB and the free list near 33 MiB. The
unused region remained reusable. The Windows private-commit values above were
unchanged from the first full cycle through the last.

Thread lifecycle probes created 100,000 unstarted Thread contexts and 2,000
started/joined/closed threads. Reachable heap stayed at 184 B, and Windows
private commit stayed at 2,334,720 B after each batch. A broad live graph grew
the native mark worklist to 2 MiB; nine low-demand collections with shrinking
returned it to 64 KiB. Tests also cover abandoned completed thread handles,
handoff roots, TLAB retirement, bounds of the heap reservation, free-list
reuse, metadata growth and concurrent GC pressure.

An interior-page residency probe distinguishes OS behavior. After collecting
a dead 64-MiB buffer between live neighbors, Linux RSS fell from about 68 MiB
to 2.16 MiB with `--heap-shrink`; without it, post-GC RSS was about 69 MiB.
Windows RSS stayed near 75.6 MiB in both variants. The Windows runtime uses
`MEM_RESET` for interior pages, which is a discard hint and does not guarantee
an immediate working-set reduction. Top-of-heap decommit did reduce Windows
private commit in the long-churn test.

## Allocation and collection cost

The existing [memory benchmark](../../benchmarks/memory_management.ml) was
compiled with a 512-MiB reserve, 32-MiB initial commit and 64-MiB periodic GC
limit. Nine alternating runs per pair were measured on an AMD Ryzen 9 9900X;
the table uses the program's workload timer. The small-churn case performs
five million 64-byte buffer allocations. Checksums matched in every run.

| System and mode | Small churn | Graph mark (40 collections) | Peak RSS, small churn |
| --- | ---: | ---: | ---: |
| Windows, synchronous default | 76.08 ms | 45.21 ms | 76.31 MB |
| Windows, `--heap-shrink` | 128.88 ms | 44.94 ms | 76.25 MB |
| Windows, `--gc-concurrent` | 82.04 ms | 73.05 ms | 119.40 MB |
| Linux/WSL, synchronous default | 79.67 ms | 45.76 ms | 69.40 MB |
| Linux/WSL, `--heap-shrink` | 133.81 ms | 44.59 ms | 69.45 MB |

Shrinking raised small-churn time by about 69% on Windows and 68% on Linux.
It lowered final managed commitment but did not lower the measured peak RSS
during this workload. Concurrent GC raised single-thread churn time by about
9% and peak RSS by about 43 MB on Windows. Neither option improved the
single-thread benchmark enough to justify enabling it as a general default.

The [thread-allocation benchmark](../../benchmarks/thread_allocation_churn.ml)
allocates two managed objects per iteration with a bounded live ring. Seven
repetitions per thread count gave approximately 17 ms for 2 million
allocations on one Windows worker, 36 ms for 8 million on four, and 67 ms for
16 million on eight. Linux/WSL was approximately 18, 36 and 69 ms. This is
roughly a twofold throughput gain from one to four workers, followed by a
plateau. The benchmark is short and does not establish scaling for a whole
application.

## Verification

- The existing memory-runtime matrix passed with both compilers on Windows and
  Linux, including the new long-churn case and both monolithic/object builds.
- The [three-host parity matrix](../../tests/check_memory_compiler_parity.py)
  produced 240 byte-identical images: Python, Windows-hosted ML and
  Linux-hosted ML, each with both object-pipeline settings and both targets.
- Additional long-churn images for default, shrink and concurrent Windows GC,
  and shrink-mode Linux GC, were byte-identical between Python and Windows ML.
- The earlier full compiler suites remained green before this test-only audit.
  No runtime or code-generator change was needed.

The new regression is intentionally small enough for routine execution. It
does not cover long-lived native resources owned by arbitrary FFI libraries,
nor does a stable post-GC live count rule out every retention pattern in a
larger program.
