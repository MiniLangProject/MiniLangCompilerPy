# Memory runtime fixes and evaluation 6 October 2026

The follow-up fixes the CLI and native string-return differences found in the
[compiler reevaluation](COMPILER_REEVALUATION_2026-10-06.md). GC bitmap access and
runtime code alignment address the measured marking and string-control regressions.
The earlier Thread lifetime, free-list and metadata-retention fixes remain enabled.
These are unreleased development changes above 1.2.17.

## Implementation

Both code generators load aligned bitmap qwords and use register BT/BTS to test
or set one bit. The register bit index wraps modulo 64; the qword index selects
the corresponding group of 64 aligned heap headers. Collection holds the heap
and world-stop coordination locks. Committed bitmap pages cover the entire
committed heap, including the last qword. Pointer/tag/block bounds checks remain.

The collector clears the used bitmap prefix at every collection entry. The
second sweep no longer clears each live bit again. This preserves the existing
protection against stale/interior bits while avoiding redundant writes.
Runtime helper/extern entries and four hot GC loops start on 32-byte boundaries.
MLO support fragments include their canonical text offset when computing padding;
user-function alignment is unchanged.

The heap-size CLIs now share positive ASCII decimal syntax, ignored underscores,
ASCII edge whitespace and binary b/k/kb/kib/m/mb/mib/g/gb/gib/t/tb/tib suffixes.
The common maximum is 1152921504606781440 bytes (2^60 minus 65536), leaving room
for 64-KiB rounding in a positive MiniLang integer. Overflow is rejected before
decimal accumulation or suffix multiplication. This is a representability limit,
not a promise that the OS can reserve that much memory.

ML now writes requested ELF listings in both pipelines. Python ELF listings now
include requested data sections and use loaded virtual addresses. Default listing
names preserve extensionless and hidden filenames. Conflicting --asm/--no-asm
flags and failed listing writes produce compiler errors instead of silent
success or a native compiler runtime failure.

Native cstr return conversion uses the same strlen/copy helpers in both emitters.
The result stays rooted across managed allocation, and its header length is
reloaded after copying because Linux may clobber the volatile length register.
NULL returns void; an empty native string remains an empty MiniLang string.

## Regression coverage

The new shared fixtures cover 20000 cyclic/aliased object graphs with varied
block sizes and repeated collection/reuse, plus native string returns of lengths
0 through 16384 in the main thread and four concurrent workers. Both run in the
default regression suites and the expanded memory/pipeline checks.

The standalone CLI contract checks aliases, maximum/overflow values, long decimal
strings, non-ASCII digits, whitespace, every heap-size flag, explicit/default
listing paths, data sections, disabled listings, contradictory flags and listing
write failures. It builds both targets through both CLI pipeline modes; Windows
images are execution-tested on Windows, Linux images on Linux/WSL.

Independent assembler tests check exact BT/BTS bytes, high registers, native
results and carry flags at indexes 0, 1, 7, 8, 31, 32, 63, 64, 65, 127 and 4095.
Timing is never a correctness test threshold.

## Reproduction

Run the usual full suites, then these focused checks from either compiler repo:

```text
python tests/check_cli_memory_contract.py <compiler>
python tests/check_memory_runtime.py <compiler>
python tests/check_memory_compiler_parity.py <python-compiler> <windows-ml> <linux-ml> --output parity.json
```

The three-host parity command runs on Windows with WSL Ubuntu. Python accepts
the object-pipeline flag for CLI compatibility but does not have an independent
MLO backend. The native ML compiler exercises both backends.

For performance, compile the same checked-in benchmark sources with the preserved
release and current compilers, then use compare_memory_management.py,
compare_runtime_codegen.py, compare_memory_threads.py, compare_memory_pauses.py,
compare_memory_lifecycle.py and compare_compiler_codegen.py under benchmarks.
Use --heap-shrink --heap-shrink-min 1m for the metadata lifecycle image.

## Completed correctness checks

- Python full suite: 166 passed, zero failed/skipped.
- ML: 136 core tests plus the complete PowerShell integration runner, including
  Windows/Linux fixtures, formatter, std.test, diagnostics and both pipelines.
  The final native compiler passed a fresh complete rerun.
- 228-image matrix: 19 fixture/option combinations times two targets, three
  compiler hosts and two pipeline flags; every six-image group is byte-identical.
- Two 72-image memory runtime matrices pass, including expected reserve
  exhaustion. All three host CLI contract runs pass.
- 146 repeated native stress runs pass: 73 per target, including bitmap cycles,
  concurrent cstr, Thread/handoff lifetimes, safepoints, TLAB retirement,
  metadata shrink/regrow and lifecycle races.
- The 232 assembler golden vectors pass; native BT/BTS result/carry tests pass.
  The optional external NASM comparison was not enabled.
- All 24 native benchmark-image comparisons match the Python images exactly.
- All 53 std source files and 351 generated std reference files are identical.
- A locally rebuilt MiniDoc generates the compiler reference from 37 files and
  3290 symbols with zero warnings. The older installed binary lacked current
  integer-division parsing; MiniDoc sources were not modified.

## Self hosting

| Target | Matching build paths | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Windows | Python bootstrap and Windows ML selfbuild | 55379968 | `F37B7EDCE0A3D379C9119A056A9D0E433E11FAEA01578A3E4AB186CDE735FF5F` |
| Linux | Python bootstrap, Windows ML crossbuild and Linux ML selfbuild | 55382096 | `2C5995975E261CF8F879086A9D7DF8EA470430CB5C09DBD1F4702A7F01F844A2` |

The usual local build/mlc_win64.exe and build/mlc_linux_x64 paths contain these
verified artifacts. Previous binaries are preserved in the ignored follow-up
build directory. No commit, push, version bump or GitHub release was performed.

## Measurement method

Measurements use an AMD Ryzen 9 9900X with 12 cores and 24 logical processors,
Windows and Ubuntu under WSL. The two OS runs are serialized, with no compiler
builds or test suites running alongside the runtime benchmarks. Alternating A/B
order and warm-ups reduce drift; values below are medians of program-internal
elapsed time, excluding process launch. The raw evidence also retains wall time,
peak RSS, checksums, sizes, hashes and every sample.

General memory and runtime benchmarks use 21 samples per version, pinned to
logical CPU 0. Selected runtime controls have independent 31-sample repeats on
CPUs 0 and 2. Thread scaling uses 11 unpinned samples per worker count; lifecycle
checks use seven process pairs. Pause measurements contain 700 pauses per
version, clustered in seven processes, not 700 independent process samples.
These measurements characterize this machine and WSL setup, not all x64 CPUs
or bare-metal Linux installations. A positive percentage below means slower.

## GC and allocation performance

Comparison with release 1.2.17, 21 samples per version:

| Workload | Windows before ms | Windows after ms | Change | Linux before ms | Linux after ms | Change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Small allocation churn | 67.565 | 67.732 | +0.25% | 65.063 | 64.338 | -1.11% |
| Large retained objects | 235.535 | 233.507 | -0.86% | 239.351 | 233.965 | -2.25% |
| Leaf marking | 16.127 | 16.274 | +0.91% | 16.253 | 16.282 | +0.18% |
| Graph marking | 47.405 | 46.589 | -1.72% | 45.144 | 45.340 | +0.43% |
| Fragmentation control | 3.216 | 3.196 | -0.62% | 6.097 | 6.159 | +1.02% |

Against the previously reevaluated, regressed development image, graph marking
improves by 2.85% on Windows and 7.20% on Linux. The old +6.2% Linux graph
regression is no longer present at that magnitude. General managed-heap
commitments are unchanged; these optimizations do not change object sizes.

The original lifecycle benefits remain. In the Windows 100000-abandoned-Thread
probe, private commit no longer grows by 19.91 MiB: it stays at its initial
33.77 MiB. After 100000 contexts, fifty GCs take 0.0077 ms in aggregate versus
54.6342 ms with the permanent old registry. Linux also avoids the registry scan
growth; that fixture does not measure Linux private commit.

With shrink enabled, the worklist returns from 2 MiB to 64 KiB after graph
release. Four thousand fragmented allocations need 7999 free-list probes
instead of 8002000, taking 0.623 versus 7.514 ms on Windows and 0.670 versus
9.901 ms on Linux. These are the retained lifecycle/cursor fixes, not gains
attributable solely to the new bitmap instructions.

| Allocation workers | Windows elapsed change | Linux elapsed change |
| ---: | ---: | ---: |
| 1 | -1.12% | -5.69% |
| 2 | +0.45% | -4.37% |
| 4 | -20.42% | -25.67% |
| 8 | -15.67% | -14.43% |
| 12 | -13.66% | -14.09% |
| 24 | -7.26% | -5.67% |

Explicit GC pause p95 changes from 1.225 to 1.141 ms on Windows and from
1.596 to 1.492 ms on Linux. Maximum observed pauses are 1.708 and 1.934 ms
respectively. These are retained-graph GC times, not worst-case stop-the-world
latency under arbitrary thread contention.

## Runtime controls and remaining tradeoffs

The Linux string regressions are substantially reduced. In the full 21-sample
run, small concatenation changes by -3.49%, two-character repeat by -2.39%,
multi-repeat by -0.61%, and join by +1.61% versus release 1.2.17.

Independent 31-sample repeat results versus release:

| Control | Windows CPU 0 | Windows CPU 2 | Linux CPU 0 | Linux CPU 2 |
| --- | ---: | ---: | ---: | ---: |
| Small concatenation | -0.91% | -0.12% | -1.89% | -1.14% |
| Two-character repeat | +1.41% | +0.46% | -0.52% | -3.38% |
| Multi-repeat | +4.28% | +2.21% | +0.54% | -1.59% |
| Join | -2.30% | +0.18% | +2.31% | +1.78% |

This is not an across-the-board speedup: the Windows multi-repeat and Linux
join controls remain measurable small regressions. The CPU 0 inline-literal
repeat also fluctuates to +7.98%, but CPU 2 is -0.05% and the full run is
+1.85%; it is not established as a consistent two-core regression.
No correctness or checksum differences occur. Further layout tuning should be
qualified on additional CPUs instead of declaring one alignment universally best.

Alignment also has a size cost. Against the release, the tested memory/runtime
PE images grow by 1024 bytes each. ELF growth is 4112 bytes for the memory image
(a page boundary) and 16 bytes for the runtime image. Full image hashes and
sample details are retained in the machine-readable evidence.

## Compiler time and memory

The Windows self-hosted compiler builds tests/compiler_qualification_cache.ml
monolithically in a median 38.19 seconds versus 40.19 seconds with release
1.2.17, a 4.98% reduction. There is one warm-up and three alternating measured
builds per compiler. Peak working set changes from 1229914112 to 1230053376
bytes, about 1.15 GiB in both cases (+136 KiB, +0.011%). The fixture's executable
grows by 1024 bytes. This is a large compiler-internals fixture, not a fresh
MiniQuake build or a measurement of full self-compilation duration.

## Final targeted audit

After the correctness and measurement runs, the final review rechecked:

- BT/BTS ModRM/REX direction, modulo-64 indexing, bitmap commit boundaries,
  entry clearing, sweep ordering and shrink/regrow coverage.
- Precise scratch/handoff roots, weak Thread registry pruning, active/native
  epilogue retention and Win64 register/stack obligations in Linux adapters.
- Free-list cursor validity after head allocation, different request sizes,
  splitting, TLAB retirement, coalescing and GC rebuilding.
- Checked decimal/suffix arithmetic, ASCII whitespace, maximum page rounding,
  ELF/PE listing failure propagation and hidden/default output filenames.
- Canonical MLO padding offsets, cstr return register clobbers and root lifetime,
  final self-host hashes, shared-library equality and source comments.

No further reproducible memory/GC correctness defect was identified in this
scope. The audit did expose and repair the vertical-tab/form-feed parser gap,
conflicting listing switches, and the ML listing-write error escape before the
qualification runs. The final pass also caught Python accepting a Unicode Kelvin
sign as the suffix k after case folding; ASCII validation now happens first,
and the extended CLI contract was rerun on all three hosts. This parser-only
change leaves the qualified generated code unchanged.
The remaining performance tradeoffs are listed above;
this is not a universal speed, leak-freedom or concurrency-interleaving proof.

[Raw measurements and validation evidence](MEMORY_FOLLOWUP_2026-10-06.json)
include all planned A/B runs, individual samples, CLI/runtime checks, self-host
hashes, benchmark byte comparisons and the final stress/parity matrices.
