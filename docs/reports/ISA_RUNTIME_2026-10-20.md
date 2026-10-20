# Native ISA/runtime optimization evaluation — 2026-10-20

## Scope and outcome

This evaluation uses the pre-version-bump checkpoint of the changes released
in 1.2.22. Both the Python and self-hosted compilers implement the same
production behavior:

1. Baseline-x64 `BSF r64` / `BSR r64` replace split 32-bit scans in the Windows
   concurrent collector's free bins and reuse/coalescing bitmaps.
2. Bounded copy/fill helpers select small scalar/SSE2 operations, an unrolled
   AVX copy loop, and large REP operations. Runtime CPU detection exposes ERMS
   (128) and FSRM (256) without changing existing feature bits.
3. Reflected IEEE CRC32 uses PCLMULQDQ folding for inputs of at least 64 bytes
   when supported. Small inputs, incremental seeds and software fallbacks
   retain their exact results. CRC32C is a different polynomial and is unchanged.

CMOV selection and SIMD Base64 were **evaluated as isolated prototypes only**.
Neither is an enabled production compiler pass or a new standard-library
implementation. See their limitations below.

The largest measured application-level gain is approximately **13.3× faster
IEEE CRC32**. Allocation-inclusive small copies take **29–31% less time**, and
small fills **15–21% less time**. Large allocation-inclusive transfers, memory
usage, and the general-code controls remain essentially unchanged.
This is not a claim that every MiniLang program becomes 13× faster.

[Raw results, all samples, image hashes and validation metadata](ISA_RUNTIME_2026-10-20.json)
are mirrored in both compiler repositories.

## Baseline and method

- Before: release **1.2.21**; Python commit `a596a57ab7cb4c8c8cf89ea2005551ea58a312a5`,
  ML commit `818bc5e8e77b6110d962453ec2a39148f7f77baa`.
- Before program images were built from the same benchmark sources with the
  preserved release compiler. Its Windows SHA-256 is
  `68bc63c79f7ce5b50b750652baaefdfcb808ea1bd825280b927a143d8ea0bebe`.
- Machine: AMD Ryzen 9 9900X, 12 cores / 24 logical processors.
- Windows 11 Pro, build 26200; Ubuntu under WSL2, kernel
  6.6.87.2-microsoft-standard-WSL2. **WSL measurements are not bare-metal Linux
  measurements and must not be used to rank the two operating systems.**
- Detected runtime feature mask: 511. Masked tests also exercise the paths
  without AVX2, ERMS and PCLMUL. Masking never enables unsupported features.
- Final program workloads: 11 alternating A/B runs after warming each image.
  General-code controls: 21 runs. Native hot-buffer helpers: 9 rounds.
  Selected noisy microbenchmarks were repeated for 21 rounds and are retained
  separately, not substituted silently for the original screen.
- These runners are pinned to logical CPU 2. Reported program times are the
  program's high-resolution workload timer; process startup/finalization is
  excluded. The JSON separately records wall time and peak RSS.
- Native microbenchmarks put the repetition loop in emitted machine code, not
  Python. They normally use unaligned source/destination addresses and hot
  buffers; they exclude allocation, page faults and language dispatch.
- Own build/test workers finished before the final serial performance run.
  Another project had an active test/build process on the same machine.
  CPU affinity does not eliminate shared-cache, memory-bandwidth, frequency or
  VM noise; differences around 1% are not treated as established improvements.
- Every program run verifies the checksum across before/after builds. Raw
  helpers additionally have independent correctness/guard-page tests.
- No MiniSQL, HollowKeep, or MiniQuake frame-rate benchmark was run in this
  evaluation. Compiler bootstrap times were collected during paired builds
  with other validation work and are **not** a compile-speed comparison.

## Allocation-inclusive program workloads

Medians in milliseconds; negative changes mean less time.

| Workload | Windows before → after | Change | WSL/Linux before → after | Change |
|---|---:|---:|---:|---:|
| IEEE CRC32, 128 MiB in 128 KiB updates | 202.332 → 15.170 | -92.5% | 203.644 → 15.321 | -92.5% |
| 200,000 allocated 63-byte copies | 4.827 → 3.429 | -29.0% | 5.675 → 3.890 | -31.4% |
| 200,000 allocated 128-byte fills | 5.680 → 4.821 | -15.1% | 7.716 → 6.060 | -21.5% |
| 128 allocated 1 MiB copies | 14.291 → 14.151 | -1.0% | 27.908 → 27.839 | -0.2% |
| 128 allocated 1 MiB fills | 12.619 → 12.605 | -0.1% | 26.018 → 25.773 | -0.9% |
| Existing Base64 encode, 4 MiB | 28.538 → 28.534 | -0.0% | 29.372 → 29.494 | +0.4% |
| Existing Base64 decode, 4 MiB output | 114.815 → 114.727 | -0.1% | 120.099 → 119.949 | -0.1% |

The large copy/fill cases spend substantial time allocating and touching fresh
pages. Their result is much smaller than the hot-buffer copy speedup. Base64
is a control: its library implementation has not been vectorized in this patch.

### General-code controls after tuning

| Workload | Windows before → after | Change | WSL/Linux before → after | Change |
|---|---:|---:|---:|---:|
| Integer division | 61.867 → 61.628 | -0.4% | 64.518 → 64.217 | -0.5% |
| Local register loop | 11.606 → 11.659 | +0.5% | 12.097 → 12.042 | -0.5% |
| Dynamic array indexing | 21.565 → 21.550 | -0.1% | 21.951 → 21.988 | +0.2% |
| String concatenation | 7.453 → 7.504 | +0.7% | 11.920 → 11.661 | -2.2% |
| String repetition | 4.648 → 4.663 | +0.3% | 8.182 → 8.134 | -0.6% |
| Small integer formatting | 6.802 → 6.819 | +0.3% | 7.159 → 7.173 | +0.2% |

The maximum slowdown among these final control medians is below 0.7%.
This is not a statistical guarantee for arbitrary applications or CPUs.

## Raw helper screen

Nine-round medians in **nanoseconds per call**, with hot buffers:

| Helper | Windows before → after | WSL/Linux before → after |
|---|---:|---:|
| Copy, 63 bytes | 4.99 → 0.93 | 4.82 → 0.96 |
| Copy, 4 KiB | 33.79 → 28.44 | 28.95 → 22.19 |
| Copy, 64 KiB | 627.08 → 536.58 | 546.75 → 539.33 |
| Fill, 128 bytes | 8.74 → 2.91 | 8.89 → 5.78 |
| Fill, 64 KiB | 232.84 → 250.26 | 222.40 → 221.99 |
| IEEE CRC32, 63 bytes | 70.04 → 71.22 | 70.49 → 70.73 |
| IEEE CRC32, 1 MiB | 1544458.33 → 118028.57 | 1552025.25 → 118342.50 |

These numbers are deliberately not substituted for the allocation-inclusive
results. In particular, the 64 KiB Windows fill was 7.5% slower in this screen.
A dedicated 21-round recheck gave 206.06 → 205.83 ns on Windows and
207.00 → 204.95 ns under WSL; the apparent regression did not persist.
The WSL 128-byte copy also varied markedly between buffer allocations/runs:
5.42 → 5.60 ns in the first screen, but 1.71 → 1.20 ns in the focused recheck.
All samples are archived. We make no universal speedup claim for these
cache-sensitive individual cases. Short CRC inputs remain table-driven and
can pay a small dispatch overhead (about 1 ns in the Windows 63-byte case).

## Decisions driven by regressions, not only microbenchmarks

- **Do not select short REP merely because FSRM exists.** On this CPU an
  unaligned 128-byte forced-REP copy took about 15.6 ns versus 1.3 ns for the
  vector path in the dispatch experiment.
- **Use ERMS from 64 KiB, not 32 KiB.** The initial 32 KiB crossover made the
  allocation-heavy WSL string-repeat control 10.6% slower in a 21-run recheck.
  Source ablation with ERMS disabled isolated this regression. The 64 KiB
  crossover keeps its 48 KiB doubling copy vectorized.
- **Interleave the AVX loads and stores.** Grouping both loads before both
  stores caused approximately 4% slower Windows concatenation. The
  interleaved variant removed that regression in the ablation and final
  program tests; the exact microarchitectural cause was not profiled.
- **Bypass vector setup on large fills.** A more elaborate feature-dispatch /
  vector-pattern setup regressed cache-sized fills. The retained path jumps
  directly to the established REP STOSB implementation above 256 bytes.

The rejected-candidate checks are marked separately in the raw JSON.
Final behavior is identical in both compilers and on both target formats.
Copy ranges must still be non-overlapping, as required by the existing
`copyBytes` / `copyArray` contract; this is not a new memmove implementation.

## Memory, GC and image size

Managed heap deltas are identical for every before/after program workload and
control. Large copy/fill cases use 134,219,776 bytes of managed heap growth in
both versions. Their peak RSS is approximately 137.5 MiB on Windows and
131.1 MiB under WSL, also unchanged within each OS. A few 4–16 KiB RSS
differences in other cases are not interpreted as memory optimizations.

The five-run Windows concurrent-GC probe maintains a fixed 800,000-node graph,
seeds a 128 MiB reusable hole, and churns through 64 collection cycles:

| Metric | Before | After |
|---|---:|---:|
| Median complete probe time | 1.1003 s | 1.0971 s |
| Median peak RSS | 212,234,240 bytes | 212,234,240 bytes |
| Committed-heap growth after warm-up | 0 | 0 |
| Allocation-frontier growth after warm-up | 0 | 0 |

That timing difference is too small to claim a meaningful GC speedup. The
64-bit bit scans simplify and shorten the generated GC code; they do not
change roots, write barriers, allocation policy or lifetime semantics.

The runtime benchmark PE grows from 222,208 to 222,720 bytes (+512 bytes);
its ELF remains 231,392 bytes because the added code/data fits existing file
alignment. General-control images retain their sizes (182,784-byte PE and
194,464-byte ELF). IEEE CRC adds 80 bytes of folding constants only when its
helper is emitted.

The full self-hosted compiler is now 56,744,960 bytes
for Windows and 56,758,992 bytes for Linux, roughly
0.3% larger than the release-1.2.21 full compiler images. This work prioritizes
runtime speed, not a smaller compiler executable or lower application heap use.

## Correctness and binary compatibility

All of the following passed on the final production source:

- Python unified suite: **178 passed, 0 failed, 0 skipped**.
- ML compiled core suite: **138 passed, 0 failed**, plus **232 unique runner
  checks** (CLI, ABI, negative cases, formatters, runtime and historical repros).
- Six native ISA tests on Windows and Linux: independent opcode bytes,
  exhaustive small lengths, multiple alignments, canaries, masked fallbacks,
  guarded page edges up to 128 KiB, randomized seeded/incremental CRC against
  Python zlib, and all 2,080 low/high set-bit combinations.
- Four native GC-codegen tests on Windows; three platform-independent checks
  on Linux, with one explicitly Windows-only execution check skipped there.
- Assembler opcode suite: 12 passing tests and one optional NASM comparison
  skipped because NASM is not installed; **239** shared golden opcode vectors.
- **30 executed byte-identical runtime images**, compared independently per
  target: three fixtures × Windows/Linux × Python / Windows-ML mono/MLO /
  Linux-ML mono/MLO.
- Concurrent-GC matrix: 44 primary image rows across three compiler hosts
  (132 executed images), 12 fallback images, 36 capacity-clamp images, and
  invalid-option/arity rejection tests. No fixture excluded. Concurrent GC
  remains Windows-only; Linux executes the existing fallback, not a newly
  enabled background collector.
- Six Windows/Linux compaction/packing fixture combinations pass: Python/ML
  and mono/MLO parity, packed execution, exact unpack restoration, malformed
  packed-input rejection and failure-path checks with UPX 5.2.1.
- Native-Linux executable-mode, case-sensitive import and project/cache
  regressions pass. Canonical Linux runtime blob remains 2,015 bytes,
  66 labels and three external relocations.
- MiniDoc strict generation: compiler 40 files / 3,368 symbols / 0 warnings;
  each standard library 53 files / 1,932 symbols / 0 warnings.
  All **53 std source files and 349 std documentation files are byte-identical**
  between repositories; the release check also includes the two hidden MiniDoc
  output markers (351 files total).

### Full-compiler fixed point

All six freshly generated compiler executables were compared by SHA-256:

| Target | Equal builds | Bytes | SHA-256 |
|---|---|---:|---|
| Windows x64 PE | Python; Windows ML Stage 2 (MLO); Stage 3 (mono) | 56744960 | `94a9d989a993d9e0bec2fead4301ee4f383cb9cec568424fa8d9eeffce61f35d` |
| Linux x64 ELF | Python; native Linux ML (mono); Windows ML cross-build (MLO) | 56758992 | `b91d1a0942943483027b872f222e397ce22531a52ef9c24f6d9a50da7bc0e2a4` |

Equality is **within each target**. Windows PE and Linux ELF are naturally
different file formats, not byte-identical to one another.

Local verified outputs are in `MiniLangCompilerML/build/isa-2026-10-20/`:
`windows-stage3.exe` and `linux-self`. Existing `build/mlc_win64.exe` and
`build/mlc_linux_x64` were deliberately not replaced: another project was
using the canonical compiler during this evaluation. The hashes above identify
the measured pre-version-bump builds, not the release packages. See the
[1.2.22 release verification](release-1.2.22-version-matrix.json) for the
separately rebuilt and tested release-stamped executables.

## CMOV and Base64: experimental evidence only

`benchmarks/evaluate_isa_candidates.py` in the Python repository emits isolated
native experiments, validates their results, and runs 15 alternating samples
on CPU 2.

- For a random integer minimum selection, CMOV was about 8.3–8.5× faster than
  a hard-to-predict branch **inside that microkernel**. For predictable data,
  WSL showed the branch at 0.211 ns/element and CMOV at 0.312 ns/element:
  indiscriminate if-conversion would regress that case.
  The Windows predictable result varied with layout/run conditions.
  A future compiler transformation needs a conservative profitability gate and
  must not eagerly evaluate expressions with side effects, errors or unsafe
  loads.
- The SSSE3 Base64 encoder prototype processes full 12-input/16-output-byte
  blocks approximately 4.4× faster than the prototype scalar loop.
  It checks random lengths against Python Base64 and uses guarded input pages.
  It **does not** implement the complete public API, allocation, padding,
  whitespace/error rules, decoding or MiniLang string conversion. It is not
  evidence that `std.encoding.base64` is 4.4× faster.

These are follow-up candidates, not hidden production changes.

## Reproduction entry points

From the Python repository:

```powershell
python tests/run_tests.py
python -m unittest discover -s tests -p test_isa_runtime.py
python mlc_win64.py benchmarks/isa_workloads.ml build/isa-after.exe -I .
python mlc_win64.py benchmarks/isa_workloads.ml build/isa-after-linux -I . --target linux-x64
python benchmarks/compare_isa_workloads.py <before.exe> build/isa-after.exe --runs 11 --cpu 2 --output build/isa-workloads.json
python benchmarks/compare_runtime_codegen.py <control-before.exe> <control-after.exe> --runs 21 --cpu 2 --cases division local-register dynamic-index concat-control repeat integer-format-small --output build/isa-controls.json
python benchmarks/compare_isa_helpers.py <saved-before-helper-image.json> --rounds 9 --cpu 2 --output build/isa-helpers.json
python benchmarks/evaluate_isa_candidates.py --output build/isa-candidates.json
```

Save a helper image with `tests/native_runtime_harness.py` before changing the
emitter, or reproduce it from the recorded baseline revision. Build both
sides from the same benchmark sources/options. Run ELF measurements inside
Linux/WSL, not through a Windows process-start timer. See each runner's
`--help` for affinity and case selection.

From the ML repository, verification entry points are
`scripts/run_tests.ps1 -Compiler <verified-compiler.exe>`,
`tests/check_isa_runtime_parity.py`, `tests/check_concurrent_gc.py`,
`tests/check_compaction_packing.py`, and
`scripts/run_native_linux_regressions.sh`. The JSON records the exact image
hashes; generated build artifacts themselves remain outside Git.

## ISA references and redistribution notice

Instruction semantics/capability checks follow the
[Intel Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
and [architecture extensions reference](https://cdrdv2-public.intel.com/774990/architecture-instruction-set-extensions-programming-reference.pdf).
CRC folding/reduction adapts
[Intel ISA-L's reflected CRC32 implementation](https://github.com/intel/isa-l/blob/master/crc/crc32_gzip_refl_by8.asm)
and [constants](https://github.com/intel/isa-l/blob/master/crc/crc_const.asm).
The Base64 prototype follows the vector-repacking approach described in
[Faster Base64 Encoding and Decoding Using AVX2 Instructions](https://arxiv.org/abs/1704.00605).

Distributors of generated programs using the accelerated IEEE CRC32 helper
must carry the [third-party notice](../../THIRD_PARTY_NOTICES.md). There is no
new external runtime-library dependency. The 1.2.22 ML binary packages include
the notice automatically.
