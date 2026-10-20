# MiniLang Compiler 1.2.22

This release improves native memory-transfer helpers, IEEE CRC32 and concurrent
GC bit scans in both compilers. Windows x64 PE and Linux x64 ELF remain supported.
Both CLI version flags (`-version`, `--version`) and compile-time
`MINILANG_VERSION` report **1.2.22**.

## Runtime improvements

- Use baseline-x64 64-bit `BSF`/`BSR` in the Windows concurrent collector's
  free bins and reuse/coalescing bitmaps, replacing split 32-bit scans.
- Use bounded scalar/SSE2 operations for small copies, an unrolled AVX copy
  loop and ERMS `REP MOVSB` for copies of at least 64 KiB. Retain the original
  fallback when the vector path is unavailable and preserve the non-overlap
  contract of internal copy helpers.
- Use SIMD fills through 256 bytes and a direct `REP STOSB` path for larger
  fills. Thresholds reflect repeated workload measurements, not CPU flags alone.
- Expose ERMS and FSRM through `std.cpu` without changing existing feature
  bits. Feature selection happens on the machine running the generated program,
  not the machine compiling it.
- Accelerate reflected IEEE CRC32 with runtime-gated PCLMULQDQ folding from
  64 bytes. Preserve seeded/incremental results, small-input/table fallbacks
  and the separate CRC32C implementation.

CMOV selection and SIMD Base64 were evaluated as isolated prototypes only;
neither is enabled in this release. No language feature is removed. Background
GC remains an opt-in Windows feature; Linux retains the existing fallback.

The IEEE CRC32 folding code derives from Intel ISA-L. Distributors of generated
programs using it must include
[THIRD_PARTY_NOTICES.md](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.22/THIRD_PARTY_NOTICES.md).
The native compiler packages include this notice. No extra native library is
required to use the accelerated helper.

## Measurements

The [Windows/Linux evaluation](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.22/docs/reports/ISA_RUNTIME_2026-10-20.md)
and raw samples describe the **pre-version-bump checkpoint** of these changes,
not freshly timed release packages:

- IEEE CRC32 is approximately **13.3x faster** in the measured workload.
- Allocation-inclusive small copies take **29-31% less time**; small fills
  take **15-21% less time**.
- Large allocation-inclusive copies/fills, general-code controls and measured
  memory usage are essentially unchanged. The GC control shows no meaningful
  speed change and no heap-growth regression.

These are workload-specific results on a Ryzen 9 9900X, not a guarantee that
every MiniLang program becomes faster. Linux runs use WSL2, not bare-metal
Linux. No new full-game Hollowkeep/MiniQuake or MiniSQL benchmark is claimed.

## Release validation

- Python suite: **178 passed, 0 failed, 0 skipped**.
- ML suite: **138 core tests and 232 outer checks passed**.
- Six native ISA tests pass on both Windows and Linux, including guard pages,
  exhaustive small lengths/alignment, masked fallbacks and randomized seeded
  CRC comparisons. Native GC tests pass (four on Windows, three on Linux plus
  one explicitly Windows-only skip).
- Assembler validation: **239 shared golden opcode vectors**, 12 passing
  tests and one optional external NASM comparison skipped.
- Full Windows Python bootstrap, native MLO stage 2 and monolithic stage 3
  match byte-for-byte. Python Linux output, Windows ML MLO crossbuild and
  Linux-native monolithic selfbuild likewise match.
- Both version flags pass on all three hosts. Twelve version/runtime images
  have six-way byte equality within each target. Thirty additional ISA runtime
  fixture images execute successfully and match within their configurations.
- Concurrent-GC verification covers 44 primary rows across three compiler
  hosts (132 executed images), 12 fallback and 36 capacity-clamp images;
  no fixture is excluded.
- Nine Windows/Linux compaction/packing configurations pass, including
  reference/mono/MLO equality, packed execution and byte-exact restoration.
  Both full compilers also start and compile successfully when packed.
- Native Linux permissions, case-sensitive imports and project-cache
  regressions pass; the canonical Linux runtime blob remains verified.
- All **53 std modules** and **351 std reference files** (349 documents/assets
  plus two MiniDoc output markers) are identical between the repositories.
- Strict MiniDoc compiler generation has **40 files / 3,368 symbols** on
  Windows and **41 files / 3,370 symbols** on Linux, with **zero warnings**.

See the [release-stamped verification manifest](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.22/docs/reports/release-1.2.22-version-matrix.json).
Equality is per target/configuration, not between Windows PE and Linux ELF.
Tests cannot prove equivalence for every possible program.

## Downloads and executable checksums

The Python repository remains **source-only**. Ready-to-run native packages
are available from the
[ML compiler release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.22).
They contain the matching standard library, native-media bridge, examples,
licenses/notices, release documentation and a source-revision manifest.
Each archive has a SHA-256 sidecar; the table identifies the unpacked executable
inside it.

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows `mlc.exe` | 56,744,960 | `830D54239616CD5EC4975413492981FFCD6688E53A5341EA45075DB07D5D79FE` |
| Linux `mlc` | 56,758,992 | `FDBCD5BAA4AEF7C36EDD602E1AA35EEFD3587DFBC7193EAEC444A74D629DC7E1` |

The distributed compilers remain **unpacked**. Optional `--pack`, `--pack-exe`
and `--unpack-exe` workflows still use an explicit trusted UPX 5.2.1 executable;
UPX is not bundled. Packing reduces disk size but can increase startup time
and peak memory. See the
[packing guide](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.22/docs/EXECUTABLE_PACKING.md).
