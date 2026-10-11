# MiniLang Compiler 1.2.20

This patch release fixes growing and fragmented heaps with optional Windows
concurrent GC and restores exact Python/self-hosted output parity for Hollowkeep.
Both CLI flags (`--version`, `-version`) and compile-time `MINILANG_VERSION`
report **1.2.20**. Windows x64 and Linux x64 remain supported targets.

## Concurrent heap reuse

- Old free ranges remain available to the allocator while background marking
  runs. An immutable exclusion bitmap protects new below-frontier allocations
  from the current snapshot.
- Sixty-four size classes preserve large contiguous buffer holes. Thread-local
  allocation buffers can refill from existing 4–64 KiB ranges instead of
  repeatedly splitting large free blocks.
- Compact-bitmap coalescing, publication under the heap monitor and actual
  refill-capacity accounting reduce fragmentation without moving live objects.
- Diagnostics cover every bin, 64-bit sizes and more than 200,000 free blocks.
  Invalid pointers and cycles fail safely. SATB barriers, weak Thread records
  and the conservative metadata-allocation-failure fallback remain intact.

These allocator changes affect optional Windows `--gc-concurrent`, not the
default Windows or Linux collector. Concurrent GC is still not supported for
Linux targets and cannot be combined with `--heap-shrink`. It does not compact
objects or return committed managed pages to the OS. The exclusion bitmap
adds approximately 1.56% of the used frontier, plus retained capacity/rounding;
bin heads add another 512 bytes.

## Compiler correctness and parity

- Resolve method `global` declarations against the correct root/package scope.
  Python also matches ML for implicit module-global member writes and qualified
  `is` type checks.
- Count actual AST nodes consistently in the bounded unroll budget, including
  nested same-kind expressions, coalescing children and call callees.
- Resolve value-flow facts in each function's own file and namespace, and align
  integer `div` facts. Do not infer original return contracts or inline original
  bodies when callable globals can be rebound; respect local/captured shadows.
- Pass the selected Windows PE subsystem through Python runtime generation.
  GUI `input()` returns an empty string without console-read code, matching ML.
  Ordinary console input is unchanged.

No language feature is removed. New shared regressions cover these cases in
both compilers and both pipeline modes.

## Measurements

The [allocator evaluation](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.20/docs/reports/CONCURRENT_GC_FRAGMENTATION_2026-10-11.md)
records ten-minute Hollowkeep runs where warm committed-heap growth falls from
176 MiB with the earlier reuse-only fix to **0 MiB** with size classes and partial
TLABs. The isolated five-pair allocation benchmark has modest median slowdowns
of 0.57% and 1.15%, not a throughput improvement.

The later [full-game and native-memory investigation](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.20/docs/reports/HOLLOWKEEP_PARITY_AND_NATIVE_MEMORY_2026-10-11.md)
confirms byte-identical game builds. Its final ten-minute run passes all 13
gameplay/save checks with constant managed commitment at 1,194.75 MiB. Private
process memory changes by -7.41 MiB at endpoints and -0.41 MiB between warm
60-second window medians.

Earlier approximately 22 MiB private-memory increases were separate from
managed commitment. Native graphics reservations repeatedly commit and release
memory; no renderer or driver fix is claimed here. These observations are not
a guarantee of leak-free behavior for every workload or duration. The version
bump is not a new isolated performance experiment.

## Release validation

- Python suite: **175 passed, 0 failed, 0 skipped**.
- ML suite: **136 core tests** and all outer integration checks passed.
- Four native emitted-GC-helper tests and five unroll-model tests passed.
- Windows Python bootstrap, native object-pipeline stage 2 and monolithic
  stage 3 are byte-identical. Python Linux output, Linux-native monolithic
  selfbuild and Windows ML object-pipeline crossbuild are byte-identical.
- Both CLI version flags, compile-time version and runtime checks pass on
  Python, Windows ML and Linux ML. Twelve version images have six-way
  per-target byte parity.
- The complete concurrent matrix covers **180 images**: 132 concurrent images,
  12 synchronous fallback images and 36 SATB-capacity images, without exclusions.
- The context/global/unroll/GUI matrix covers **60 images**, with per-target
  byte equality across all three compiler hosts and both pipeline flags.
- The additional default-memory matrix passes **192 of 228 planned images**.
  It is explicitly **partial**: Windows Defender quarantined a generated
  `memory_policy.ml` image in both full-run attempts
  (`Trojan:Win32/Wacatac.C!ml`). The remaining run excludes this fixture's
  36 cross-host/target/pipeline combinations. Antivirus settings and quarantine
  were not changed. This limitation does not affect the passing regular suites
  or the complete concurrent/context matrices.
- Heap-size, listing, bitmap and FFI CLI contracts pass on all three hosts.
- All **53 std modules** and **351 std reference files** match between repos.
  MiniDoc regenerates **3,321 compiler symbols in 38 files with zero warnings**.
- Fresh release-stamped compilers generate the same **86,633,472-byte**
  Hollowkeep image, also identical to the previously validated ten-minute image:
  `C0EC23FB3780655405B7AC9FFB85813395CE0CE5C30EC4C534E49C83C0200499`.

Python accepts the object-pipeline flag but emits its monolithic equivalent;
ML exercises distinct pipelines. Exact equality is checked within each target
and configuration; Windows PE and Linux ELF are not expected to equal each
other. Selected regressions cannot prove equality for every possible program.

Evidence: [version and self-host manifest](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.20/docs/reports/release-1.2.20-version-matrix.json),
[partial memory matrix](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.20/docs/reports/release-1.2.20-memory-parity.json),
[concurrent matrix](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.20/docs/reports/release-1.2.20-concurrent-parity.json),
[context matrix](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.20/docs/reports/release-1.2.20-codegen-parity.json)
and [Hollowkeep image comparison](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.20/docs/reports/release-1.2.20-hollowkeep-parity.json).
Earlier development reports keep their original versions and hashes.

## Compiler checksums

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows `mlc.exe` | 57,280,512 | `3AE28058916B6931DD4B13AF49A3306E3EEC7166128FDD7EAD7AE60FDEAD6426` |
| Linux `mlc` | 57,278,800 | `D458F61655B085566FF658B0CB1A9B17C5A404A38919E36A1A48927B11B78CD9` |

These hashes identify the native compilers, not the compressed archives.
Archive checksums are supplied as separate `.sha256` downloads.

## Downloads

This repository publishes the Python compiler as a source release. Run
`python mlc_win64.py --version` to verify the version. Matching ready-to-run
[Windows and Linux native compiler packages](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.20)
are published by MiniLangCompilerML; those packages do not require Python.
