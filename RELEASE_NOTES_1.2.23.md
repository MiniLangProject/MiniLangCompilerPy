# MiniLang Compiler 1.2.23

This patch release restores Python/native output parity for dynamic ordered
comparisons and fixes a Python compilation failure involving unused functions
and concurrent GC. Windows x64 PE and Linux x64 ELF remain supported.
Both version flags (`-version`, `--version`) and compile-time
`MINILANG_VERSION` report **1.2.23**.

## Fixes

- In the self-hosted compiler, let the last non-numeric error block for
  dynamic `<`, `>`, `<=` and `>=` fall through to its join. A redundant
  jump previously displaced the earlier void-error skip as the assembler's
  forward-relaxation candidate. Inside `try(...)`, native output could keep
  a five-byte jump where Python emitted a two-byte jump.
- Preserve Python assembler spill hooks while lowering unused functions for
  diagnostics. Concurrent-GC member writes in discarded code no longer fail
  compilation. Keep runtime-helper reachability isolated from retained code:
  calls in discarded bodies must not add runtime helpers to the final image.
  This also fixes CRC/concurrent-GC fixture byte differences introduced by
  the earlier Python-only hook fix. The fixture and three-host checks are
  mirrored, with an additional six-configuration Python code-shape regression.
- Add ordered-comparison runtime/error checks, generated-code shape checks
  and assembler relocation/boundary coverage. No language feature is removed;
  ordered-comparison error semantics and the bounded relaxation algorithm
  remain unchanged.

The MiniSQL backup executable is rebuilt through Python, native monolithic
and native MLO paths. All three outputs are byte-identical and pass
`--version` and `--m0-self-test`, with MiniSQL source fingerprints checked
before and after. No MiniSQL workaround or database change is included.

## Release validation

- Python suite: **179 passed, 0 failed, 0 skipped**.
- ML suite: **138 core tests and 237 outer checks passed**.
- Ordered-comparison fixture: **320 assertions per execution**;
  **15 executed images** agree per target/configuration across Python,
  Windows-native and Linux-native hosts, including Windows concurrent GC.
- All 12 suppressed error joins use short branches. Assembler coverage
  includes adjacent joins, 29/126/127/128-byte spans, relocation rebasing
  and a 64-KiB boundary: **239 shared opcode vectors**, **13 passing tests**
  and one optional external NASM comparison skipped.
- Six complete compiler builds reach identical Windows and Linux fixed
  points: Python bootstrap, native mono/MLO and cross-host builds.
  Twelve additional version/runtime images have six-way byte parity per target.
- Thirty ISA runtime images pass. Native ISA tests pass on Windows and Linux;
  native GC tests pass (four on Windows, three on Linux, one Windows-only skip).
- Concurrent-GC verification covers **46 primary rows across three hosts**
  (138 executed images), plus 12 fallback and 36 capacity-clamp images.
  No fixture is excluded.
- Nine packing configurations pass, with reference/mono/MLO parity, packed
  execution and byte-exact restoration. Both packed full compilers start
  and compile successfully.
- Native Linux permissions, case-sensitive import and project-cache checks
  pass; the canonical Linux runtime blob is verified.
- All **53 std modules** and **351 std reference files** remain byte-identical.
  Strict MiniDoc compiler generation reports **40 files / 3,368 symbols**
  for Windows and **41 files / 3,370 symbols** for Linux, with zero warnings.

See the [release-stamped verification manifest](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.23/docs/reports/release-1.2.23-version-matrix.json)
and [root-cause analysis](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.23/COMPILER_PARITY.md).
The earlier ordered-comparison report records the pre-version-bump checkpoint;
the release manifest records the rebuilt 1.2.23 artifacts.
Equality is per target/configuration, not between PE and ELF. Tests cannot
prove equivalence for every possible program.

No new application-throughput or full-game performance claim is made for
this patch. Build durations recorded during parallel qualification are not
performance benchmarks. The 1.2.22 runtime optimizations remain included;
their earlier measurements are not relabeled as fresh release measurements.

## Downloads and executable checksums

The Python repository remains **source-only**. Ready-to-run Windows and Linux
packages are published in the
[ML compiler release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.23).
They include the matching standard library, native-media bridge, examples,
licenses/notices, release documentation and a tagged source-revision manifest.
Each archive has a SHA-256 sidecar. These hashes identify the unpacked compilers:

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows `mlc.exe` | 56,742,912 | `8B99430A8262EDB60CCBC9D8FAC322F444D5EBA0AAC5A7965A656852E019F3EF` |
| Linux `mlc` | 56,758,992 | `F61488A7B453571C48DDA6FCB5A451AE89D443ACBADF105990866DEBE5E9AE53` |

Published compilers are **unpacked**. Optional `--pack`, `--pack-exe` and
`--unpack-exe` use an explicit trusted UPX 5.2.1 executable; UPX is not bundled.
See the [packing guide](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.23/docs/EXECUTABLE_PACKING.md)
for startup/memory trade-offs and signing constraints.
The accelerated IEEE CRC32 helper includes Intel ISA-L-derived code;
include [THIRD_PARTY_NOTICES.md](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.23/THIRD_PARTY_NOTICES.md)
when distributing generated programs using it.
