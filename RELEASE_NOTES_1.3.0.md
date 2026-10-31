# MiniLang Compiler 1.3.0

Both the Python reference compiler and the self-hosted MiniLang compiler report
**1.3.0** through `--version` and compile-time `MINILANG_VERSION`.

## Changes since 1.2.26

- Add typed inline x64 assembly with `in`, `inout`, typed scratch operands and
  typed results. Local labels and forward or backward branches support loops;
  backward branches include cooperative GC polls. The compiler checks jump
  targets and result initialization on every reachable exit.
- Add explicit `asm unsafe x64` byte and little-endian 32-bit reads and writes
  for `bytes` operands. Callers must check bounds before entering these blocks.
  See [the inline assembly guide](docs/INLINE_ASM.md).
- Use inline assembly in standard-library byte XOR, LZ4 matching and hashing,
  and selected self-hosted parser, AST and assembler paths.
- Keep measured standard-library improvements in Base64 decoding, RLE and LZ4
  encoding, stack and list bulk copies, sorting, string operations, quoting,
  constant-time comparison, time fields and native math. Both repositories have
  identical standard-library sources.

## Measured effects

The [standard-library performance report](docs/reports/STDLIB_PERFORMANCE_2026-10-31.md)
contains paired Windows measurements and Linux checks. Representative isolated
workloads improved from roughly 500–547 ms to 265–282 ms for decoding 20 MiB
of Base64 input, 766–828 ms to 47–62 ms for 100 MiB repeated-byte RLE
encoding, and 203–250 ms to 15–32 ms for large list front shifts. These are
workload measurements, not whole-application speedup claims. Variants without a
repeatable gain were removed.

## Validation and distribution

The release checks cover typed inline-assembly runtime and rejection fixtures,
standard-library and compression behavior, and Windows and Linux compiler
builds. The Python release remains source-only. The self-hosted release includes
Windows x64 ZIP and Linux x64 tar.gz packages with SHA-256 sidecars and a
[version matrix](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.3.0/docs/reports/release-1.3.0-version-matrix.json).
