# MiniLang Compiler 1.3.3

This release improves generated application code and reduces temporary work
inside both compiler implementations. Recompile applications to benefit;
previously compiled executables keep their existing behavior. No new language
syntax or optimization flag is required.

## Generated application code

- Fuse eligible string-concatenation chains of three to eight pure operands
  into one result allocation. Checked fallbacks preserve evaluation order,
  mixed-value behavior, error propagation and GC roots.
- Keep the fields of proven nonescaping local structs in rooted stack slots,
  including structs whose fields have checked type annotations. Constructor
  type checks, optional fields and source error context are preserved.
  Aliases, escapes and unsupported uses retain ordinary object allocation.
- Fuse direct decode(slice(bytes, offset, length)) calls into one string
  allocation, retaining strict bounds and argument order. This also avoids
  the temporary byte copy in partial StringBuilder buffers.

On an AMD Ryzen 9 9900X, the eight-string benchmark used 73% less execution
time on Windows and 72% less under Linux/WSL, with 76% less managed heap growth.
The typed-local-struct case used 32% and 41% less execution time respectively
and eliminated 16 MB of heap objects in its bounded workload. These are
specific microbenchmarks, not predictions of whole-game or server speedups.
Fusion can increase generated instruction size slightly.

## Compiler internals

- Emit ordinary/indexed memory operands directly instead of constructing
  temporary encoding records and short byte arrays.
- Avoid optional assembly-listing interception on normal Python builds and
  use fixed-schema Python token records.
- Start native AST arenas smaller and serialize MLO code/data sections without
  duplicating them into paged buffers.
- Write normalized MLO patch fields through known offsets and use one x64
  store for four-byte metadata values contained within a page. Boundary
  fallbacks and the MLO version 2 layout are preserved.

Compact-relocation prototypes were measured and rejected because their build
time or memory tradeoff was unfavorable. Full native self-build timing varies
too much to claim a reproducible overall speedup from the follow-up changes.

## Validation and compatibility

Both CLI flags, -version and --version, and the compile-time MINILANG_VERSION
constant report 1.3.3. Release qualification rebuilds the compiler through
Python bootstrap, native self-hosting and cross-target compilation, checking
byte equality separately for Windows x64 and Linux x64. The 53 standard
library sources are byte-identical between repositories.

See the [release verification matrix](docs/reports/release-1.3.3-version-matrix.json)
for version-stamped compiler hashes and release checks. Detailed baseline,
performance, regression and parity evidence is recorded in the
[4 November evaluation](docs/reports/COMPILER_OPTIMIZATIONS_2026-11-04.md) and
[6 November evaluation](docs/reports/COMPILER_OPTIMIZATIONS_2026-11-06.md).
Their development artifact hashes remain historical; use the release matrix
and package manifests for 1.3.3 downloads.

## Distribution

This Python reference release provides source and requires Python 3.11 or
newer. A source ZIP with a SHA-256 sidecar is attached to the release.
Ready-to-run Windows x64 ZIP and Linux x64 tar.gz packages are in the
[self-hosted release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.3.3).
