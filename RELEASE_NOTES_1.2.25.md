# MiniLang Compiler 1.2.25

This release adds five compiler optimizations to the Python reference compiler
and the self-hosted MiniLang compiler. Both `--version` and compile-time
`MINILANG_VERSION` report **1.2.25**.

## Optimizations

- **Profile-guided inlining:** compile a training program with
  `--profile-calls`, capture its `[call-profile]` lines from `callStats()`, then
  pass that file with `--pgo-profile FILE`. Hot callees receive more inline
  budget; cold callees receive less. Profiling includes inlined calls.
- **String concatenation:** three pure, left-associated string parts use one
  allocation and one copy per part. Dynamic or mixed-type cases retain their
  original behavior.
- **Local value numbering:** a short straight-line region can reuse equal
  integer expressions when their inputs have not changed.
- **Incremental lexer cache:** persistent, checked token records avoid
  lexing compatible sources again. Corrupt records become cache misses.
- **Byte loops:** suitable `0..len(buffer)-1` loops use a checked entry and a
  faster nonempty-buffer path. The empty-buffer behavior remains unchanged.

## Measured effects

On Windows, nine paired, CPU-pinned compilations of `tools/mlfmt.ml` gave
these median times (before to after): native 1.183 to 1.186 seconds without
cache and 0.582 to 0.537 seconds with a warm cache; Python 1.860 to 1.746
seconds without cache and 0.720 to 0.697 seconds with a warm cache. Warm
native peak working set fell from 128.6 to 125.2 MiB; Python's was essentially
unchanged.

In 11-run paired runtime fixtures, three-part concatenation ran about 55%
faster and reduced measured heap growth from 8.39 to 4.80 MB. Repeated local
integer expressions ran about 26% faster, and indexed byte loops about 9%
faster, with essentially unchanged memory in those two cases. Optional PGO
improved a long hot-call fixture by about 0.9% in 15 paired runs while
increasing that program by 15.5 KiB. These are fixture-specific measurements,
not general speedup guarantees. See the [evaluation](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.25/docs/reports/COMPILER_OPTIMIZATIONS_2026-10-30.md)
for methodology and memory measurements.

## Validation and distribution

The Python and self-hosted compilers produce byte-identical Windows compiler
binaries at the fixed point. Python cross-compilation and Linux self-hosting
also produce byte-identical Linux compiler binaries. The integration gate checks semantics, Python and
native monolithic/MLO output parity, cold/warm cache output, corrupt lexer
cache fallback, call profiles and PGO. Windows and Linux x64 remain supported.
Cross-host Linux fixtures, including PGO output, have byte parity and run on
Ubuntu 24.04. The [version matrix](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.25/docs/reports/release-1.2.25-version-matrix.json)
records compiler and fixture hashes.

The release-stamped Python suite passed 179 tests with no failures or skips;
the native ML harness passed 138 tests with no failures; and the incremental
regression gate passed 96 compilation checks across three backends.

The Python repository is source-only. Ready-to-run Windows and Linux compiler
packages, each with a SHA-256 sidecar, are published with the
[self-hosted compiler release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.25).
