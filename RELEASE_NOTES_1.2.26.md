# MiniLang Compiler 1.2.26

This release updates both the Python reference compiler and the self-hosted
MiniLang compiler. `--version` and compile-time `MINILANG_VERSION` report
**1.2.26**.

## Changes

- Unchanged incremental builds can reuse a checked declaration fingerprint.
  Cache keys include compiler identity, options and every parsed source;
  damaged records are recomputed.
- Suitable `0..len(array)-1` loops now use a guarded nonempty fast path with
  fewer index bounds checks. Empty arrays retain the checked descending path.
- The self-hosted MLO serializer copies page spans with native `memmove`.
- Standard-library hot paths in arrays, paths, sorting, encoding, compression
  and concurrency include the changes made after 1.2.25.

## Measured effects

On Windows x64, the declaration cache reduced warm build time by 3.2% in
Python and 4.7% in MiniLang on a 1,000-function fixture. The smaller `mlfmt`
fixture showed no cache gain. Generated dynamic-array loops ran about 1%
faster in paired measurements, with no material peak-memory change and about
1–1.5 KiB more executable code. The isolated MLO copy shortened its measured
serialization phase slightly but did not improve the full self-build time.
The full new compiler's warm self-build was about 4.9% slower in this test.
See the [evaluation](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.26/docs/reports/COMPILER_OPTIMIZATION_EXPERIMENTS_2026-10-30.md)
for methods, samples and limits.

## Validation and distribution

The Python and self-hosted compilers produce byte-identical Windows and Linux
x64 outputs in the release checks. Changed-build, corruption and output-parity
checks cover three backends on both targets. The
[version matrix](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.26/docs/reports/release-1.2.26-version-matrix.json)
records the release compiler and fixture hashes.

The Python repository remains source-only. Windows ZIP and Linux tar.gz
packages of the self-hosted compiler, each with a SHA-256 sidecar, are attached
to the [self-hosted release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.26).
