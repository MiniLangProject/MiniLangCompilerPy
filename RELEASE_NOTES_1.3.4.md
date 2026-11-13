# MiniLang Compiler 1.3.4

This release restores byte-identical output from the Python and self-hosted
compilers for loops whose indexed accesses appear inside else-if conditions
or switch case expressions. Runtime results already agreed for the reproduced
failures; the compiler implementations had selected different loop versions.
The native analysis now includes case values and both range bounds.

## Optimization and regression coverage

Dynamic loops with a single indexed use keep their checked body. Multiple
uses can select guarded fast/slow versions; empty inputs keep the existing
inclusive descending-loop semantics and bounds errors. Rebinding a container
disables hoisting. The native analysis stores a counter per container instead
of copying a per-access array. Native register lookup uses length-based
dispatch with the same supported spellings and encodings.

Both suites cover conditional array/byte reads, nested branches, switch range
bounds, empty inputs and container replacement. Release qualification checks
Python bootstrap, native self-hosting, both targets, both object pipelines,
incremental-cache behavior, and OOP byte parity. The standard-library sources
and generated standard-library documentation match between repositories.

See the [release verification matrix](docs/reports/release-1.3.4-version-matrix.json)
for exact executable hashes and test evidence, and the
[before/after evaluation](docs/reports/LOOP_PARITY_2026-11-13.md) for measurements.
The older November reports describe their own development artifacts; those
hashes are not the 1.3.4 release checksums.

Both -version and --version and the compile-time MINILANG_VERSION constant
report 1.3.4. Recompile applications to use the corrected optimization.
There is no language syntax change.

## Distribution

The [native release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.3.4)
provides Windows x64 ZIP and Linux x64 tar.gz packages, each with a
SHA-256 sidecar, matching std library, native media bridge, build manifest
and documentation. The
[Python release](https://github.com/MiniLangProject/MiniLangCompilerPy/releases/tag/v1.3.4)
provides source for Python 3.11 or newer.
