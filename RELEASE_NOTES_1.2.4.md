# MiniLang Compiler 1.2.4

MiniLang 1.2.4 adds statically resolved user-defined operators to the matching
Python reference and self-hosted compilers while retaining byte-identical
Windows x64 PE and Linux x64 ELF output across compiler implementations.

Highlights:

- struct-owned overloads for arithmetic, comparison, bitwise and unary
  operators, with exact operand-type resolution, overload sets and optional
  inlining;
- compound variable assignments and unary numeric `+`, with deterministic
  diagnostics for invalid, missing or ambiguous overloads;
- an updated cross-platform formatter covering the complete modern language
  syntax;
- the cross-platform `std.test` unit-test framework and self-hosted `mltest`
  declaration-tag discovery runner; and
- expanded positive, negative, formatting, Windows, Linux and object-pipeline
  regression coverage plus refreshed MiniDoc references.

This remains a source-only release. Generated executables are excluded from Git
and GitHub release assets and are reproducibly built from the tagged sources.
See `README.md`, `CHANGELOG.md` and `COMPILER_PARITY.md` for syntax, build and
verification details.
