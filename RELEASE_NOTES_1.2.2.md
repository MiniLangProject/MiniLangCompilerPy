# MiniLang Compiler 1.2.2

MiniLang 1.2.2 is a source-only performance and reliability release of the
matching Python reference and self-hosted compilers. Generated executables
remain excluded from Git and from GitHub release assets; native compilers are
rebuilt and verified from the tagged sources.

Highlights:

- a MiniDoc-guided self-host optimization that removes redundant lexical-frame
  scans and reuses stable package-suffix resolution across binding generations;
- approximately 43-45% lower full self-host compilation time in the recorded
  same-window profile and production comparisons, with neutral peak memory;
- dedicated regressions for authoritative scope indexes, suffix-cache
  invalidation, ambiguous names and lexical shadowing;
- a reproducible compiler call-profile harness and refreshed strict MiniDoc
  implementation documentation; and
- a hardened cross-platform networking test that avoids Windows dynamic-port
  reservation ranges.

Python and self-hosted compilers retain byte-identical Windows x64 PE32+ and
Linux x64 ELF64 target output. The release acceptance record, exact compiler
hashes and test totals are documented in `COMPILER_PARITY.md`.

Build the compiler from source by following the repository README. See
`CHANGELOG.md` and `COMPILER_PARITY.md` for the detailed verification record.
