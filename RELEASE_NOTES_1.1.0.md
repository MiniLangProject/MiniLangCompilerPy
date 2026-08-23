# MiniLang Compiler 1.1.0

MiniLang 1.1.0 is a source-only release of the matching Python reference and
self-hosted compilers. No generated executable is tracked or attached.

Highlights:

- native Windows threads, synchronization and thread-safe collections;
- a process-wide managed heap with per-thread stacks and cooperative GC;
- `defer`, expanded FFI support and incremental project builds;
- CPU-dispatched checksums, native byte search and Windows CNG cryptography;
- faster generated code and a bounded, substantially faster self-hosted object
  pipeline; and
- byte-identical target output across Python, self-hosted monolithic and `.mlo`
  builds, backed by fixed-point, standard-library and MiniQuake acceptance tests.

Build the compiler from source by following the repository README. See
`CHANGELOG.md` and `COMPILER_PARITY.md` for the detailed feature and verification
record.
