# MiniLang Compiler 1.1.0

MiniLang 1.1.0 is a source-only release of the matching Python reference and
self-hosted compilers. No generated executable is tracked or attached.

Highlights:

- native Windows and Linux x64 output with matching threads, synchronization,
  managed heap/GC and thread-safe collections;
- fine-grained `synchronized(lock)`, futures/tasks, cooperative cancellation
  and bounded multi-producer/multi-consumer channels;
- a process-wide managed heap with per-thread stacks and cooperative GC;
- `defer`, expanded FFI support and incremental project builds;
- typed conditional compilation with source options, CLI/project overrides and
  nested target-dependent branches;
- deterministic PE32+/ELF64 images and Linux `.so` FFI through the System V ABI;
- native Linux self-hosting and byte-identical monolithic/`.mlo` ELF linking;
- hardened self-hosted array stacks and Linux project/path normalization with
  a project-manifest bootstrap smoke test;
- shadow-safe qualified enum resolution with identical language-suite output;
- a cross-platform standard library for files, sockets, time, synchronization,
  shared values and cryptography, using Windows CNG or Linux OpenSSL 3;
- portable platform/path/process/console services, durable random-access files,
  UUID v4, PBKDF2, configurable sockets and a provider-neutral TLS contract;
- CPU-dispatched checksums and native byte search;
- faster generated code and a bounded, substantially faster self-hosted object
  pipeline; and
- byte-identical target output across Python, self-hosted monolithic and `.mlo`
  builds, backed by fixed-point, standard-library and MiniQuake acceptance tests.

Build the compiler from source by following the repository README. See
`CHANGELOG.md` and `COMPILER_PARITY.md` for the detailed feature and verification
record.
