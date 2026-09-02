# MiniLang Compiler 1.2.1

MiniLang 1.2.1 is a source-only maintenance release of the matching Python
reference and self-hosted compilers. Generated executables remain excluded from
Git and from GitHub release assets; the native compilers are rebuilt and
verified from the tagged sources.

Highlights:

- explicit `///` declaration comments in both compiler frontends, kept outside
  the runtime AST and generated program;
- complete English declaration documentation for the shared standard library
  and the self-hosted compiler implementation;
- strict MiniDoc configurations and committed HTML and GitHub-compatible
  Markdown API references;
- the synchronization, native timeout, Linux FFI, socket, project-cache,
  assembler, GC and thread-lifecycle hardening accumulated since 1.2.0; and
- unchanged Windows x64 PE32+ and Linux x64 ELF64 target compatibility between
  the Python and self-hosted compilers.

The acceptance build verifies both compiler suites, strict warning-free MiniDoc
generation, byte-identical shared standard-library sources and documentation,
Windows fixed-point self-hosting, and a native Linux MiniDoc build and test run.
Exact release hashes are recorded in
`COMPILER_PARITY.md`.

Build the compiler from source by following the repository README. See
`CHANGELOG.md` and `COMPILER_PARITY.md` for the detailed feature, performance
and verification record.
