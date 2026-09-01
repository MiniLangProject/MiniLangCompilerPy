# MiniLang Compiler 1.2.0

MiniLang 1.2.0 is a source-only release of the matching Python reference and
self-hosted compilers. Generated executables remain excluded from Git and from
GitHub release assets; both native compiler targets are rebuilt and verified
from the tagged sources.

Highlights:

- native Windows x64 PE32+ and Linux x64 ELF64 output, including native Linux
  self-hosting and byte-identical monolithic/`.mlo` linking;
- matching cross-platform standard-library support for files, sockets, TLS,
  cryptography, processes, consoles, durable random-access files and system
  services;
- gradual runtime type contracts, optional values, expression lambdas,
  default/named/variadic calls, value/range `match`, pull iterators, `yield`
  and structural interfaces;
- tasks, futures, cancellation, bounded channels, `async`/`await`/`select`,
  fine-grained synchronized blocks and a shared thread-safe managed heap with
  thread-local allocation buffers;
- typed conditional compilation for portable Windows/Linux source trees;
- substantially lower self-hosted compiler time and memory use through compact
  token/AST storage, phase-local graph release, reused analysis state, native
  bulk copies and streamed canonical object linking; and
- hardened GC safepoints and conservative interior-pointer scans, Linux
  pthread behavior, project/cache boundaries and assembler reuse after
  materialization; and
- post-release audit hardening for atomic thread startup, concurrent joins,
  native-handle ownership across `Join`/`Close`/GC, and exact Linux FFI symbol
  resolution.

The 1.2.0 acceptance build verifies the version CLI, the complete Windows and
Linux language/runtime suites, fixed-point self-hosting and byte-identical
representative output between the Python, self-hosted monolithic and `.mlo`
paths. Exact release hashes are recorded in `COMPILER_PARITY.md`.

Build the compiler from source by following the repository README. See
`CHANGELOG.md` and `COMPILER_PARITY.md` for the detailed feature, performance
and verification record.
