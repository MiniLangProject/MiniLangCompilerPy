# Changelog

All notable changes to the MiniLang compiler are documented here.

## 1.1.0 - 2026-08-24

- Added `--target windows-x64|linux-x64` and manifest `target` selection. The
  new deterministic ELF64 backend includes the managed runtime, global GC heap,
  TLABs, native Linux threads/synchronization and glibc-compatible `.so` FFI.
- Made the complete public standard library usable on Windows and Linux:
  filesystem, IPv4 TCP/UDP, monotonic/calendar time, locks/semaphores/events and
  shared-value storage use native platform adapters, while cryptography selects
  Windows CNG or Linux OpenSSL 3 behind the same API.
- Added target-neutral platform, path, process and console modules; durable
  positional file I/O with advisory locks and atomic replacement; explicit
  socket options and listener addresses; UUID v4; PBKDF2-SHA-256/SHA-384; and a
  provider-neutral TLS stream contract. Linux builds now diagnose unguarded
  Windows `.dll` imports during validation.
- Completed `std.tls` with native Schannel and OpenSSL 3 client/server
  providers, system or explicit trust, DNS-name verification, SHA-256 leaf
  pinning, TLS 1.2/1.3 minimums, server identities and clean shutdown. Added
  real cross-target handshake tests and fixed the Linux null-address `accept`
  FFI signature exposed by TLS listeners.
- Made committed-heap growth precede the one emergency full collection at the
  reserved ceiling, so normal heap expansion does not bypass `--gc-limit` or
  repeatedly scan large retained object graphs.
- Fixed `--gc-limit` and `--no-gc-periodic` so generated runtime pressure
  counters receive the requested values in both compilers, including the
  unboxed signed-64-bit disable sentinel used by the self-hosted backend.
- Fixed inactive empty lines shifting source/debug locations in the self-hosted
  conditional preprocessor, and removed quadratic label-array copying from the
  self-hosted ELF linker for large, FFI-heavy Linux programs.
- Added real Windows threads over a process-wide, thread-safe managed heap,
  per-thread stacks, cooperative stop-the-world GC and synchronization.
- Added 64 KiB thread-local allocation buffers for lock-free small-object
  allocation in threaded programs while preserving the single global heap.
- Fixed a rare high-CPU safepoint livelock under back-to-back collections by
  atomically republishing resumed workers as parked for the next GC request.
- Added thread arguments, logical thread IDs, status inspection, worker pools,
  locks, semaphores and thread-safe list, hash map and shared-value modules.
- Added `defer`, native FFI output parameters and project manifests with
  content-validated incremental builds.
- Added typed, nested conditional compilation with `#option`, `#const`,
  `#if/#elif/#else/#endif`, `#error`, CLI `-D` overrides and manifest
  `[defines]`, while preserving Python/self-host target-byte parity.
- Added CPU feature detection, native byte-search primitives, CRC-32,
  hardware-dispatched CRC-32C and platform-native cryptography helpers.
- Improved generated-code optimization with known-struct method
  devirtualization/inlining, hot primitive XMM register homes and constant
  integer strength reduction; also improved global/object initialization and
  the memory-bounded self-hosted `.mlo` pipeline while preserving cross-compiler
  target-byte parity.
- Added guarded type-flow specialization for fallible `bytes(...)` results and
  16-byte user-function alignment. This restores compact byte-processing hot
  paths without weakening runtime errors and prevents local size wins from
  shifting later functions onto unstable instruction-cache boundaries.
- Replaced the self-hosted type-flow pass's repeated whole-function fixed-point
  scans with indexed facts and a dependency worklist, keeping compiler-sized
  source builds bounded while preserving emitted target bytes.
- Made package-qualified enum constants available to integer-flow analysis and
  replaced repeated self-hosted candidate-membership scans with indexed,
  monotone validation. This restores Python/self-host target parity without
  slowing large generated programs.
- Expanded cross-compiler, runtime, standard-library, fixed-point and large
  application regression coverage.

## 1.0.0 - 2026-08-22

- First stable, source-only release of the Python reference compiler and the
  self-hosted MiniLang compiler.
