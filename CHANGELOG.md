# Changelog

All notable changes to the MiniLang compiler are documented here.

## 1.1.0 - 2026-08-24

- Added real Windows threads over a process-wide, thread-safe managed heap,
  per-thread stacks, cooperative stop-the-world GC and synchronization.
- Added 64 KiB thread-local allocation buffers for lock-free small-object
  allocation in threaded programs while preserving the single global heap.
- Added thread arguments, logical thread IDs, status inspection, worker pools,
  locks, semaphores and thread-safe list, hash map and shared-value modules.
- Added `defer`, native FFI output parameters and project manifests with
  content-validated incremental builds.
- Added CPU feature detection, native byte-search primitives, CRC-32,
  hardware-dispatched CRC-32C and Windows CNG cryptography helpers.
- Improved generated-code optimization, global/object initialization and the
  memory-bounded self-hosted `.mlo` pipeline without changing target bytes.
- Expanded cross-compiler, runtime, standard-library, fixed-point and large
  application regression coverage.

## 1.0.0 - 2026-08-22

- First stable, source-only release of the Python reference compiler and the
  self-hosted MiniLang compiler.
