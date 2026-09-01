# Changelog

All notable changes to the MiniLang compiler are documented here.

## Unreleased

- Made `Thread.Start` an atomic one-shot transition, preventing concurrent
  callers from launching the same thread object twice or overwriting its
  argument/handle state. `SetLogicalId` is atomic against that transition,
  `Stop` owns the publicly alive startup window, concurrent Linux `Join` calls
  share one `pthread_join`, and atomic handle references make `Join` safe against
  a concurrent `Close`. Blocking cleanup is published as native to the GC and
  cannot release roots or handles before every waiter and worker has exited.
- Packed stable thread control records into synchronized 64-KiB arenas instead
  of allocating one OS page per `Thread`. A 50,000-object stress case reduced
  Windows working set from about 202 MiB to about 17 MiB without changing the
  process-lifetime identity contract.
- Fixed native `out double` parameters to pass their address in an integer ABI
  register, reject aliases that give one library/symbol incompatible native ABI
  classes, and preserve exact Linux library spelling consistently. Missing
  Linux libraries/symbols remain catchable managed errors.
- Fixed the x64 PUSH/POP peephole so it only cancels truly adjacent operations;
  an intervening instruction ending in a PUSH-like byte can no longer be
  deleted. Also fixed Python async-variadic lowering, lambda expressions in
  default arguments, and interface declarations in imported modules and
  namespaces.
- Hardened Linux output: float formatting propagates rounding into the integer
  part, `writeAllText` retries partial writes, and source externs resolve
  through their declared library's `dlopen` handle so equal symbol names in
  different shared libraries remain distinct.
- Corrected `std.fs.Sleep` to declare the native function's `void` return and
  integrated Linux loader identity, scalar-out and ABI-conflict regressions into
  the standard test commands.
- Distinguished actual conversion failures from pooled user strings whose text
  is `"void"` or `"<unsupported>"`, so those literals concatenate normally while
  real `void` operands still raise error 1303.

## 1.2.0 - 2026-09-01

- Added gradual runtime type annotations and optional values, expression
  lambdas, default/named/variadic calls, value/range `match`, eager and lazy
  pull iterators with `yield`, structural interfaces, and pooled
  `async`/`await`/`select`. Type contracts now feed representation flow; small
  typed expression functions/lambdas are considered for bounded automatic
  inlining; proven non-escaping variadic tails use immutable stack views; and
  proven primitive returns elide redundant contract checks while async calls
  share a four-worker pool. The positive/negative and performance
  fixtures remain byte-identical with the self-hosted compiler on Windows and
  Linux x64.
- Added Windows/Linux x64 target parity, native Linux self-hosting, typed
  conditional compilation, cross-platform TLS/system services and a matching
  standard library surface on both operating systems.
- Added structured concurrency with tasks, futures, cooperative cancellation,
  bounded channels, `async`/`await`/`select` and fine-grained
  `synchronized(lock)` cleanup semantics.
- Added thread-local allocation buffers and hardened cooperative GC
  safepoints, Linux pthread behavior, project caching, host process boundaries
  and compiler thread-pool shutdown.
- Kept the reference compiler byte-identical with the self-hosted compiler's
  canonical streamed `.mlo` pipeline, compact internal representations,
  phase-local graph release, reused analysis state and native bulk copies for
  both Windows PE and Linux ELF output.
- Added matching regression coverage for resumed assembler emission and
  unresolved patch application after materialization in the self-hosted
  assembler.
- Bounded variable-size GC scans to their candidate heap blocks. This prevents
  conservative interior pointers whose payload resembles arrays or closure
  environments from causing out-of-bounds reads; the regression is exercised
  on Windows and Linux and restores native Linux self-hosting stability.

## 1.1.0 - 2026-08-24

- Added the shallow native `copyArray` primitive and synchronized its runtime
  emission with the self-hosted backend. The sibling compiler now uses it for
  exact one-allocation chunk materialization; controlled self-build private
  peak fell by about 65 MiB (3.58%) while Python and self-hosted outputs remain
  byte-identical.
- Revalidated target parity after the sibling self-hosted compiler compacted
  its internal `FastMap` slot generations into byte buffers and raised their
  occupancy limit from 70% to 80%. The self-build private peak fell by
  120.3 MiB (6.19%) and object-emission time by 2.68%; Python Stage 1 and
  self-hosted Stages 2/3 are byte-identical 60,690,432-byte images.
- Coalesced a retired TLAB tail with the still-adjacent central free-list head
  in O(1). This avoids retaining two neighboring fragments until the next full
  sweep without adding a list scan to the allocation path. A controlled
  self-build improved from 105.781 to 103.573 seconds with an unchanged
  2,279 MiB process-tree private peak. Python Stage 1 and self-hosted Stage 2
  are byte-identical at 60,690,944 bytes; the threaded allocation/GC fixture is
  also byte-identical and verifies the new retirement path in both suites.
- Revalidated target parity after the sibling self-hosted compiler began
  reusing capacity-backed worklists and epoch-cleared maps across serial
  per-function analysis. The optimization changes compiler allocation traffic
  only; controlled MiniQuake and optimizer outputs remain byte-identical.
- Added a Windows/Linux heap-shrink runtime regression and synchronized the
  self-hosted backend's post-GC decommit block and default 4 MiB threshold with
  this reference implementation. Python-built and self-hosted Stage 2/3
  compiler images now have the same size and SHA-256.
- Revalidated target parity after the sibling self-hosted compiler began
  reusing one materialized semantic state across its serial function-object
  batches. The change is internal to self-hosted compiler throughput and does
  not alter Python code generation or MLO v2. All 297 fixed-point compiler
  objects, all 497 MiniQuake objects and their final executables remain
  byte-identical to the clone-per-batch baseline.
- Revalidated target parity after the self-hosted MLO writer stopped
  flattening its complete local-patch set before folding. The optimization is
  internal to the sibling compiler and leaves the MLO v2 wire format and this
  Python implementation unchanged. Windows optimizer, Linux static and Linux
  FFI outputs remain byte-identical across Python, self-hosted monolithic and
  self-hosted object builds.
- Revalidated target parity after the self-hosted MLO v2 writer began folding
  same-fragment `rel32`/`rip32` fields directly into materialized text. Its
  reader remains compatible with v1 and earlier numeric-target v2 caches; the
  Python compiler continues to emit the equivalent canonical monolithic image.
  Representative Windows and Linux outputs remain byte-identical.
- Documented and revalidated compatibility with the self-hosted compiler's
  backward-readable MLO v2 pipeline. The Python compiler continues to emit its
  canonical monolithic image when `--object-pipeline` is accepted for CLI and
  manifest parity. Representative Windows and Linux outputs remain
  byte-identical to the self-hosted MLO-v2 results.
- Added fine-grained `synchronized(lock)` blocks with exactly-once lock
  evaluation and guaranteed release on normal, return and propagated-error
  exits, while retaining synchronized variables/functions unchanged.
- Added cross-platform futures/tasks, cooperative cancellation tokens,
  `whenAll`/`whenAny` completion helpers and bounded MPMC channels with
  backpressure, timeouts, close/drain semantics and valid `void` messages.
- Added a native Linux self-host script and completed canonical `.mlo` linking
  for ELF. Large links now stream sections, labels and relocations by object;
  dynamic-import ordering preserves byte identity with monolithic ELF output.
- Fixed self-hosted array-stack truncation that incorrectly called the
  bytes-only `slice()` builtin. Parent-path normalization, assembler patch
  rollback and namespaced enum type-query optimization now retain array values;
  the Linux self-build also verifies project-manifest path handling.
- Aligned package-qualified enum-variant resolution in the Python compiler with
  the self-hosted compiler while preserving local shadowing, restoring exact
  target bytes for the complete language acceptance suite.
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
- Hardened Linux servers by ignoring `SIGPIPE`, made nonblocking OpenSSL reads
  report retryable readiness, and made exact leaf-pin validation independent
  of a machine CA store while retaining hostname, validity-period and TLS
  server-purpose checks.
- Replaced raw `clone(2)` workers with `pthread_create`/`pthread_join` so every
  Linux thread owns valid glibc TLS for malloc, pthread synchronization and
  native providers. The SysV bridge now preserves MiniLang's nonvolatile XMM
  contract, process termination uses `exit_group`, and Linux thread-pool/GC
  regressions run as part of the target gate.
- Kept extern lookup package-qualified when user functions share a native
  symbol's basename, and synchronized the conservative small-loop unroll
  complexity budget across both compilers. This prevents TLS-heavy Windows
  code bloat while preserving byte-identical Python/self-host targets.
- Made committed-heap growth precede the one emergency full collection at the
  reserved ceiling, so normal heap expansion does not bypass `--gc-limit` or
  repeatedly scan large retained object graphs.
- Fixed `--gc-limit` and `--no-gc-periodic` so generated runtime pressure
  counters receive the requested values in both compilers, including the
  unboxed signed-64-bit disable sentinel used by the self-hosted backend.
- Fixed inactive empty lines shifting source/debug locations in the self-hosted
  conditional preprocessor, and removed quadratic label-array copying from the
  self-hosted ELF linker for large, FFI-heavy Linux programs.
- Removed the remaining large-program relocation bottleneck in the self-hosted
  compiler. Very large monolithic builds now resolve text labels directly and
  materialize only section/IAT overrides, codegen assemblers omit unused full
  call histories while retaining helper discovery, and the `.mlo` linker
  preallocates its object-patch index. These changes preserve target bytes.
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
