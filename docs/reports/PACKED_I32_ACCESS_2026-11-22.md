# Faster checked Int32Array access

Both x64 code generators lower the standard library's `Int32Array.get`
and `set` through a checked signed 32-bit load or store. The existing
method inliner can expand the operation when it knows the receiver.
An unknown receiver uses normal method dispatch and reaches the same
operation in the method body.

The byte buffer supplies its own length. Both paths validate the whole
cell and use the full-width index when resolving negative indices and
checking bounds. A failed write leaves the original cell intact.
The constructor, methods, signed 32-bit range and error codes are unchanged.

## Windows x64 microbenchmark

Each case used one million cells. The timing measures wall time,
including allocation and process startup. Three warm-up trials were
discarded and 20 trials were measured in rotating order. The benchmark
images use `--no-gc-periodic`.
The checksum was validated on every run. Python and the self-hosted
object pipeline produced identical images for the measured variants.

| Operation | Normal array | Previous Int32Array | Current Int32Array |
| --- | ---: | ---: | ---: |
| Write and read every cell | 17.27 ms | 46.22 ms | 22.11 ms |
| Read every cell | 16.34 ms | 28.74 ms | 18.12 ms |
| Write every cell and read the last one | 16.49 ms | 30.80 ms | 17.64 ms |

The combined case improved by 52.2%. Its range was 43.82–55.43 ms
before and 20.81–29.72 ms after. In
[`packed_array_storage.ml`](../../benchmarks/packed_array_storage.ml),
use `-D PACKED=true` to select the packed collection. The `ACCESS`
option selects combined (`0`), read-only (`1`), or write-only (`2`).
With one million cells, `heap_bytes_used()` increased by 8,000,016 bytes
for the normal array and 4,000,040 bytes for the packed array. The
allocation measurements were collected separately from the timing trials.

## MiniSQL buffer-pool experiment

The M5 buffer-pool stress workload ran with 4,096 pages and 16,384
operations. One variant used the original array for expected page
markers and one used `Int32Array`. Both exercised the actual buffer
pool, including evictions, flushes, reopen, and persisted-page checks.
Files were recreated for each run. Seven measured trials per variant
followed two warm-up trials. Wall time includes process startup and
storage I/O.

| Metric | Normal array | Int32Array |
| --- | ---: | ---: |
| Marker storage | 32,784 bytes | 16,424 bytes |
| Median total runtime | 7.75 s | 7.61 s |
| Runtime range | 6.79–8.27 s | 6.92–8.38 s |
| Median peak working set | 75.49 MiB | 75.44 MiB |
| Median peak pagefile usage | 82.78 MiB | 82.78 MiB |

Every run passed and produced a database with SHA-256
`e43e14b26a56cc8312dcf252e72e7478e4759289428f8e711fcc0c95f789c62c`.
The Python and self-hosted object pipeline builds of each test variant
were byte-identical. The difference in total runtime lies within the
observed variation. The change to the MiniSQL fixture was experimental.

## Verification

- The Python suite passed 263 tests. The self-hosted harness passed 179
  tests and its outer integration runner finished successfully.
- The runtime fixture covers known and dynamic receivers, large signed
  indices, the empty collection, invalid allocation length, named arguments,
  signed 32-bit extremes, and error propagation through `try`.
- The assembly check verifies inline bounds and range checks on known
  receivers and dispatch for the unknown receiver.
- The Python, self-hosted monolithic and object pipeline outputs matched
  across five fixtures on Windows x64, Linux x64 and MinUX x64. The
  packed-array fixture ran on all three targets, including the packed
  MinUX build under QEMU, and passed under Windows concurrent GC.
- The incremental regression suite passed 180 Windows executions with
  matching clean, cold-cache, and warm-cache outputs within their groups.

The complete compiler images also matched between Python and native
self-hosted builds for Windows and Linux, and between Python and
self-hosted packed cross-builds for MinUX.

| Compiler image | SHA-256 |
| --- | --- |
| Windows x64 | `545cf5480b7bfb4818bf3062ec4b3e0bbe67cc64b1528f7f11bcf6494edbded2` |
| Linux x64 | `c2bf5ec8a7270ace83033f9513487a5f189a0fb51d2871dbf65c25185dc6ba9f` |
| MinUX x64 packed | `f569be5ec397e9487363309a362fde8ab081ee93a23497e8b51bb71ee72f2e02` |
