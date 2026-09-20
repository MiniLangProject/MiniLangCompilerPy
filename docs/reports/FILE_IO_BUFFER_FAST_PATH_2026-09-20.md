# Positional file-I/O buffer fast path (20 September 2026)

`std.io.file.readAt` previously allocated a temporary byte array and copied
every result. `writeAt` previously sliced the source before every native call.
Both implementations now pass the caller's bytes directly for zero-offset
buffer ranges; nonzero offsets and write retries retain the safe copy path.
The public API and on-disk file format are unchanged.

## Windows x64 measurement

`benchmarks/file_io.ml` was built once with the old standard library and once
with the changed library. The executables ran nine times each in alternating
AB/BA order on the same host. The same small file region was repeatedly
accessed at offset zero, so the result primarily measures API overhead rather
than storage-device throughput. Values below are median elapsed milliseconds
for each loop.

| Buffer and operation | Calls | Before | After | Elapsed change |
| --- | ---: | ---: | ---: | ---: |
| 4 KiB write | 80,000 | 156 ms | 140 ms | -10.3% |
| 4 KiB read | 80,000 | 125 ms | 110 ms | -12.0% |
| 64 KiB write | 10,000 | 47 ms | 31 ms | -34.0% |
| 64 KiB read | 10,000 | 47 ms | 16 ms | -66.0% |

Windows monotonic tick values have coarse effective resolution, especially
for the short 64-KiB loops. Results do not predict end-to-end database gains.

## Correctness and parity

`tests/platform_services.ml` now covers full-buffer and prefix I/O, nonzero
buffer offsets, short reads, EOF preservation, and invalid ranges. It passed
with both compilers on Windows and under Ubuntu/WSL. The Python and self-hosted
compilers produced byte-identical Windows and Linux executables for both the
test and the benchmark. A Linux candidate benchmark also passed on WSL's
native filesystem; no before/after Linux timing comparison was recorded.
