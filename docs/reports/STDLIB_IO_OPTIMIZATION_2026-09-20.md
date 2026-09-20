# Standard-library I/O follow-up (20 September 2026)

Both compiler repositories received identical standard-library changes. The
baseline is the Python repository at `f97f7c9`; candidate builds use the
working-tree changes described here. All timings are medians from alternating
baseline/candidate process runs on the same Windows x64 host, or Ubuntu under
WSL with benchmark files on its native `/tmp` filesystem. They measure the
specified isolated workloads, not application-level throughput.

## Changes

- `std.fs.appendAllBytes` and `appendAllText` use native append handles and
  no longer read, concatenate and rewrite the prior file. Both Windows and
  Linux whole-file reads fill their final byte buffer directly in up to 1-MiB
  chunks. Byte writes retry partial native writes without making slices.
- `std.io.file.readAt` and `writeAt` now pass validated interior byte-buffer
  pointers to native positional APIs, including nonzero offsets and write
  retries. Existing APIs and range checks remain.
- `std.net.tcpSendAll` sends from the original byte buffer after partial
  sends. New `tcpRecvInto` and `udpRecvFromInto` fill caller-owned buffers at
  checked offsets; the allocation-returning APIs are unchanged.
- `std.tls.sendAll` avoids the first full-payload copy for providers that
  accept a complete send, copying only after a partial send. Provider input
  buffers are now explicitly read-only by contract.

## Paired measurements

`benchmarks/stdlib_io_paths.ml` appends 256 × 4 KiB to a 1-MiB file, then
reads that file 500 times. Seven AB/BA pairs:

| Workload | Windows baseline | Windows candidate | Linux baseline | Linux candidate |
| --- | ---: | ---: | ---: | ---: |
| 256 appends | 1125 ms | 47 ms | 904 ms | 1 ms |
| 500 whole-file reads | 172 ms | 78 ms | 45 ms | 44 ms |

The Linux append result reaches the millisecond timer's granularity; it
establishes a large improvement but not a precise 904× speedup. Whole-file
reads on Linux were effectively unchanged in this cache-hot workload.

`benchmarks/file_io_offsets.ml` repeatedly accesses the same cached region
at a 16-byte buffer offset and verifies guard bytes. Seven AB/BA pairs:

| Workload | Windows baseline | Windows candidate | Linux baseline | Linux candidate |
| --- | ---: | ---: | ---: | ---: |
| 4-KiB write × 80,000 | 157 ms | 141 ms | 52 ms | 27 ms |
| 4-KiB read × 80,000 | 125 ms | 110 ms | 28 ms | 18 ms |
| 64-KiB write × 10,000 | 47 ms | 31 ms | 44 ms | 20 ms |
| 64-KiB read × 10,000 | 47 ms | 16 ms | 34 ms | 10 ms |

The short Windows loops show coarser effective timer resolution. These numbers
primarily isolate copy and call overhead, not durable-device performance.

`benchmarks/stdlib_tls_send.ml` calls `sendAll` one million times with a
64-KiB buffer and a synthetic provider that consumes the payload immediately.
Five AB/BA pairs: Windows **2235 → 31 ms**; Linux **2386 → 36 ms**. This
isolates wrapper copying; it does not measure TLS encryption, socket writes or
real application throughput. No TCP throughput claim is made for the new
pointer-send path.

## Correctness

The expanded `tests/stdlib_unit_tests.ml` covers append creation and byte
preservation, reads spanning the 1-MiB chunk boundary, and TCP/UDP receive
buffers with invalid ranges, untouched guards and full-size payloads.
`tests/platform_services.ml`
covers positional offset I/O, prefix and short reads, EOF and range errors.
Both fixtures pass with both compilers on Windows and Linux. The corresponding
Windows PE and Linux ELF outputs, plus both offset-benchmark outputs, are
byte-identical between compilers. The TLS benchmark outputs are also
byte-identical after rebuilding from the final source.

The full self-hosted compiler regression runner and the Python compiler's
150-test suite passed. Real Schannel and OpenSSL TLS integration tests passed
with both compilers, including expected certificate/hostname rejections.
