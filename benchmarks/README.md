<!--
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
-->

# Native primitive benchmarks

## Crypto and compression

`crypto_compression.ml` measures SHA-256/384, HMAC-SHA-256/384, HKDF,
PBKDF2, X25519, ECDSA-P256 verification, AES-256-GCM, secure random bytes,
constant-time equality, secure erasure, and fast/compact compression on
repeated, patterned, and random-like 1-MiB inputs. Compression ratios and
decoded-byte checks accompany throughput numbers. Pass `--crypto-only` to
the compiled benchmark when profiling native crypto without compression.

```powershell
python .\mlc_win64.py .\benchmarks\crypto_compression.ml .\build\crypto_compression.exe -I .
.\build\crypto_compression.exe
```

Use `build/mlc_win64.exe` instead of Python in the self-hosted repository.
For Linux, add `--target linux-x64` and run the resulting ELF on Linux.
Repeat at least five times on an otherwise idle host; compare medians rather
than single millisecond-resolution observations. See the
[crypto/compression report](../docs/reports/CRYPTO_COMPRESSION_2026-09-20.md).
The optional `tests/compression_interop.py` checks raw LZ4 blocks against
liblz4 in both directions after compiling `tests/compression_interop.ml`;
it does not add a library dependency to generated applications.

## Positional file I/O

`file_io.ml` checks and times cached 4-KiB and 64-KiB positional reads and
writes with reusable buffers. It writes repeatedly to one file location to
focus on per-call buffer, runtime and system-call overhead, not storage-device
throughput. It removes its temporary file on success.

```powershell
python .\mlc_win64.py .\benchmarks\file_io.ml .\build\file_io_bench.exe -I .
.\build\file_io_bench.exe
```

For Linux, add `--target linux-x64`, run the ELF on Linux and compare only
measurements from the same host and filesystem. Alternate baseline and
candidate builds across multiple runs and compare medians; Windows tick
readings are millisecond values with coarser effective resolution. These
numbers are not a promise of end-to-end database throughput.

The initial paired results are in
[the file-I/O fast-path report](../docs/reports/FILE_IO_BUFFER_FAST_PATH_2026-09-20.md).

`file_io_offsets.ml` repeats the same cached positional operations with
nonzero source and destination offsets, checks untouched guard bytes, and
isolates the newer interior-buffer fast path. `stdlib_io_paths.ml` measures
256 successive 4-KiB appends followed by 500 whole-file reads;
`stdlib_tls_send.ml` measures the `std.tls.sendAll` wrapper with a synthetic
provider, deliberately excluding network and encryption costs. The paired
Windows and Linux results, including measurement caveats, are in
[the standard-library I/O report](../docs/reports/STDLIB_IO_OPTIMIZATION_2026-09-20.md).

`stdlib_collections_copy.ml` pairs the previous stable insertion-sort loop
with the current stable sort on reversed integers. It also times hash-map
churn, a 50-ms channel timeout, and a 32-MiB file copy. On Linux it runs the
previous read-all/write-all copy as a local baseline before the new copy.
Run the Linux image once from a native filesystem (for example WSL `/tmp`)
and separately from DrvFS if that path matters to you; filesystem results
are not interchangeable. The fixture removes its own per-process files.

```powershell
python .\mlc_win64.py .\benchmarks\stdlib_collections_copy.ml .\build\stdlib_collections_copy.exe -I .
.\build\stdlib_collections_copy.exe
```

See the [standard-library audit optimization report](../docs/reports/STDLIB_AUDIT_OPTIMIZATION_2026-09-20.md)
for the first paired measurements and compiler parity checks.

## Paired code-size experiments

`compare_code_size.py` compares two already-built native programs, records
their SHA-256 and file sizes (plus unpadded PE `.text` sizes), performs one
warmup per image, and alternates A/B and B/A order across repeated runs.
Nonzero exit codes and timeouts are failures, not timing samples.

```powershell
python benchmarks/compare_code_size.py --baseline build/before.exe --candidate build/after.exe --runs 7 --output build/size-comparison.json
```

Append common program arguments after `--`. Use `--wsl` for Linux images on
Windows; those wall times include WSL startup, while the language optimizer's
internal millisecond counters measure its individual workloads. Keep compiler
builds and other CPU-heavy jobs out of the measurement window. This is a
diagnostic benchmark, not a fixed timing assertion in the regression suite.

The [5 September 2026 experiment](../docs/reports/CODE_SIZE_2026-09-05.md)
records the initial compact-encoding measurements.

Compile and run `native_primitives.ml` with the compiler revision being
measured. Redirect each run to a revision-specific text file and compare the
same machine, power plan, compiler options, and idle-system conditions.

```powershell
.\build\mlc_win64.exe .\benchmarks\native_primitives.ml .\build\native_primitives_bench.exe -I .
.\build\native_primitives_bench.exe | Tee-Object .\build\native_primitives_bench.txt
```

The benchmark covers a 64 MiB CRC-32C workload, found and missing byte scans,
short and long substring scans, AES-256-GCM at three message sizes, SHA-256,
and SHA-384. CRC and search are measured with forced scalar dispatch and with
all detected CPU features. Each result reports elapsed milliseconds,
throughput in MiB/s, live-heap change, and committed-heap change.

These are diagnostic measurements, not fixed pass/fail performance tests.
Record at least five runs per revision and compare medians. A change is
actionable only when it repeats outside ordinary run-to-run noise.

## Parallel allocation churn

`thread_allocation_churn.ml` starts 1, 2, 4, 8, 12 or 24 native workers behind
a common start barrier. Every worker performs one million iterations with two
small managed allocations while retaining only a bounded 256-entry ring. This
exercises TLAB refills, frequent collection of short-lived graphs and
stop-the-world coordination under server-style allocation pressure.

```powershell
python .\mlc_win64.py .\benchmarks\thread_allocation_churn.ml .\build\thread_allocation_churn.exe
.\build\thread_allocation_churn.exe 24
```

The program validates thread completion and result checksums, then reports the
managed workload time, allocation count and post-collection heap counters. Run
separate processes repeatedly; a timeout or non-zero exit is a correctness
failure, not a performance sample.

## Language optimizer features

`language_optimizer.ml` compares typed and dynamic arithmetic, automatic
inlining and an equivalent typed call, eager and lazy iterators, stack-backed
and escaping variadic tails, and compiler-managed async jobs versus native
thread creation. It validates equal checksums before reporting time and heap
deltas. The pairs deliberately isolate one optimizer decision where practical;
lazy iterators trade throughput for bounded memory, so compare both columns.
Pass `--long` to the built benchmark for ten times as many arithmetic/call
iterations; iterator, allocation and threading workload sizes stay unchanged.

```powershell
python .\mlc_win64.py .\benchmarks\language_optimizer.ml .\build\language_optimizer.exe -I .
.\build\language_optimizer.exe
```

## Tasks, channels and fine-grained synchronization

`concurrency.ml` measures 10,000 thread-pool tasks, 250,000 values transferred
through a bounded channel and 400,000 updates protected by
`synchronized(lock)`. It uses the target-neutral monotonic clock and therefore
runs unchanged on Windows and Linux.

```powershell
python .\mlc_win64.py .\benchmarks\concurrency.ml .\build\concurrency_bench.exe -I .
.\build\concurrency_bench.exe
```

For Linux, add `--target linux-x64`, make the output executable and run it on
an x64 Linux host. Record at least five fresh-process runs and compare medians;
the benchmark validates every result before printing elapsed milliseconds.
