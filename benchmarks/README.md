<!--
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
-->

# Native primitive benchmarks

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
