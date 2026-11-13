# Conditional-loop parity and release evaluation — 13 November 2026

The source heads after the Open Code changes were ML `a1112f7` and Python
`ad60351`. Their normal test suites and self-host fixed points passed,
but an extended audit reproduced a cross-compiler byte-parity regression.
This evaluation records the repair and the version-stamped 1.3.4 artifacts.
Raw samples and baseline identifiers are in [the JSON record](LOOP_PARITY_2026-11-13.json).

## Cause and correction

The new profitability gate needs at least two indexed uses before duplicating
a dynamic loop into fast and checked versions. Python counted accesses in
else-if conditions, switch values and case-range endpoints. The native
statement walker visited the nested bodies but skipped those expressions.
One ordinary indexed read plus a conditional read therefore selected different
code in the two implementations. Runtime outputs agreed in the reproduced
cases; byte equality failed on both Windows and Linux. The released 1.3.3
pair produced matching bytes for the same original probes.

The native walker now scans every conditional expression used by Python.
The native target table stores one [name, first expression, count] record per
container, eliminating repeated entry allocation and array copying. Python's
code generator already handled these expressions correctly and needs no
code-generation change; both repositories receive the regression coverage.

Both suites assert the loop-versioning decision and runtime results for
array/byte else-if reads, switch values, lower and upper range bounds,
nested bodies, rebinding and empty input. Empty inclusive 0..-1 ranges still
descend and preserve bounds errors; container replacement disables hoisting.

The native register-name dispatch and single-use loop gate from the preceding
commits are retained. Their original measurements remain in the
[use-count report](ARRAY_LOOP_USE_COUNT_GATE_2026-11-12.md) and
[register-dispatch report](REGISTER_NAME_DISPATCH_2026-11-13.md).
The proposed per-file interface-cache shortcut remains rejected.

## Compiler time and memory

The before compiler is the frozen audited Open Code head; the after compiler
is the repaired 1.3.4 build. Both compile the **same final ML compiler source**.
Native measurements use the object pipeline; Python uses its monolithic path.
All use `-I . --heap-reserve 4g --heap-commit 512m --heap-shrink --heap-shrink-min 128m --gc-limit 384m`. One warm-up round is followed by three
measured rounds, with order reversed between rounds and CPU affinity 4.

| Compiler | Before median | After median | Time change | Before peak tree commitment | After peak tree commitment |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native ML (MLO) | 50.87 s | 51.83 s | +1.9% | 1416.0 MiB | 1416.0 MiB |
| Python | 46.40 s | 45.60 s | -1.7% | 1405.4 MiB | 1405.3 MiB |

Native ML (MLO) measured wall-time ranges: 49.62–52.61 s before; 49.63–52.14 s after.

Python measured wall-time ranges: 45.85–47.13 s before; 45.44–47.07 s after.
Memory is the Windows job's peak commitment across the compiler and its
children, **not physical RAM** and not a sum of unrelated process peaks.
The JSON additionally records peak working set and CPU time. With only three
measured rounds and overlapping ranges, these small changes do not establish
a systematic speedup or regression. Other desktop work was active; these are local measurements, not
an isolated laboratory or a guarantee for large applications.

## Generated-program runtime

These gains apply to programs built by the native compiler. Python already
selected the same guarded fast paths before the repair; its generated loops
do not acquire an additional speedup from this fix.

The portable `benchmarks/loop_conditions.ml` fixture mirrors the checked
loop bodies and verifies expected checksums. Each workload processes 512
elements 40,000 times. Before/after images run in alternating order after a
warm-up, 15 measured runs per image and workload, pinned to CPU 4. Windows
and Linux/WSL measurements are evaluated separately.

| OS | Workload | Before ms | After ms | Time change | Heap growth before / after (bytes) |
| --- | --- | ---: | ---: | ---: | ---: |
| windows | array-elif | 76.35 | 71.17 | -6.8% | 0 / 0 |
| windows | bytes-elif | 78.17 | 75.48 | -3.4% | 0 / 0 |
| windows | case-value | 74.40 | 69.70 | -6.3% | 0 / 0 |
| windows | case-range | 61.51 | 51.55 | -16.2% | 0 / 0 |
| windows | single-control | 43.79 | 43.94 | +0.3% | 0 / 0 |
| linux | array-elif | 79.99 | 74.06 | -7.4% | 0 / 0 |
| linux | bytes-elif | 80.53 | 78.31 | -2.8% | 0 / 0 |
| linux | case-value | 82.23 | 75.17 | -8.6% | 0 / 0 |
| linux | case-range | 63.20 | 52.90 | -16.3% | 0 / 0 |
| linux | single-control | 43.52 | 43.88 | +0.8% | 0 / 0 |

Heap growth is the managed bump-pointer delta during the workload, not total
allocation volume or process RSS. Checksums match for every sample. Python
and native after-builds are byte-identical on each target. Restoring guarded
versions adds 13,312 bytes to this focused Windows fixture and 12,288 bytes to
Linux; it trades duplicated code for bounds-check removal. The single-use
control remains checked. These microbenchmarks do not predict whole-game or
server throughput.

Reproduce with `benchmarks/compare_loop_conditions.py BEFORE AFTER --runs 15
--cpu 4 --output RESULTS.json`; invoke the same runner inside Linux for ELF
images. Full compiler measurements use `tests/bench_compiler_optimization.py`;
the JSON includes the commands, raw rounds and source hashes.

## Release verification

- 222 Python integration tests; 45 Python unit tests, with one optional NASM
  comparison skipped.
- 138 native harness tests and 249 successful outer compile/runtime checks.
- 84 focused images across Python, Windows-native and Linux-native compiler
  hosts, both targets, and monolithic/object pipelines: matching bytes and
  runtime output within each target/fixture group.
- 132 OOP parity images and 96 incremental checks for each target.
- Seven full compiler images verify Python bootstrap, native self-hosting,
  monolithic stage 3, Linux-host self-build and cross-target builds.
- 53 standard-library sources and 351 generated standard-library documents
  are byte-identical. Compiler and library MiniDoc generation has no warnings.

Windows compiler: 65,873,408 bytes,
SHA-256 `f531d4aee1d2361ee45e92f016f6ed016dc39567969c847f680980b96bc2b9d0`.

Linux compiler: 65,890,480 bytes,
SHA-256 `c28bceee3c5d8d5730c133d7d0ab789848e7dd975cf20d88285e12d464b775c1`.

See the [release matrix](release-1.3.4-version-matrix.json) for the individual
builds and regression evidence. Equality is established for the tested inputs,
not a proof about every possible MiniLang program.
