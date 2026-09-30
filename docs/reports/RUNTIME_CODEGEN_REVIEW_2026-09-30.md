# Runtime code generation and heap review — 2026-09-30

## Scope and baseline

This performance-focused review covers both expression backends, the relevant
type/constant facts and overload dispatch, statement-level integer inference,
allocation and GC-root handling, native bulk-copy/fill helpers, and PE/ELF
monolithic/object-pipeline parity. It is not a proof that every possible compiler
bug is excluded. No language syntax, standard-library API, object layout or
thread-synchronization contract was changed.

Baseline: v1.2.12, Python commit `bb59783c9ce4d8fcf6b4290d19ceca1978883eca`,
ML commit `16ef8e9d419c1bffc1dff606148664b4850c4cab`.
The before compiler was exported from Git HEAD into an ignored build directory;
both versions compiled the **same current benchmark source** and used identical
heap settings. These are development changes, not a new published release.

## Implemented findings

1. **Known integer floor division:** positive power-of-two divisors in the signed
   61-bit domain use an arithmetic shift and retagging; division by one reuses the
   tagged value. Operand evaluation and overload resolution still happen first.
   Negative, zero, dynamic, non-power-of-two and out-of-domain constants retain
   the generic path. Arithmetic shift correctly rounds negative dividends down.
2. **Immutable string identities:** empty concatenation operands, repeat count
   one and singleton joins reuse the existing string rather than allocating and
   copying. Both concatenation conversions still run; void/error behavior and
   separator/element validation remain intact. All exit paths clear temporary
   GC roots. This does **not** share mutable arrays or byte buffers.
3. **Repeated strings:** seed the destination once and double the initialized
   prefix with a bounded final chunk. Copy-helper calls become O(log count),
   while output storage and bytes copied remain O(output length). One-byte seeds
   dispatch directly to the existing native fill helper, including NUL bytes.
   Nonpositive counts, invalid inputs and length overflow retain prior behavior.
   No safepoints or allocations were introduced in the copy loop.
4. **Large-integer scalar arrays:** a parity test exposed an existing difference:
   ML used a scanned-array header where Python used a scalar-array header for
   some large integer constants. ML now separates header classification from
   whether the encoded value fits in the compiler's own integer representation.
   Normal element emission handles the full range. Later pointer stores still
   promote the array to GC-scanned storage.

The first repeat prototype made a short control case about 4% slower. The final
implementation removes unnecessary loop bookkeeping and uses native fill for
one-byte seeds. Both one-byte and multi-byte short controls are retained below;
the benchmark does not hide the less favorable results.

## Reviewed but deliberately unchanged

- Register residency, loop-hoisted array access and inlining already have guards
  for captured/global/synchronized variables and escape/alias behavior. Broadly
  removing those guards would risk wrong-code bugs.
- Upper/lower ASCII conversion and whole-string slices already avoid several
  unnecessary copies; duplicating those optimizations would add no benefit.
- General concatenation-chain fusion could eliminate more temporary strings,
  but must preserve conversion failures, evaluation order, overloads and GC
  roots across arbitrary expressions. It needs a separate lowering design.
- Decimal formatting still has general division by ten. Reciprocal-multiply
  lowering is a follow-up candidate, not an unmeasured change in this patch.
- Packed numeric containers could reduce array memory substantially, but change
  representation, mutation/promotion and FFI assumptions. They are deferred.
- Heap/TLAB reservation and GC scheduling were not tuned to make these numbers
  look smaller. The savings come from avoiding allocations, not hiding them.

## Measurement method

AMD Ryzen 9 9900X; Windows x64 and Linux x64 under WSL on the same machine.
One warm-up per case/version, then 11 fresh-process samples per version in
alternating A/B order. Timings below are **workload medians**, using
QueryPerformanceCounter / CLOCK_MONOTONIC. Timer scratch buffers are allocated
before measurement. Raw data also contains process wall time (including startup),
all samples, checksums, sizes and image SHA-256 hashes.

Flags: `--heap-reserve 1g --heap-commit 128m --gc-limit 512m`, plus
`--target linux-x64` for ELF. Each case starts after an explicit collection.
The largest case remains below the GC limit, so the heap delta measures
allocated bytes rather than net bytes after an intervening collection.

Earlier exploratory runs overlapped an unrelated MiniRedAlert build. The final
listed series was collected after that observed build ended and before starting
our final rebuilds. This is a desktop microbenchmark, not an isolated performance
lab. Small control-case differences must not be interpreted as a universal gain.

| Workload | Windows before → after (ms) | Linux before → after (ms) | Allocated heap bytes before → after |
|---|---:|---:|---:|
| division | 137.135 → 92.054 | 115.982 → 91.539 | 0 → 0 |
| repeat | 29.763 → 4.933 | 33.723 → 8.028 | 50,343,936 → 50,343,936 |
| repeat-one | 8.147 → 0.072 | 13.073 → 0.063 | 82,400,000 → 0 |
| concat-empty | 8.232 → 0.099 | 12.873 → 0.087 | 82,400,000 → 0 |
| join-one | 8.045 → 0.084 | 13.134 → 0.077 | 82,400,000 → 0 |
| concat-control | 8.114 → 8.093 | 12.770 → 13.034 | 82,400,000 → 82,400,000 |
| concat-small-control | 12.383 → 12.840 | 11.949 → 11.701 | 24,000,000 → 24,000,000 |
| repeat-two-control | 12.745 → 11.342 | 11.480 → 10.848 | 24,000,000 → 24,000,000 |
| repeat-two-multi-control | 13.058 → 13.295 | 12.960 → 12.462 | 24,000,000 → 24,000,000 |
| join-control | 3.190 → 3.342 | 3.118 → 3.059 | 4,800,000 → 4,800,000 |

Division performs 24 million loop iterations with two power-of-two divisions.
Large repeat produces 512 strings of 98,304 bytes. Identity cases each execute
20,000 operations on a 4,096-byte string. Small concat and two-repeat controls
execute one million operations; ordinary join executes 200,000.

The three identity cases eliminate **82,400,000 allocated bytes each**, not
82.4 MB of guaranteed process RSS. Existing live inputs, reserved/committed heap,
thread stacks, metadata and the final output of non-identity operations still
occupy memory. Large repeat allocates exactly as much output as before.

The main gains are clear, but controls show small mixed changes (roughly within
±5% in this series). In particular, Windows small concat, multi-byte repeat-two
and ordinary join did not improve in this run. Application-level MiniSQL,
MiniQuake or HollowKeep speedups have **not** been measured here.

## Reproduce

See `benchmarks/runtime_codegen.ml` and `benchmarks/compare_runtime_codegen.py`.
Preserve before and after images, then run:

```text
python benchmarks/compare_runtime_codegen.py build/runtime_codegen.before.exe build/runtime_codegen.after.exe --runs 11 --output build/runtime_codegen.windows.json
```

For Linux, run the script inside WSL/Linux with the corresponding executable ELF
paths. Do not include a separate WSL startup in each measured process launch.

Raw series: [Windows](RUNTIME_CODEGEN_WINDOWS_2026-09-30.json),
[Linux](RUNTIME_CODEGEN_LINUX_2026-09-30.json).

## Image size

- windows: 134,144 → 134,144 bytes for the benchmark image.
- linux: 141,008 → 141,008 bytes for the benchmark image.

These are small PE/ELF alignment-dependent differences, not a promise that every
application executable becomes smaller. The string helper grows while the
specialized divisions remove generic instructions.

## Correctness and compatibility

- Python suite: **155/155 passed**, no skips.
- ML full harness: **136/136 core tests and 162/162 outer checks passed**,
  including Linux execution and object-pipeline comparisons.
- Regression coverage: negative and extreme signed-61-bit dividends; all 60
  legal power-of-two shifts in the Python instruction-selection model; wrapped
  negative/zero divisors; dynamic/noninteger fallbacks; UTF-8 and embedded NUL;
  repeat tails, count/length overflow and validation order; singleton validation;
  observable evaluation order; allocation-free identities; GC safepoints;
  scalar/SIMD copy and fill; array promotion and worker-result lifetime.
- Identical standard libraries: **53/53 files**, byte-for-byte unchanged.
- The same regression source generates byte-identical output across Python/ML
  and monolithic/MLO modes, separately for each target:
  - Windows PE: `B9D408D7FD25D5A695B9864BE5481FD744480665329984C9A4F2B20B280F125C`
  - Linux ELF: `8B4A070E04539007E28F23B92004D90A786623A86D8A68FD0614EC2B9D7B1DD3`
- Both benchmark images are also byte-identical across Python and ML. Their
  hashes are retained in the raw measurement JSON.
- Windows self-hosting: Python bootstrap and native self-rebuild match:
  `2EAB70CF9E776CFEFA55FC051ED4A3D6DE17FB5E538D9604F4966B8C19FBAEE9`.
- The Python-built Linux compiler
  (`9785A5BD317A62D14DB3BAACE8CD47B309D27A07169E1F6B2983AF0D8F96C82D`)
  runs under WSL and builds/runs the regression fixture with exactly the same
  ELF hash as the Windows cross-compilers. A full Linux-native self-rebuild was
  not repeated in this review.
- These are scoped equality checks, not a claim of universal compiler parity.
  The previously documented native `cstr` return-lowering difference is outside
  this patch; see the existing compiler-parity documentation.

Detailed local logs are under `build/runtime-review-tests-final2*` in each
repository and `build/runtime-review-final2-{bootstrap,self}.log` in ML.
The checked native artifacts are `build/mlc_win64.review.final2.self.exe`
and `build/mlc_linux_x64.review.final2`.
After verification, they also replace the local canonical `build/mlc_win64.exe`
and `build/mlc_linux_x64`. The previous binaries are preserved as
`build/mlc_win64.before-runtime-review-20260930.exe` and
`build/mlc_linux_x64.before-runtime-review-20260930`.
No commit, push, version bump or GitHub release is part of this task.
