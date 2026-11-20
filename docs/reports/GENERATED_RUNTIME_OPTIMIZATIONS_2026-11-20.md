# Generated-program runtime and memory experiments — 20 November 2026

This review evaluates the **programs produced** by the Python and self-hosted MiniLang compilers, not compiler throughput. Four candidates were tested in priority order. Two bounded code-generation extensions are retained. The wider single-use array loop version and global GC-policy changes are rejected.

## Method and scope

All A/B pairs compile identical MiniLang source. The baseline is the unchanged 1.3.9 native compiler from ML source revision `98fb230`; its Windows and Linux binaries are retained locally under `MiniLangCompilerML/build/runtime-opt-20261120/mlc_windows_baseline.exe` and `mlc_linux_baseline`. The verified candidate binaries now occupy `MiniLangCompilerML/build/mlc_win64.exe` and `build/mlc_linux_x64`, with the two source changes below. The benchmark fixture and comparison runner are checked in at `benchmarks/runtime_codegen.ml` and `benchmarks/compare_runtime_codegen.py`. Windows and Linux use 11 alternating process pairs per case; the single-use array trial uses 31. Checksums are required to match within each OS. Linux binaries run on WSL's native `/tmp` filesystem. Runs were unpinned on a shared host, so small differences are not treated as wins. `bytes` is the change in managed heap frontier between benchmark timestamps, not a universal cumulative-allocation counter. Peak RSS/working set includes the entire process. The two accepted cases disable or do not reach periodic collection during their bounded workload, making the frontier delta a useful allocation indicator.

Raw per-run results and image hashes are in the [evidence directory](runtime-optimization-2026-11-20/). Figures below are medians of each version's recorded samples, not extrapolated application gains.

## 1. Thirteen-statement float loops: retained

The guarded raw-float loop already supported up to twelve statements and at most eight arithmetic definitions. Allowing thirteen statements admits eight definitions, four aliases and the induction update without changing the existing definition, state, register, deoptimization or thread safety bounds. The `float-long` benchmark runs 32 calls of 100,000 iterations. The source-level reference uses ordinary helper calls; the extended regression compares zero, short, normalization-fallback and alias cases against that reference.

| OS | Baseline work ms | Candidate work ms | Heap frontier before → after | Peak process memory before → after |
| --- | ---: | ---: | ---: | ---: |
| Windows | 206.93 | 59.58 | 8,388,912 → 4,864 B | 16.74 → 8.10 MB |
| Linux/WSL | 205.17 | 58.08 | 8,388,912 → 4,864 B | 10.03 → 1.38 MB |

The speedups are about 3.47x and 3.53x **for this eligible kernel**. Programs using threads/concurrent GC still take the ordinary loop path. No whole-game or database improvement is claimed.

## 2. Nonescaping structs up to twelve fields: retained

The existing scalar-replacement proof requires one unconditional local constructor, unique unboxed binding, known fields, no object-valued calls, no identity/reflection and no escape. Its former eight-field size cap excluded otherwise-proven wider records. The cap is now twelve, retaining the same proof. The `wide-struct-local` benchmark performs 500,000 nine-field constructions, field updates and reads. A separate escaping nine-field constructor must still allocate and survive GC.

| OS | Baseline work ms | Candidate work ms | Heap frontier before → after | Peak process memory before → after |
| --- | ---: | ---: | ---: | ---: |
| Windows | 12.53 | 4.33 | 44,000,000 → 0 B | 52.11 → 8.08 MB |
| Linux/WSL | 11.09 | 4.26 | 44,000,000 → 0 B | 45.42 → 1.38 MB |

The speedups are about 2.90x and 2.61x for the isolated nonescaping record case. Structs that escape or have unsupported uses keep the normal heap representation. The combined benchmark Windows image grows from 229,376 to 231,936 bytes (+2,560 B); the Linux image remains 239,568 bytes after ELF layout padding.

## 3. Single-use dynamic array loop versioning: rejected

A temporary Python-backend experiment lowered the dynamic-loop use-count gate from two indexed accesses to one. The change would duplicate the loop body and hoist its bounds guard. In 31 Windows A/B pairs, `dynamic-index` changed from 21.359 to 21.033 ms (about 1.5%); heap frontier and peak memory did not fall, while the benchmark image grew by 1,024 bytes. The unchanged `local-register` control changed from 11.615 to 11.558 ms. This is too small and narrow to justify enabling the extra loop body broadly. The Linux repeat finds 21.547 → 21.070 ms (about 2.2%) in the same isolated read loop, with zero heap/RSS change and a 4,096-byte larger ELF. Its `local-register` control changes 11.466 → 11.516 ms. The threshold remains two in **both** compilers.

## 4. Global GC and heap policy: rejected

Two existing runtime options were tested against the unchanged default using `benchmarks/memory_management.ml` on Windows, with 11 A/B pairs per workload. A final committed-heap number is not the same as resident RAM.

| Policy | Workload | Default → trial work ms | Final committed heap | Peak process memory |
| --- | --- | ---: | ---: | ---: |
| `--heap-shrink --heap-shrink-min 1m` | small churn | 67.96 → 106.33 | 32.0 → 8.0 MiB | 16.67 → 16.57 MB |
| same | large live graph | 234.70 → 309.23 | 96.0 → 87.8 MiB | 104.75 → 104.70 MB |
| `--gc-limit 16m` | small churn | 67.37 → 68.40 | 32 → 32 MiB | 16.67 → 25.19 MB |
| same | large live graph | 229.42 → 244.45 | 96 → 96 MiB | 104.75 → 103.11 MB |
| same | fragmented | 3.256 → 2.465 | 48 → 32 MiB | 42.72 → 28.34 MB |

Linux/WSL confirms the trade-off in 11 alternating pairs. `--heap-shrink` changes small churn from 67.01 to 116.56 ms and the large live graph from 233.81 to 297.94 ms; both cases retain the same measured peak RSS despite lower final managed commitment. `--gc-limit 16m` changes small churn from 64.85 to 63.31 ms but raises its peak RSS from 9.83 to 18.28 MB; it slows the live graph from 228.73 to 244.23 ms while helping the fragmented case from 6.55 to 4.41 ms and reducing its peak RSS from 35.98 to 21.43 MB.

The two knobs help particular memory patterns but are poor global defaults: heap shrinking sharply slows churn/live-graph workloads without lowering their observed peak resident memory, while a 16-MiB limit has mixed effects. The default GC code and options are unchanged.

## Correctness and parity

The accepted Windows benchmark image is byte-identical from Python and the rebuilt ML compiler: 231,936 bytes, SHA-256 `4E96ACD2FE89A9958B3EE5C30F6DAD3758C01270F76D1F2E2E04F47300CDCBDF`. The Linux image is likewise byte-identical: 239,568 bytes, SHA-256 `45033D1641CBB5FBB91C1813986A511993280B8BB595952223C5535B4DF2F88B`. GC-policy images also match across compilers. The focused float fixture matches on Windows, Linux and MinUX targets; the Windows fixture executes successfully. The Python unified suite passed 249/249 cases after correcting an existing test helper with an outdated type-inference override signature. The native self-hosted regression suite passed. Updated float and runtime-codegen fixtures execute successfully on Windows and Linux. The Python unit suite passed 60 tests with one optional skip.

Python bootstrap, first native self-build and second native self-build of the updated ML compiler are byte-identical: 66,369,024 bytes, SHA-256 `AC32EE51A3947DE360B5D257E36BEA3B536D1581808BC9EEB06CE9721D16AD13`. For both new regression fixtures on Windows and Linux, Python and ML object-pipeline outputs match byte-for-byte, and the object pipeline matches monolithic output. The shipped formatter is a real-program control: baseline and candidate produce the same 1,659,904-byte formatter (`8663B5CA9C3411D2864A3B02F53E476C8E72243262858834B511E2930C6AB23E`), so this change cannot improve that formatter's runtime.

The Linux compiler also reaches the same Python-bootstrap/native/self-build fixed point: 66,393,008 bytes, SHA-256 `0933330911C685E0FA4E2DA08190BD96BEA3EE732C9CA9F57248FF5DC4515F53`. The Linux-native compiler generates the same runtime benchmark and float-fixture ELF hashes as the Python cross-compiler; the native float fixture executes successfully.

The float stress fixture previously assumed that an asynchronous concurrent collection had already completed. Its default-GC branch still checks automatic collection; its concurrent branch now requests a completed collection before validating retained roots. Both branches pass, and Python/ML images match on Windows. Linux and MinUX float images match byte-for-byte; the Linux executable passes under WSL.
