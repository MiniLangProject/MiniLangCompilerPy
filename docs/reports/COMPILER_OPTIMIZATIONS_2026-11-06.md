# Compiler and generated-code optimizations — 6 November 2026

This follow-up evaluates five proposals in the Python and self-hosted compiler
worktrees. Its baseline includes the retained
[4 November optimizations](COMPILER_OPTIMIZATIONS_2026-11-04.md).
The source version is 1.3.2; the changes described here are unreleased.

## Decisions and implementation

1. **Direct assembler emission — retained.** Python now writes 28 ordinary
   and indexed memory instructions directly into its existing byte buffer.
   The native compiler also removes temporary EncMem records and short byte
   arrays from its five indexed-address emitters. The standalone encoders
   remain available as independent regression oracles. Register validation,
   REX, SIB, displacement widths, prefixes, immediates and listing hooks retain
   their behavior. Invalid index/scale inputs fail before writing an instruction.

2. **Compact relocation columns and integer handles — rejected.** A Python
   prototype replaced stored patch tuples with numeric columns and reference
   arrays. An ML prototype used negative integer handles into position/kind
   columns and a GC-visible target array, materializing public records at
   boundaries. Both preserved the tested output bytes, but the measured
   memory/time tradeoff did not justify their integration. These representations
   remain confined to the ignored experiment directory.

3. **Native MLO metadata serialization — retained.** Normalized MloPatch records
   use known member offsets; the existing coercions and permissive fallback
   remain available for other record shapes. A four-byte integer contained
   within one 64-KiB page now uses one x64 store. Boundary-crossing writes
   retain the general byte writer. MLO version 2 and its serialized layout
   are unchanged. This is an ML object-writer improvement; Python accepts the
   object-pipeline flag for CLI compatibility and emits its monolithic equivalent.

4. **Bounded string-concatenation fusion — retained in both backends.**
   The existing three-leaf fast path now handles up to eight pure leaves.
   Literals and unboxed local/parameter reads can be evaluated into precise
   stack roots, validated, and copied into one result allocation. Empty,
   non-string and excessive-length cases take sequential checked additions.
   Calls, globals and captured values retain ordered evaluation. Longer chains
   continue through the existing iterative lowering. The common three-leaf
   analysis remains short-circuiting; rejected longer chains stop at their first
   effect before allocating another operand list.

5. **Typed-field scalar replacement — retained in both backends.**
   Proven nonescaping local structs with 1–8 fields can store their fields in
   precise stack roots even when the fields have type contracts. Constructor
   guards execute in their original order and retain source positions,
   optional-value behavior and error propagation. The proof requires an
   unconditional constructor assignment to an unannotated local binding and
   only subsequent known field reads/writes. Aliases, object escapes, closures,
   unsupported syntax and annotated object bindings keep ordinary allocation.

All 53 standard-library source files remain byte-identical between repositories.

## Measurement method

Hardware: AMD Ryzen 9 9900X, 12 cores / 24 logical processors.
Windows x64 measurements use Python 3.11; Linux programs run under Ubuntu/WSL.
These are WSL measurements, not a separate bare-metal Linux comparison.

Runners pin themselves and inherited processes to logical CPU 4, warm both
variants, alternate execution order, and exclude warm-up runs from medians.
Runtime and metadata microbenchmarks use 15 measured runs per variant.
The final Python formatter comparison uses 7; the full native compiler
comparison uses 3.

The final native comparison compiles the same final compiler source tree with
both compiler images and the object pipeline. Both use:

```text
--heap-reserve 4g --heap-commit 512m --heap-shrink
--heap-shrink-min 128m --gc-limit 384m
```

The compiler's startup policy raises its own GC threshold to 3 GiB.
These settings are held constant for the experiment.

Process-tree private commitment is the Windows job's simultaneous peak across
the parent compiler and its emitter/linker children. It is not physical RAM,
live-object size, or the sum of unrelated process peaks. Parent-only working
set counters in the raw JSON omit the main child allocation load.

The allocation-sensitive runtime cases disable collection during a bounded
workload. Their heap deltas therefore measure managed heap growth, including
object headers/alignment, rather than a prediction of a long-running game's
resident memory. Runtime timing excludes process startup; wall time and peak
RSS are also retained in the raw data.

## Generated-program results

| Workload | Platform | Before | After | Time change | Managed heap growth |
| --- | --- | ---: | ---: | ---: | ---: |
| Eight strings, 64-byte inputs | Windows | 26.760 ms | 7.209 ms | -73.1% | 196.0 → 47.2 MB |
| Eight strings, 64-byte inputs | Linux/WSL | 34.061 ms | 9.659 ms | -71.6% | 196.0 → 47.2 MB |
| Eight strings, one-byte inputs | Windows | 7.589 ms | 2.444 ms | -67.8% | 17.6 → 3.2 MB |
| Eight strings, one-byte inputs | Linux/WSL | 6.527 ms | 2.519 ms | -61.4% | 17.6 → 3.2 MB |
| Local typed pair | Windows | 10.235 ms | 6.981 ms | -31.8% | 16.0 → 0.0 MB |
| Local typed pair | Linux/WSL | 12.529 ms | 7.402 ms | -40.9% | 16.0 → 0.0 MB |
| Three-string control | Windows | 1.954 ms | 1.927 ms | -1.4% | 4.8 → 4.8 MB |
| Three-string control | Linux/WSL | 2.037 ms | 1.958 ms | -3.9% | 4.8 → 4.8 MB |
| Untyped-pair control | Windows | 4.384 ms | 4.375 ms | -0.2% | 0.0 → 0.0 MB |
| Untyped-pair control | Linux/WSL | 4.580 ms | 4.605 ms | +0.5% | 0.0 → 0.0 MB |

The eight-string cases perform 100,000 calls. With 64-byte inputs they return
checksum 44,900,000 and reduce heap growth from 196.0 MB to 47.2 MB
(**75.9% less**). With one-byte inputs the checksum is 800,000 and growth falls
from 17.6 MB to 3.2 MB. A typed pair is constructed, updated and read in
500,000 calls; checksum 250,001,000,000 is preserved and its 16.0 MB of heap
objects disappears. Stack storage still holds the scalar fields.

The three-string and already scalarized untyped-pair controls have unchanged
allocation volume and similar timings. All measured program images were
reproduced byte-for-byte by the final Python, Windows ML and Linux ML compilers.
The native baseline also reproduces both baseline benchmark images.

Fusion trades some instruction bytes for fewer allocations. The Windows
runtime benchmark grows from 223,744 to 224,768 bytes; the Linux image remains
235,456 bytes after file alignment. For the common final compiler source,
the new code generation adds 62,976 bytes
(0.096%) to the Windows executable.
No whole-game FPS or production-server improvement is claimed by these cases.

## Compiler and metadata measurements

| Measurement | Before | After |
| --- | ---: | ---: |
| Python formatter build, wall median | 1.016 s | 0.993 s |
| Python formatter build, job CPU median | 0.969 s | 0.969 s |
| Python formatter build, peak private commitment | 59.68 MiB | 58.75 MiB |
| ML full self-build, wall median | 70.44 s | 51.18 s |
| ML full self-build, measured range | 49.94–76.67 s | 50.23–82.18 s |
| ML full self-build, peak process-tree commitment | 1431.1 MiB | 1415.4 MiB |
| One million metadata u32 appends | 423.013 ms | 410.324 ms |

The Python wall-time change is -2.2%;
CPU medians are equal at the timer's resolution. The isolated assembler-only
comparison recorded 1.016 → 0.989 s with identical output bytes.

**The full native timing ranges overlap substantially.** The large median
difference is not evidence of a reproducible general compiler speedup.
Both versions have runs near 50 seconds and much slower outliers; the cause
of that variation was not isolated. The more stable memory measurement
decreases by 15.7 MiB
(-1.1%).

The metadata integer microbenchmark improves by
3.0% with the same
4,068,312-byte heap delta and checksum 4,999,999. It isolates paged integer
writes, not the complete serializer or disk throughput. A separate normalized-
record writer comparison on the formatter measured 1.132 → 1.122 s;
that small end-to-end difference should not be generalized.

## Rejected representation experiments

- Python compact patches saved 8.58 MiB of formatter process commitment
  (58.77 → 50.19 MiB), but increased median build time from 0.962 to
  0.989 s (+2.8%).
- Native compact patches increased formatter time from 1.122 to 1.165 s
  (+3.8%), without reducing the measured commitment peak.
- On the large frozen-source build, the native packed variant used
  18.8 MiB more process-tree commitment than the corresponding unpacked
  candidate. Its variable timing did not establish a compensating benefit.

The final implementation keeps the existing relocation representation.
Earlier raw experiment labels such as `retained` describe intermediate
candidates. The final compiler acceptance measurements are
`selfhost-results` and `python-final-results`; their source and image
hashes are included in the JSON.

## Correctness and compatibility

- Python unified suite: **222 passed**, no failures or skips.
- Python unit suite: **45 passed**, one optional NASM cross-check skipped.
- Native harness: **138 passed**; **249 successful outer steps**, including
  Windows/Linux runtime checks and object-pipeline regressions.
- Indexed/native emission: 2,240 address/width vectors plus invalid-operand
  checks. Python direct emission: 34,816 comparisons against the standalone
  encoder, plus golden instructions, listing and execution tests.
- Integer metadata writes: signed/truncation values, neighboring-byte
  preservation, and offsets on both sides of the 64-KiB page boundary.
- New semantics: 4/8-leaf fusion, longer-chain fallback, empty/mixed operands,
  UTF-8, ordered effects, error propagation, optional typed fields, escaping
  objects, source provenance and forced collections.
- Structural gates prove the typed local has no object allocation, retains
  its error paths, and the bounded concat has both one-allocation and guarded
  fallback paths.
- Incremental/cache gate: **96 checks per target**, Windows and Linux,
  including corruption fallback, invalidation and fresh/warm output parity.
- OOP parity: **132 images** across three compiler hosts, two targets and
  both accepted pipeline settings.
- Focused semantics and parity: **48 compiled and executed images**, with
  identical output and bytes within each source/target group.
- The benchmark artifacts themselves have eight additional hash checks:
  both baseline targets and the final three compiler hosts on both targets.
- All **53 standard-library source files** match byte-for-byte.

The existing FlowPoint fixture now uses an explicit object annotation so it
continues exercising actual heap member loads/stores. Separate structural
tests cover the newly scalarized typed fields; no heap-path assertion was
removed.

### Full compiler images

Windows Python bootstrap, Windows MLO stage 2, Windows monolithic stage 3,
and Linux-host Windows crossbuild all match:

```text
bytes:  65892864
sha256: acd5f0144d82c37db1a695bdea37a9e02d13239423dbc0b17c74fbd3c293482b
```

Linux Python bootstrap, Windows-host Linux crossbuild and Linux-native
self-build all match:

```text
bytes:  65910960
sha256: 91e639476492811ac62d7458167b0ecbf31fbe29f6e3d492a6ab0bb546d4ac9b
```

These are development artifacts in
`MiniLangCompilerML/build/optimization-2026-11-06/`, with entry images
`final-stage2.exe` and `final-linux-self`. The installed
`build/mlc_win64.exe` was not replaced. Validation-only build timings in
the JSON can overlap other checks and are separate from the isolated
benchmark rows.

## Reproduction and evidence

The raw [measurements and verification manifest](COMPILER_OPTIMIZATIONS_2026-11-06.json)
include commands, all warm-up/measured samples, phase timings, image hashes,
source fingerprints, standard-library hashes and compatibility results.

The runtime comparisons use the common benchmark source and runner from
MiniLangCompilerML for both compiler implementations. Run the commands below
from that repository; its source includes the three-string control workload.

```text
python tests/bench_compiler_optimization.py CONFIG.json REPORT.json --repeats 7 --cpu 4

python benchmarks/compare_runtime_codegen.py BEFORE AFTER --runs 15 --cpu 4 \
  --cases typed-struct-local concat-eight concat-eight-small concat-three struct-local \
  --output runtime.json

python benchmarks/compare_mlo_metadata.py BEFORE AFTER --runs 15 --cpu 4 \
  --output metadata.json
```

For the metadata case, compile identical copies of
`benchmarks/mlo_metadata.ml` from an independent directory, selecting
each version of `mlc/tools.ml` through its include root. The metadata
benchmark and its comparison runner belong to MiniLangCompilerML. Run Linux
benchmark images and the comparison script inside Linux. Ordinary unit,
runtime, incremental and parity runner commands remain documented in the
repository README.
