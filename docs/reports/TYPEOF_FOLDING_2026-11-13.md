# Type-query optimization and correctness — 13 November 2026

MiniLang 1.3.5 integrates the direct `typeof` comparison optimization from the
parallel compiler checkouts. The draft was not safe to release unchanged.
This report records the repairs, release gates and measurements against the
frozen 1.3.4 release. Raw samples and source hashes are in the
[JSON record](TYPEOF_FOLDING_2026-11-13.json).

## Findings and fixes

1. **Qualified type lookup:** the draft Python fold used a second, incomplete
   name resolver. Nested namespace/import type names could fail or generate
   different bytes. Both implementations now share their builtin resolver with
   the comparison optimization and the type-query analysis pass. Type-only
   declarations remain valid even when their unused constructor is pruned.
2. **Inline error boundaries:** an inlined callee inherited its caller's
   `try(...)` suppression. Failed parameter/body/return contracts could continue
   with an error object as a normal value. Each inline expansion now owns its
   suppression and synchronization depth and flushes its deferred error blocks
   before restoring the caller's return target. Argument order remains unchanged.
3. **Shadowed members:** native type queries and member loading could interpret
   a parameter's field as a namespace declaration. Python's enum/static member
   paths had the same missing local-binding guard. Both preserve dynamic reads
   when a local/parameter shadows a declaration. Native enum variants are emitted
   as immediate values before attempting a global-binding load.
4. **Previous parity repair:** the parallel drafts preceded the 1.3.4 fix for
   loop-use counts in else-if and switch expressions. Integration starts from
   1.3.4 and retains that repair and its regression coverage in both repositories.

The old release can also reproduce the inline error bug at a cold first call;
the smaller optimized code merely made it easier to trigger within the inline
budget. The fix is independent of how many calls were compiled earlier.

## Optimization and coverage

Direct `typeof(expr) == "primitive"` and `!=` comparisons, in either operand
order, use value tags and object headers instead of calling `fn_typeof` and
comparing type-name strings. Known types and nominal type identifiers retain
the builtin fast paths. `expr` is evaluated once, with existing error semantics.

- `tests/typeof_literal_checks.ml`: 23 representative values × 11 literals ×
  two operators × two operand orders = **1,012 comparisons**, plus side effects,
  root type names and thread lifecycle checks. Includes boxed/immediate floats,
  mutable/immutable arrays, closures, builtin functions, errors and unknown tags.
- `tests/typeof_named_argument_error.ml`: optimized comparisons preserve the
  normal diagnostic for invalid named builtin arguments. An additional 36
  negative checks cover generic calls and both comparison orders across all
  three compiler hosts, both targets and both pipeline modes.
- `tests/type_query_resolution.ml` and its imported fixture: nested namespaces,
  aliases, enum types/variants, shadowing and both `typeof`/`typeName`.
- `tests/typeof_declared_call.ml`: a declared function with this spelling keeps
  ordinary default/named-argument normalization and ordered effects. The fold
  accepts only resolved builtin calls. Native indirect calls to declarations
  with builtin spellings now keep arguments rooted until callee evaluation has
  finished; reusing released argument slots previously corrupted these calls.
- `tests/inline_error_boundaries.ml`: cold and late inline calls, named/default
  arguments, ordered effects, parameter/body/return failures, nested `try`,
  passed error values, synchronized cleanup and another thread's progress.
- All 227 Python integration checks, 45 unit tests (one optional NASM skip),
  143 native harness tests and 257 native outer steps pass.
- 156 focused images and 132 OOP images agree byte-for-byte per target across
  Python, Windows-native and Linux-native hosts, with and without MLO.
- 96 incremental checks per target pass. All 53 std sources and 351 generated
  std documentation files are identical. MiniDoc reports zero warnings.

The compiler-techniques gate also verifies profiling/PGO and corrupted-cache
recovery. Its PGO workload now uses 64 call sites: the optimized guards made
the old 12-site workload fit entirely within the ordinary inline budget, so
that workload no longer tested whether PGO increased the budget.

Seven complete compiler builds, including bootstrap, native self-hosting and
cross-host/target builds, reach a fixed point per target. Final rebootstrap
checks reproduce those hashes. See the [version matrix](release-1.3.5-version-matrix.json).

## Compiler time and memory

Both versions compile the **same final 1.3.5 compiler source**, with
`-I . --heap-reserve 4g --heap-commit 512m --heap-shrink --heap-shrink-min 128m --gc-limit 384m`. Native uses MLO; Python uses the monolithic path.
One warm-up round precedes three measured rounds, reversing execution order
between rounds. The runner and children inherit logical CPU affinity 4.

| Compiler | Before median | After median | Time change | Before peak tree commitment | After peak tree commitment |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native ML (MLO) | 76.10 s | 43.54 s | -42.8% | 1431.8 MiB | 1410.8 MiB |
| Python | 58.36 s | 64.26 s | +10.1% | 1414.5 MiB | 1366.9 MiB |

Native ML (MLO) ranges: 67.78–92.73 s before; 42.59–61.68 s after.
Python ranges: 51.68–70.05 s before; 48.47–66.01 s after.

Paired per-round time changes: native ML -44.0%, -35.8%, -33.5%;
Python -16.9%, +24.3%, -5.8%.
Native ML is faster in every measured pair. Python's aggregate median is
+10.1% higher,
but the paired changes reverse direction. This run establishes no consistent
Python compile-time improvement and does not rule out a smaller regression.
The raw median must not be presented as an isolated, repeatable compiler effect.

Peak tree commitment is the Windows job's peak private committed memory,
not physical RAM and not a sum of unrelated process peaks. The JSON includes
CPU time and peak working set. Other user builds were active during this work;
affinity does not reserve a CPU. Three samples cannot establish a small speed
change reliably. These are local measurements, not a performance guarantee.

The same-source Windows compiler image changes from **66,146,304** to
**63,586,816 bytes** (-3.87%). Version-to-version
published image sizes also include source changes and are not the same comparison.

## Generated-program runtime

`benchmarks/typeof_checks.ml` runs 40 million iterations of tag checks, object
header checks and valid typed inline calls, plus 120 million integer-control
iterations. The runner warms each image and alternates order for 15 measured
runs per case. Windows uses QPC; Linux uses `CLOCK_MONOTONIC`. Checksums agree.
The fixed benchmark image is byte-identical when built by Python or ML.

| OS | Workload | Before median ms | After median ms | Time change | Before / after managed heap delta |
| --- | --- | ---: | ---: | ---: | ---: |
| windows | tag | 197.53 | 81.45 | -58.8% | 24 / 24 |
| windows | header | 562.25 | 96.73 | -82.8% | 24 / 24 |
| windows | guard | 201.27 | 119.05 | -40.9% | 24 / 24 |
| windows | control | 270.28 | 270.48 | +0.1% | 24 / 24 |
| linux | tag | 196.63 | 81.70 | -58.4% | 24 / 24 |
| linux | header | 586.19 | 98.45 | -83.2% | 24 / 24 |
| linux | guard | 198.03 | 115.61 | -41.6% | 24 / 24 |
| linux | control | 278.04 | 277.27 | -0.3% | 24 / 24 |

Heap deltas measure bump-pointer growth, not cumulative allocation or RSS.
Per-process peak working sets are recorded separately in the JSON. The workload
control helps expose machine drift. The optimization benefits matching generated
code in both compilers; these targeted loops do not predict whole-game or server
speedups. No end-to-end HollowKeep/MiniSQL claim is made by this release.

## Reproduction

Use `python tests/run_tests.py` in the Python repository and
`scripts/run_tests.ps1 -Compiler <compiler>` in the ML repository. The latter
also checks the new fixtures on Linux through WSL. For runtime comparisons,
compile `benchmarks/typeof_checks.ml` with each preserved compiler, then run
`python benchmarks/compare_typeof_checks.py <before> <after> --runs 15 --cpu 4 --output results.json`
inside each target OS. Compiler measurements use `tests/bench_compiler_optimization.py`
with the commands recorded in the JSON, three measured rounds and CPU 4.
