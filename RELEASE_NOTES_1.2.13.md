# MiniLang Compiler 1.2.13

This patch release improves generated-code performance and avoids unnecessary
string allocations in both compiler implementations. Both CLI version flags
and the compile-time MINILANG_VERSION report **1.2.13**.

## Improvements

- Proven integer floor division by positive powers of two uses arithmetic shifts,
  including correct rounding for negative dividends. Zero, negative, dynamic and
  out-of-domain divisors retain the generic path.
- Empty string concatenation, repetition by one and singleton joins reuse
  immutable strings after validation instead of copying. Mutable arrays and
  byte buffers are not shared by this optimization.
- String repetition doubles an initialized prefix instead of copying each
  repetition separately; single-byte seeds use the native fill helper.
- The self-hosted compiler now matches Python's scalar-array classification
  for large integer constants. Later pointer stores retain GC promotion.

## Evaluation

In eleven alternating before/after microbenchmark runs on the same Ryzen 9 9900X,
integer-division workloads took **21–33% less time** and large string repetitions
**76–83% less time** across Windows and Linux/WSL. Three identity workloads each
went from **82,400,000 allocated heap bytes to zero**.

These are targeted workloads, not measured MiniSQL/Quake/HollowKeep speedups.
Control cases show small mixed changes (approximately ±5%), and heap allocation
savings are not equivalent to process RSS savings. See the
[review and raw measurements](https://github.com/MiniLangProject/MiniLangCompilerPy/blob/v1.2.13/docs/reports/RUNTIME_CODEGEN_REVIEW_2026-09-30.md).

## Validation

Regression coverage includes signed-61-bit boundaries, wrapped divisors,
UTF-8/NUL data, scalar/SIMD copy and fill, overflow and error paths, evaluation
order, allocation-free identities, GC safepoints, array promotion and thread
result lifetime. The versioned Python suite passes **155/155** tests; ML passes
**136/136 core tests and 162/162 outer checks**, including Linux execution and
object-pipeline comparisons. Native Linux-host regression and compile-time
version checks also pass.

Python bootstrap and native self-hosted rebuilds are byte-identical on each
platform:

| Compiler image | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows x64 | 65,430,528 | `28EBDED382E66D296254D181D5BAA3E786B1514FC2066E21E0FE53A1CBE47CA2` |
| Linux x64 | 65,437,504 | `7C7AA6D9DD70428419421AD5951B9EA765274A54CFA6C436B34662550268B556` |

The Linux-native self-build ran from an exported source snapshot on the Linux
filesystem; this avoids slow source metadata access through the WSL /mnt/c mount.

Parity claims concern the tested sources and matching options per target;
the previously documented native cstr return-lowering exception remains.
The standard library and native media ABI are unchanged.

## Downloads

This Python compiler release provides GitHub source archives. Ready-to-run
Windows and Linux packages with the matching standard library and media runtime
are available in the [matching self-hosted release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.13).
