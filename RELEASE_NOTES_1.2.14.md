# MiniLang Compiler 1.2.14

This patch release improves generated integer code in both compiler
implementations. Both CLI version flags and compile-time MINILANG_VERSION
report **1.2.14**. No language, standard-library or native media ABI change.

## Improvements

- Replace proven integer floor division by positive non-power-of-two constants
  with exact reciprocal multiplication and correction. Existing power-of-two
  shifts remain; negative, zero, dynamic and wrapped divisors retain checked
  fallbacks. Ordinary / division is unchanged.
- Replace division by ten in native integer decimal formatting with exact
  reciprocal multiplication.
- Reuse identical bounded pure local integer expression trees. Calls, heap
  reads, globals, captures and potentially failing operations are excluded.
- Remove redundant right-operand stack stores/loads and keep literal-right
  operands in registers, preserving evaluation order and GC roots.
- Make Windows bootstrap memory diagnostics explicitly opt-in with
  -BootstrapProbe; -NoBootstrapProbe remains supported and takes precedence.

These are local instruction-selection and temporary-storage improvements,
not a function-wide register allocator or general dead-store elimination.

## Evaluation

Eleven alternating pre-release A/B microbenchmark samples per case on Windows
and Linux/WSL measured **41–54% less time for constant integer division**,
**66–68% less time for repeated local arithmetic** and **53–54% less time for
large integer formatting**. The benchmark Windows image is 2.7% smaller.
A separate compiler fixture took 3.4% less compile time and 1.2% less peak
working set.

Managed allocation counts are unchanged. String controls have small mixed
changes, including slower cases; these are not whole-application speedup
claims. See the [report and raw samples](https://github.com/MiniLangProject/MiniLangCompilerPy/blob/v1.2.14/docs/reports/LOCAL_CODEGEN_OPTIMIZATIONS_2026-09-30.md).
The report preserves pre-version-stamp hashes; release artifact hashes follow.

## Validation

- Release-stamped Python tests: 155 passed, zero failed/skipped.
- Release-stamped ML: 136 core tests and the complete outer suite passed.
- Windows Python bootstrap and native selfbuild are byte-identical.
- Python and Windows-hosted ML produce byte-identical Linux compiler images.
- The release Linux compiler runs under WSL. Version and runtime fixtures
  pass six-way output parity per target: Python, Windows ML and Linux ML,
  each using monolithic and object pipelines.
- Both -version and --version and the compile-time version assertion pass.
- Compiler MiniDoc regenerated: 37 files, 3,283 symbols, zero warnings.
- Standard libraries remain identical: 53 files.

| Compiler image | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows x64 | 64,587,264 | `058924B6ABFF723908CF89F5659898D37E3C1A880E68623A6412B27727757158` |
| Linux x64 | 64,589,648 | `28236D138EEAA9BA79BE3B1C9593CA939927189582DC96201B71EEA19F4E77D1` |

The full Linux-native compiler selfbuild passed before the version-only stamp
and matched both cross-host builds. It was not repeated after the stamp;
release Linux-hosted compilation and execution were tested separately.
That full build took 1,354 seconds including a deliberate measurement pause;
without a matched baseline this is not evidence of a regression or speedup.

Parity is scoped to tested sources and matching per-target options. The
previously documented native cstr return-lowering exception remains.

## Downloads

This Python release provides GitHub source archives. Ready-to-run Windows and
Linux packages are available in the [matching self-hosted release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.14).
