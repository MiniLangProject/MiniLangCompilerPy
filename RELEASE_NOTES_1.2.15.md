# MiniLang Compiler 1.2.15

This patch release brings bounded code-generation optimizations to both compiler
implementations. Both CLI version flags and compile-time MINILANG_VERSION
report **1.2.15**. No language, standard-library or native-media ABI change.

## Improvements

- Eliminate immediate field projections of small temporary structs when all
  positional arguments are total integer expressions and contracts cannot fail.
  Effectful constructors and escaping objects keep their existing behavior.
- Hoist stable array/bytes roots in dynamic-length loops, retaining bounds
  checks, descending empty-range semantics, GC roots and cancellation polls.
- Reduce operand spills for proven integer arithmetic.
- Share constant runtime-error construction to reduce generated code size,
  retaining error codes, messages, source locations and catchability.
- Specialize integer literals inside existing single-return inline expansions
  without creating additional function copies or removing callable fallbacks.

These are conservative local optimizations, not a general escape-analysis pass,
whole-function register allocator, loop-versioning pass or PGO implementation.

## Evaluation and trade-offs

Twenty-one CPU-pinned, alternating pre-release A/B pairs per workload on Windows
and Linux/WSL measured:

- **94–95% less time** and **16 MB fewer allocations** in the targeted temporary
  struct-projection benchmark.
- **35–39% less time** in the literal-inline arithmetic benchmark.
- **3–5% less time** for the local-register workload; **1–2% less time on Linux**
  and **2.3% less time on Windows** for dynamic indexing.
- About **15.6% smaller compiler binaries**, and **6.5–7.7% smaller benchmark images**.

There is **no universal speedup**. On Windows the caught-error stress benchmark
takes **10.7% longer** and a local-CSE control takes **11.5% longer**. Other
controls also show mixed changes. Shared error construction deliberately trades
an extra cold-path call/frame for much less code. These microbenchmarks are not
whole-application MiniSQL/MiniQuake/HollowKeep performance claims.

See the [evaluation and raw samples](https://github.com/MiniLangProject/MiniLangCompilerPy/blob/v1.2.15/docs/reports/BOUNDED_CODEGEN_2026-10-02.md). That report preserves
pre-version-stamp image hashes; release-stamped artifact checksums are below.

## Validation

- Python regression suite: **156 passed, 0 failed, 0 skipped**.
- Self-hosted suite: **136 core cases passed, 0 failed**, plus the outer
  language/runtime, structure, object-pipeline and smoke checks.
- Code-generation structural checks passed in both implementations.
- All **53 standard-library modules are byte-identical** between repositories.
- Both CLI version flags and compile-time `MINILANG_VERSION` report 1.2.15.
- Version/runtime fixtures execute successfully and have six-way byte parity
  per target across Python, Windows ML and Linux ML hosts, with normal/object
  pipeline options. Python accepts the object option but emits its monolithic
  equivalent.
- Windows Python bootstrap and native selfbuild are byte-identical. Python and
  Windows ML Linux cross-builds are also byte-identical. A full Linux-native
  compiler selfbuild was not repeated for this release.
- MiniDoc compiler reference regenerated: **37 files, 3,285 symbols, 0 warnings**.

The existing native `cstr` return-lowering exception to general byte parity
remains unchanged; see [compatibility scope](COMPILER_PARITY.md).

### Release-stamped compiler checksums

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows `mlc.exe` | 54,494,720 | `4357346D79C3C3D9E3A2D8FB20CAE974C5B94D0A66830B95762B15EBC65AFBBA` |
| Linux `mlc` | 54,497,120 | `D0C73E7CD0CC83BCBB195F2D10E5FD4EAB271F6562452CFD7ADC36A6A9DF42B4` |

Archive checksums are supplied separately as `.sha256` release downloads.

## Downloads

This Python release supplies GitHub source archives. Ready-to-run Windows and
Linux packages are available in the [matching self-hosted release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.15).
