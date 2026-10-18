# MiniLang Compiler 1.2.21

This release adds conservative native-code compaction, bounded register reuse,
local struct scalar replacement, and optional executable packing in both
compilers. Windows x64 PE and Linux x64 ELF remain supported. Both version flags
(`-version`, `--version`) and compile-time `MINILANG_VERSION` report **1.2.21**.

## Code generation

- Shorten eligible local forward branches and eliminate immediate fallthrough
  jumps. Rebase labels and relocations, including chunk-boundary cases.
- Omit native function bodies only when their names are proven unreferenced
  across all loaded source. Preserve diagnostics, metadata and inline fallbacks.
- Reuse up to six primitive register mirrors across disjoint conservative
  lifetimes. Gate extra registers by loop-use profitability; retain stack roots.
- Replace nonescaping, untyped local structs with rooted stack field slots.
  Aliases, escaping objects, typed guards and uncertain cases keep allocations.
- Align Linux counted-loop headers using the canonical object-stream position.
  Windows retains its existing layout, which performed better in measurements.
- Fix native bare-return analysis, Python deferred-cleanup namespace context and
  native chunked relocation removal; refresh the canonical Linux runtime blob.
- Include the post-1.2.20 concurrent-GC snapshot improvements: fewer free-list
  passes and bounded skipping of empty bitmap spans.

No language feature is removed. These optimizations deliberately fail closed
when their safety conditions cannot be established.

## Optional packing and exact unpacking

Both compiler CLIs support the same workflows:

```text
compiler app.ml app.exe --pack --upx PATH_TO_UPX
compiler --pack-exe app.exe app-packed.exe --upx PATH_TO_UPX
compiler --unpack-exe app-packed.exe app-restored.exe --upx PATH_TO_UPX
```

For Linux output, add `--target linux-x64` when compiling. Use a trusted
host-compatible **UPX 5.2.1** executable; `MINILANG_UPX` is an alternative to
`--upx`. UPX is optional, is not bundled, and is never downloaded automatically.
The packed program decompresses at startup without an installed UPX tool.

Validated restoration metadata preserves byte-exact explicit unpacking,
including PE bytes normalized by UPX. Publication uses private staging and an
atomic final operation; standalone packing refuses to overwrite destinations.
Checksums detect corruption, not malicious modification.

Packing remains **off by default**. It reduces file size, not the managed heap,
and can increase startup time and peak memory. Antivirus false positives are
possible. Sign only after packing; appended signatures are outside the exact
unpack contract. The distributed compiler binaries are deliberately **unpacked**.
See the [packing guide](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.21/docs/EXECUTABLE_PACKING.md).

## Measurements

The [11-pair Windows/Linux evaluation](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.21/docs/reports/CODEGEN_COMPACTION_AND_PACKING_2026-10-18.md)
uses the pre-version-bump checkpoint, not new release-package timing samples:

- The nonescaping local-struct workload is **44.6% faster on Windows** and
  **38.5% faster on Linux**, with measured managed allocation falling from
  **16,000,000 bytes to zero** for 500,000 calls.
- Most other arithmetic/register controls are approximately neutral; some
  small regressions remain. This is not a claim that every program is faster.
- The formatter benchmark output is about **10% smaller**; compilation takes
  about **3.3% longer** and peaks about **5.6% higher** in the seven-pair run.
- Optional packing reduces the full compiler from roughly **56.6 MB to 5.85 MB**
  (about **89.7%**). Warm `-version` startup increases from roughly 8.6 to 61.2 ms
  on Windows and 6.2 to 76.3 ms on Linux, with higher peak memory.

Linux measurements use WSL2, not bare-metal Linux. Full Hollowkeep gameplay and
the extended 1.2.20 memory matrices were not rerun for this release.

## Release validation

- Python suite: **177 passed, 0 failed, 0 skipped**.
- ML suite: **138 core tests and 230 outer checks passed**.
- Focused tests: 5 packing, 3 compaction and 13 assembler tests; the optional
  external NASM comparison is the single skipped assembler check.
- Full Windows Python bootstrap, native MLO stage 2 and native monolithic
  stage 3 match byte-for-byte. Python Linux output, Windows ML MLO crossbuild
  and Linux-native monolithic selfbuild likewise match.
- Both version flags and compile-time version checks pass on all three hosts;
  twelve version/runtime images have six-way byte equality within each target.
- Nine Windows/Linux compaction/packing configurations pass, including
  monolithic/MLO/reference equality, packed execution and exact restoration.
- Both full release compilers also start and compile the optimizer fixture
  successfully after packing, and explicitly unpack to their original bytes.
- All **53 std modules** and **351 std reference files** match between repos.
- MiniDoc documents **40 compiler source files and 3,361 symbols**, with no
  warnings for the Windows documentation build. Linux-target documentation
  also passes with **41 files, 3,363 symbols and zero warnings**.
- The canonical Linux runtime blob check passes.

See the [release-stamped verification manifest](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.21/docs/reports/release-1.2.21-version-matrix.json).
Equality is per target/configuration, not between Windows PE and Linux ELF;
tested cases cannot prove equivalence for every possible program.

## Downloads and executable checksums

The Python repository remains source-only. Ready-to-run native packages are
available from the [ML compiler release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.21).
Each includes the matching standard library, native-media bridge, examples,
packing guide and source-revision manifest. Archive SHA-256 sidecars accompany
both downloads; the table identifies the unpacked compiler inside each archive.

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows `mlc.exe` | 56,576,512 | `68BC63C79F7CE5B50B750652BAAEFDFCB808EA1BD825280B927A143D8EA0BEBE` |
| Linux `mlc` | 56,586,912 | `6C28B63B871DCEC6263CE0102B049FD67E02CDC361809796421D8EBAA87005FD` |
