# MiniLang Compiler 1.2.16

This patch release improves the shared managed-heap runtime in both compiler
implementations. Both CLI version flags and compile-time `MINILANG_VERSION`
report **1.2.16**. Standard-library and native-media ABIs are unchanged.

## Memory management

- Add allocation-free `gc_stat(index)` diagnostics with 15 scalar counters.
  Invalid indices/types return `void`. Hot diagnostic accounting is omitted
  when application code does not reference the builtin, including indirectly.
  Individual concurrent reads are supported; several reads are not a snapshot.
- Adapt default collection thresholds to retained live block bytes, within
  fixed bounds. Explicit CLI/runtime limits and disabled periodic GC retain
  their previous behavior; allocation-failure collection remains available.
- Accelerate small single-thread allocations when the free list is empty,
  and avoid repeated unsuccessful free-list searches with an invalidated cache.
- Mark reference-free leaf objects without adding them to the tracing worklist.
  Reserve the 64-MiB worklist separately and initially commit only 64 KiB,
  growing on demand instead of committing the entire worklist at startup.
- With `--heap-shrink`, discard full interior dead pages while preserving
  allocation metadata, free-list links and live neighbors. Windows uses a
  discard hint; Linux uses `MADV_DONTNEED`. Top-trim accounting changes only
  after a successful OS operation; Linux decommit errors are propagated.
- Remove an unused recursive ML helper, correct runtime comments and verify
  Linux runtime label emission order.

This retains the shared heap, per-thread stacks/TLABs and stop-the-world
mark/sweep collector. It is not a moving, generational or concurrent collector,
nor a complete size-class allocator. Shared-object writes still require
appropriate synchronization.

## Evaluation and trade-offs

The pre-version-stamp Windows and Linux/WSL A/B measurements show:

- **75–83% less time** in fragmented, unsuccessful-fit allocation workloads.
- **44–46% less time** with a large retained live graph and repeated allocations.
- **16–18% less time** in the leaf-marking benchmark.
- Approximately **64 MiB less Windows commit charge** for the small control,
  not 64 MiB less resident RAM.
- Linux interior-hole RSS falling from **66.00 to 2.06 MiB** after collection
  with heap shrinking enabled. Windows' discard hint did not produce an
  equivalent immediate working-set reduction.

There is **no universal speedup**: small allocation churn takes **2.4% longer
on Windows and 6.8% longer on Linux**, and reference-graph marking about **3%
longer**. Threaded cases show no throughput gain. Adaptive GC keeps more
temporary heap in the retained-live case (80 to 96 MiB final committed heap,
about 10 MiB more peak RSS). Compiler binaries are approximately 1% larger.

See the [evaluation and raw samples](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.16/docs/reports/MEMORY_MANAGEMENT_2026-10-03.md).
Those measurements preserve pre-version-stamp hashes. They are targeted
microbenchmarks, not new MiniSQL, MiniQuake or HollowKeep performance claims.

## Validation

- Python full regression suite: **158 passed, 0 failed, 0 skipped**.
- Self-hosted suite: **136 core cases passed, 0 failed**, plus outer
  language/runtime, object-pipeline, codegen and smoke checks.
- Supplemental memory-policy, first-class diagnostics, page-purge, TLAB and
  safepoint runtime matrices pass on Windows and Linux/WSL.
- **96 memory-fixture images** match byte-for-byte per target/configuration
  across Python, Windows ML and Linux ML hosts and both pipeline options.
- Version/runtime fixtures execute successfully with six-way parity per target;
  both CLI flags and compile-time version values report 1.2.16.
- Windows Python bootstrap and native selfbuild are byte-identical. Python and
  Windows ML also produce byte-identical Linux compiler images.
- A full Linux-native selfbuild passed before the version-only stamp; it was
  not repeated afterward. Release-stamped Linux compilation/runtime fixtures
  were rechecked.
- All **53 standard-library modules are byte-identical** between repositories.
- Structural codegen and canonical Linux runtime-blob checks pass.
- MiniDoc compiler reference: **37 files, 3,287 symbols, 0 warnings**.
- Extracted Windows/Linux binary packages pass version, standard-library import
  and managed-memory smoke checks; manifests and archive checksums are verified.

The [memory parity manifest](docs/reports/release-1.2.16-memory-parity.json)
and [version matrix](docs/reports/release-1.2.16-version-matrix.json) preserve
the release-stamped fixture hashes.

Python accepts the object-pipeline option but emits its monolithic equivalent.
The existing native `cstr` return-lowering exception to general byte parity
remains unchanged; see [compatibility scope](COMPILER_PARITY.md).

### Release-stamped compiler checksums

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows `mlc.exe` | 55,015,936 | `0BB6AF2112F74DFF0E4EEC0584434B2174F5ACA45C852018875F711A891C959A` |
| Linux `mlc` | 55,017,456 | `986044376AD1BC6E625E5424607C876C5471991045A3E616D27672EED4BFE1C5` |

Archive checksums are supplied separately as `.sha256` release downloads.

## Downloads

This Python release supplies GitHub source archives. Ready-to-run Windows and
Linux packages are available in the [matching self-hosted release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.16).
