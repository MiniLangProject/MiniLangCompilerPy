# Code-generation compaction and executable packing

Date: 18 October 2026. **Pre-release measurement checkpoint**, still reporting
version 1.2.20. Baseline source heads: Python `fd5792b`, MiniLang `a8a05e1`.
These changes are included in [release 1.2.21](../../RELEASE_NOTES_1.2.21.md).
The measurements and hashes below retain the original pre-version-bump build;
see the [release manifest](release-1.2.21-version-matrix.json) for shipped binaries.

## Result and scope

Both backends implement the four optimizations below, with matching native
output in the verified matrix. Optional UPX packing produces much smaller PE
and ELF files and provides byte-exact explicit restoration.

The strongest measured runtime/memory improvement is nonescaping local struct
replacement. Register expansion is essentially neutral on the supplied tests;
it is deliberately cost-gated. These results do **not** establish that every
program becomes faster or smaller. Packing is a file-size trade-off, not a
managed-heap optimization.

## Implemented optimizations

1. **Bounded forward branch relaxation.** The last unresolved forward branch
   can become rel8 when its target is within 127 payload bytes; a branch to
   immediate fallthrough is removed. Intervening labels and trailing call/RIP
   relocations are rebased. Other branches end the candidate window. This is
   bounded local relaxation, not an iterative whole-program layout algorithm.
2. **Conservative unused native bodies.** Count ASCII tokens across every
   loaded source, including comments and strings. Remove a function's native
   body only when its name occurs exactly once, as a declaration. Keep main,
   methods, generated names and profiling builds. Missing source disables the
   proof. Discarded bodies still undergo lowering for diagnostics and canonical
   metadata/budget effects; their static data is retained. Unreachable cycles
   and broadly referenced unused functions are not eliminated. This does not
   restore the previously unsafe inline-fallback pruning.
3. **Primitive register mirrors and lifetime reuse.** Up to six preserved
   XMM6-XMM11 homes for proven int/bool locals, with canonical stack stores
   retained. Lifetimes cover whole top-level statements, including all loop
   iterations. Additional/reused homes need at least three explicit loop reads
   per write, and cannot be induction variables. Unknown syntax or more than
   4096 visited AST nodes falls back to the original two-home policy. This is
   not a general SSA register allocator or pointer-only register storage.
4. **Local struct scalar replacement.** Replace a unique unconditional local
   constructor with 1-8 rooted field slots when every subsequent use is a
   known member read/write. Only untyped fields and complete positional
   constructors qualify. Aliases, object returns, reassignment, closures,
   reflection, typed guards/default/named calls and uncertain syntax keep the
   existing allocation path. Argument order and field liveness through GC are
   preserved; this does not change the shared-heap/GC model.

The register gates matter: the initial ungated expansion slowed simple
single-read accumulator loops. The final policy keeps those cases essentially
neutral rather than treating more registers as an automatic performance win.

### Layout follow-up

Shorter code shifted one Linux integer loop to an unfavorable instruction
alignment. An independent 21-pair repeat reproduced roughly 12% slowdown.
Counted-loop headers now receive at most 15 entry-only NOP bytes on the ELF
target. The final whole-suite sample puts that case within 1% of the baseline.

The same alignment policy regressed the Windows layout (roughly 29% in that
case), so **PE deliberately retains its previous loop policy**. Alignment uses
the canonical object-stream base, not a fragment-local offset, so MLO and
monolithic output remain identical. The nonzero-origin assembler regression
guards the mismatch caught during development.

Additional fixes found while validating this change:

- Pop relocations correctly across sealed 256-record and second-level chunk
  boundaries; the initial relaxation implementation could overwrite a call.
- Treat the ML parser's zero-valued bare-return child like Python's absent child.
- Keep Python's synthesized deferred cleanup in its function/package context.
- Refresh the Linux runtime blob, ordered labels, external relocations and the
  native runner's fixed-layout expectations. The canonical gate reports
  2015 bytes, 66 labels and three external relocations.

## Correctness and binary parity

Final checks:

- Python unified suite: **177 passed, 0 failed, 0 skipped**.
- ML suite: **138 core tests and 230 outer checks passed**.
- Focused Python modules: 5 packing tests, 3 compaction tests, 13 assembler
  tests (one optional NASM comparison skipped because it was not enabled).
- Native opcode tests include zero/127/128-distance edges, 64-KiB code seams,
  255/256/16383/65535 relocation boundaries and nonzero alignment origins.
- Shared fixtures cover typed constructor errors, escaped/reassigned objects,
  object returns, GC-rooted scalar fields, six mirrors across GC, disjoint
  lifetime reuse, deferred package resolution and unused-body diagnostics.
- Windows-host integration: three fixtures on Windows and Linux, compared
  between Python, ML monolithic and ML MLO; packed execution, compile-time
  packing, cross-compiler packed bytes and exact restoration all pass.
- Linux-native integration: the same three Linux fixtures, both pipelines,
  Python reference and Linux UPX, all pass.
- Corrupt/rechecksummed metadata, record boundaries, overlapping/trailing
  records, existing destinations, unsuitable tools, double packing and cleanup
  are covered. Failed compile-time packing retains its valid unpacked output.
- All **53 files** under the two `std` trees are byte-identical; std is unchanged.
- Whitespace checks and the canonical Linux-runtime-blob gate pass.

### Full compiler fixed point

| Target | Full-compiler builds compared | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Windows x64 | Python bootstrap, Windows ML MLO selfbuild, Windows ML monolithic selfbuild | 56576512 | `5054f258b3859c2bf70bbb4fab08cb2a22ab14d75ce39862a5294e482c0a5e9f` |
| Linux x64 | Python crossbuild, Windows ML MLO crossbuild, Linux-native monolithic selfbuild | 56586912 | `d478819d6547b193409ba7a6d83129b5afc714500e937239f5baf0fe367a8228` |

These are exact file comparisons for each target/configuration, not PE/ELF
equality or a proof for every possible MiniLang program. Both packed compiler
images also compiled and ran the optimizer fixture successfully; explicit
restoration reproduced the full-compiler hashes above.

Self-host validation wall times were about 90 seconds (Windows MLO), 166 seconds
(Windows monolithic) and 185 seconds (Linux monolithic). The Linux selfbuild's
peak RSS was 1,792,704 KiB. These builds overlapped other checks; treat the times
as validation observations, not an isolated before/after compiler benchmark.

## Runtime and allocation measurements

Host: AMD Ryzen 9 9900X, Windows build 26200 and Linux through WSL2. Each target
was measured separately with warm-up, **11 alternating A/B pairs**, logical-CPU
4 affinity, matching output checksums, workload-only monotonic timing and
per-process peak working set/RSS. Other development processes were active on
the workstation; small differences should not be generalized. WSL results are
not bare-metal Linux measurements.

The preserved pre-change native compiler built the baseline; the current
Python compiler built the comparison. The new native backend's benchmark image
was checked against Python bytes. All final Windows/Linux benchmark images
were rechecked after the final source changes.

The local-struct case performs 500,000 calls and disables collection only for
this bounded measurement. Heap-frontier growth drops from **16,000,000 bytes
to zero** on both targets. Peak process memory changes from
22.05 to
6.75 MiB on Windows, and from
16.50 to
1.13 MiB on Linux.
Rooted stack fields replace these allocations; this is not a measurement of
lower memory for escaping objects.

Times below are medians in milliseconds; negative change is faster.

| Workload | Windows before | Windows after | Change | Linux before | Linux after | Change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| struct-local | 8.001 | 4.431 | -44.61% | 8.083 | 4.973 | -38.47% |
| many-registers | 79.556 | 80.082 | 0.66% | 88.955 | 89.447 | 0.55% |
| register-dependent | 40.524 | 40.689 | 0.41% | 45.813 | 46.023 | 0.46% |
| struct-projection | 0.472 | 0.471 | -0.25% | 0.850 | 0.657 | -22.74% |
| dynamic-index | 21.268 | 21.238 | -0.14% | 24.146 | 24.487 | 1.41% |
| local-register | 11.389 | 11.456 | 0.59% | 12.926 | 12.932 | 0.04% |
| inline-literal | 3.150 | 3.136 | -0.45% | 3.633 | 3.717 | 2.30% |
| cold-errors | 2.073 | 2.092 | 0.91% | 2.623 | 2.540 | -3.20% |
| division | 60.840 | 60.647 | -0.32% | 69.211 | 70.370 | 1.68% |
| division-constants | 24.578 | 24.596 | 0.07% | 27.684 | 27.778 | 0.34% |
| division-wide | 57.037 | 56.439 | -1.05% | 61.390 | 62.386 | 1.62% |
| local-cse | 6.944 | 6.917 | -0.40% | 7.825 | 7.779 | -0.58% |
| integer-format | 24.193 | 24.192 | -0.00% | 27.865 | 28.222 | 1.28% |
| integer-format-small | 6.986 | 6.785 | -2.87% | 8.240 | 8.053 | -2.27% |
| repeat | 4.715 | 4.695 | -0.43% | 9.044 | 9.067 | 0.25% |
| repeat-one | 0.080 | 0.075 | -6.84% | 0.217 | 0.206 | -5.16% |
| concat-empty | 0.104 | 0.098 | -5.97% | 0.239 | 0.235 | -1.61% |
| join-one | 0.091 | 0.090 | -1.21% | 0.239 | 0.229 | -4.11% |
| concat-control | 7.466 | 7.491 | 0.34% | 17.349 | 18.090 | 4.27% |
| concat-small-control | 8.946 | 8.744 | -2.26% | 10.768 | 9.804 | -8.95% |
| repeat-two-control | 7.455 | 6.936 | -6.95% | 8.462 | 8.079 | -4.53% |
| repeat-two-multi-control | 9.156 | 9.386 | 2.50% | 10.162 | 9.375 | -7.74% |
| join-control | 3.009 | 3.006 | -0.11% | 3.153 | 2.959 | -6.16% |

Most arithmetic/register controls are close to neutral. Some controls are
slightly slower, while sub-millisecond percentage differences are particularly
sensitive to noise and layout. No MiniQuake, Hollowkeep or MiniSQL application
performance claim is made by this report.

The complete benchmark image changes from 183,808 to 182,784 bytes on Windows.
Linux remains 194,464 bytes after file-segment rounding and alignment.

### Compiler cost and a representative tool

A separate seven-pair monolithic build of the same `tools/mlfmt.ml` source
measured the following medians:

| Metric | Before | After |
| --- | ---: | ---: |
| Compile wall time | 1.151 s | 1.190 s |
| Compiler peak working set | 146.44 MiB | 154.61 MiB |
| Generated formatter image | 1707520 bytes | 1537024 bytes |

Thus the formatter image is about 10% smaller, but the extra analyses have a
measured compile-time cost of 3.33%
and peak-working-set cost of 5.58%
in this sample. An earlier five-pair run was nearly time-neutral. We do not
claim a universal compiler speed or compiler-memory improvement.

## Packing measurements and trade-offs

UPX **5.2.1**, with fixed `--best --no-lzma --overlay=copy` options plus
`--no-env --no-progress`. The compiler runs test/unpack verification before
publishing, and appends deterministic MiniLang restoration metadata.

| Full compiler | Unpacked | Packed, including metadata | File reduction |
| --- | ---: | ---: | ---: |
| Windows x64 | 56576512 | 5846584 | 89.67% |
| Linux x64 | 56586912 | 5847444 | 89.67% |

Packed SHA-256:

- Windows: `4ee2edfe8563c9b5745e4c9b45ebdb2e132a8cb73d59f9cb8b1e2820634ac294`
- Linux: `3dca72a32f09513deccd50da3044392f12c0f521eee45ced935ff952cd6f4e9f`

Eleven-pair warm `-version` startup measurements include process startup and
decompression, not a long-running application workload:

| Metric | Windows unpacked | Windows packed | Linux unpacked | Linux packed |
| --- | ---: | ---: | ---: | ---: |
| Median wall time | 8.58 ms | 61.21 ms | 6.23 ms | 76.29 ms |
| Peak working set/RSS | 6.73 MiB | 60.57 MiB | 1.31 MiB | 58.88 MiB |

OS caching/prefetch affects these numbers. The packed loader touches code pages
that an unpacked short-lived process may never need, so the smaller disk file
can consume **more** resident/private memory. Packing also costs additional
build time (especially `--best` for a 56-MB compiler). It remains opt-in.

See the [packing guide](../EXECUTABLE_PACKING.md) for commands, atomic
publication, dependency requirements, format limits, signing and scanner
caveats. CRC32 detects corruption, not malicious replacement.

## Reproduction and artifacts

From the ML repository, with the sibling Python checkout:

```powershell
python ../MiniLangCompilerPy/tests/run_tests.py
pwsh -File scripts/run_tests.ps1 -Compiler build/mlc-compact-final.exe
python scripts/check_linux_runtime_blob.py
python tests/check_compaction_packing.py --compiler build/mlc-compact-final.exe --reference ../MiniLangCompilerPy/mlc_win64.py --upx C:/Tools/upx.exe --linux
python benchmarks/compare_runtime_codegen.py BEFORE.exe AFTER.exe --runs 11 --cpu 4 --output build/runtime-comparison.json
python benchmarks/compare_compiler_codegen.py BEFORE-COMPILER.exe AFTER-COMPILER.exe tools/mlfmt.ml --include . --runs 7 --output build/compiler-comparison.json
python benchmarks/compare_executable_startup.py UNPACKED.exe PACKED.exe --output build/startup-comparison.json
```

The benchmark requires genuinely preserved before/after binaries; compiling
both with the current compiler is not a valid before/after comparison.
Run Linux measurements inside Linux with ELF paths and the same runner.

[Machine-readable medians, manifests and packing matrix](codegen-compaction-and-packing-2026-10-18.json)
are stored in both repositories. Full local samples/logs are under `build/`;
the compiler sources, tests and measurement scripts are the reproducible inputs.

Verified new native images are `build/mlc-compact-final.exe` and
`build/mlc-compact-final-linux`, with separate `-packed` variants. The usual
`build/mlc_win64.exe` was being used by a concurrent MiniRedAlert build, so
the existing default compiler paths were deliberately **not replaced**.
No other project's source or active build was changed.

A large exploratory monolithic label-dump run was stopped while exporting its
diagnostic listing; normal no-dump selfbuilds above completed. Large diagnostic
exports are not included in the compiler timing comparisons.
