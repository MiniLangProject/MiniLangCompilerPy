# Compiler allocation and emission optimizations — 2026-11-04

This evaluation covers the Python reference compiler and the self-hosted
compiler, starting from version 1.3.2. Changes are in the worktrees; this is
not a release announcement.

Baseline revisions:

- Python: `6ebdddb2a1f9e1ce4089b7de5045f6603826e8a8`.
- MiniLang: `5a2e25421ac4d36e7512ce2ab5e6b6e2814fbcc8`.

## Retained changes

1. **Remove optional tracing from normal Python instruction emission.**
   Only listing-enabled `Asm` instances now intercept attribute lookup.
   Enabling/disabling a listing preserves the instance, subclass state and
   GC spill callbacks. The ordinary path uses Python's normal lookup.
2. **Emit native memory operands directly.** The ML assembler emits ModRM,
   SIB and displacement bytes into its existing output buffer. Twenty-five
   base/displacement emitters no longer create an `EncMem` object and several
   short byte buffers for every instruction. Indexed-address encoding remains
   unchanged. Golden opcodes and displacement-boundary comparisons cover the
   replacement; output bytes are preserved.
3. **Write MLO sections without a second paged copy.** The ML writer borrows
   code/data sections during synchronous output and stages metadata separately.
   Sections of at least 1 MiB bypass the staging buffer; smaller fragments
   remain batched. Short-write handling and the MLO version-2 byte layout are
   preserved. This change is specific to the ML object writer; Python's
   executable-output path and compatibility flags remain unchanged.
4. **Reduce fixed metadata overhead.** Python tokens and assembler records use
   slots. The initial ML leaf arena capacity is 8,192 instead of 65,536;
   binary-node arenas start at 1,024 instead of 4,096. Geometric growth remains
   available for large programs.
5. **Fuse a temporary bytes slice followed by decoding.** Both backends lower
   direct `decode(slice(data, offset, count))` to one string allocation and
   one payload copy. This also benefits partially filled StringBuilder buffers.
   Strict type/bounds checks, negative offsets, argument order and GC roots are
   preserved. The result owns its bytes; subsequent source mutation cannot
   change the string. Explicit encodings and indirect calls retain the existing
   path. This adds no public builtin or syntax.

The new internal helper also exposed a native helper-dispatch boundary issue.
The dispatch ranges now cover all 109 canonical helpers, including `fn_decref`;
a structural regression checks every rank against its dispatch group.

## Measurement method

Windows x64, AMD Ryzen 9 9900X (12 cores / 24 logical CPUs), Python 3.11.9.
Linux execution and native-host checks use Ubuntu under WSL. Windows timing
runners pin themselves and inherited children to logical CPU 4, warm up each
case, reverse case order on alternate rounds, and exclude warm-up samples.

The native self-build comparison uses one frozen compiler source tree for all
variants, with the object pipeline and compiler phase profiling enabled.
All native compiler images use the same runtime settings:

```text
--heap-reserve 4g --heap-commit 512m --heap-shrink
--heap-shrink-min 128m --gc-limit 384m
```

The compiler's own startup policy raises its GC threshold to 3 GiB. These
benchmark settings are deliberately held constant and are not changes to
release defaults. An initial comparison using inconsistent heap settings was
discarded.

`peak_tree_private` is the Windows job's maximum simultaneous committed
private memory across the compiler and its object-pipeline child processes.
It is neither live managed-object size nor physical RAM. Parent-only peaks
would miss the emitter's main allocation load. The JSON also records parent
working-set peaks, CPU time, image sizes and SHA-256 hashes.

Other applications remained active during measurement. Wall times vary, so
the medians describe this machine and these workloads; they are not universal
speedup guarantees. Memory peaks are much more stable.

## Measured results

| Workload / metric | Baseline | Retained | Change |
| --- | ---: | ---: | ---: |
| Python formatter build, median of 7 | 1.909 s | 1.069 s | -44.0% time |
| ML full compiler build, median of 3 | 55.32 s | 54.91 s | -0.7% time |
| ML full build, peak process-tree commitment | 1609.4 MiB | 1427.0 MiB | -11.3% |
| Bytes slice + decode, median of 11 | 56.01 ms | 31.77 ms | -43.3% time |

The full native build's small time difference is within the observed variation.
Treat it as approximately unchanged runtime with **182.4 MiB less peak
commitment**, not as a demonstrated general speedup. Measured ranges were
55.20–56.79 s before and
53.07–66.58 s after. Median job CPU times were
55.09 s and 54.28 s.

The emitter-only variant reached 54.06 s and
1437.4 MiB, accounting for most of the memory saving.
The remaining retained changes save a further
10.3 MiB.
Their small aggregate timing difference is not enough to claim an additional
speedup.

The runtime benchmark makes 150,000 copies of 4,093 bytes. Both images return
checksum 613950000; process commitment remains
49.9 MiB. A separate allocation regression proves one
central allocation for an 8,191-byte fused result instead of the temporary
bytes allocation plus the string allocation. The focused images are
83,968 and 84,480 bytes: the internal helper adds one 512-byte
file-alignment unit here. This is a targeted copying/allocation optimization,
not a claim of smaller programs or faster whole-game frame times.

For 140,001 Python tokens, token records plus their instance dictionaries
decrease from 21,280,152 to 7,840,056 bytes (**63.2%**). This excludes referenced
text/position objects and the token list; it is not a process-memory reduction
of 63.2%. The formatter build's process commitment changes only from
60.07 to 59.68 MiB.

For the native formatter parse (5,891 compact leaves, 1,530 compact binary
nodes), arena backing storage decreases from 1,490,944 to 229,376 bytes
(**84.6%**). Large programs still grow their arenas as required.

The large native measurement input was frozen before rejecting the loop-cost
prototype, so its output is a benchmark artifact, not the final compiler
artifact listed in the validation section. Every compiler variant sees that
same input. Baseline and emitter-only output hashes match exactly. Retained
output differs where the new string-copy lowering applies.

Raw samples and configurations:
[COMPILER_OPTIMIZATIONS_2026-11-04.json](COMPILER_OPTIMIZATIONS_2026-11-04.json).

## Experiments not retained

- **Broader loop-versioning cost model:** a bounded AST cost walk saved only
  16 KiB in the roughly 63 MiB compiler image. The exploratory native medians
  were 56.38 s before and 57.40 s after, with no material peak-memory saving.
  This was not a worthwhile tradeoff; the existing loop gate is preserved.
- **Slots throughout the Python AST:** the isolated prototype preserved
  self-build bytes and saved about 55 MiB of process commitment (3.9%) on a
  full compiler build. The measured pair took 56.74 s without it and 60.61 s
  with it; warm-up runs also showed a slowdown. A smaller formatter build
  saved 4.2% of commitment with essentially unchanged CPU time. This broader
  rewrite was rejected; only fixed-schema tokens/assembler records use slots.
- **Direct writes for every 64 KiB MLO page:** reduced temporary storage but
  increased native write-call overhead. The retained writer batches these
  pages and directly writes only sections at least as large as the 1 MiB
  staging buffer.

These exploratory comparisons are decision evidence, not precision estimates:
the AST prototype has one measured full-build pair, and host load affected
timings in the native experiment matrix.

## Reproduction

The same benchmark runner is included in both repositories:

```powershell
python tests/bench_compiler_optimization.py config.json results.json --repeats 3 --cpu 4
```

The configuration is a JSON list of objects containing `name`, a `command`
argument array, `cwd`, optional `artifact` and optional `timeout` in seconds.
Preserve a baseline compiler and compile the same source tree with both
versions. Use identical runtime flags. The runner includes a warm-up round,
records each measured round, and hashes output artifacts.

For runtime copies, compile `benchmarks/decode_slice.ml` with the baseline and
current compiler, then measure those executables with the same runner using
11 measured rounds. Each execution must print `613950000`. GC diagnostic
counters are intentionally absent from this benchmark so they do not change
the allocation path.

The companion measurement JSON contains raw samples and medians. Additional
local logs and experimental binaries are under the ignored
`MiniLangCompilerML/build/optimization-2026-11-04/` directory.

## Correctness and binary identity

Final-source validation completed successfully:

- Python unified suite: **221 passed, 0 failed, 0 skipped**.
- Python unit tests: **44 tests**, no failures; the optional NASM cross-check
  is the single skipped test.
- Native compiler harness: **138 passed, 0 failed**.
- Native outer suite: **245 successful steps**, including Windows and
  WSL Linux execution, formatter checks, opcode boundaries, GC and threads.
- Incremental builds: **96 checks per target**, covering Python and both
  native pipelines, changed inputs, option invalidation, corrupt caches and
  project-manifest cache hits.
- Binary parity: **132 OOP images plus 24 focused decode/slice images** across
  Python, native Windows ML and native Linux ML hosts, both target systems and
  pipeline flags. All six images in each fixture/target group match.
- Compiler-technique, code-generation structure and all **109 helper dispatch
  ranks** pass. The 26-workload runtime-codegen benchmark image remains
  byte-identical to the baseline, so unaffected generated code is preserved.
- Both standard libraries contain **53 byte-identical MiniLang files**.

The strengthened allocation test checks both heap growth and the central
allocation-request counter, preventing free-block reuse from hiding an
intermediate allocation. It also exercises invalid values, negative offsets,
zero-length ranges, UTF-8/NUL payloads, explicit encodings, first-class calls,
left-to-right evaluation, GC between arguments and StringBuilder snapshot
independence. A separate two-worker test stresses shared-heap collection while
workers construct and copy private byte buffers.

Full self-hosting agrees as well: the Python-built Windows compiler, the
Windows-native self-build through MLO, and a full Windows-target self-build
performed by the new Linux-native compiler are all **65,842,688 bytes** with
the same SHA-256:

~~~text
72bb0fb9bd181fadcfdf33ac1101475533643ce46947ee70c8816f977241ff4c
~~~

This also exercises the revised MLO writer on both native host OSes with the
full compiler workload. Binary comparisons always use the same target:
Windows PE and Linux ELF executables are intentionally different formats.

The standard-library trees remain byte-identical. Installed compiler artifacts
and GitHub releases are not replaced by this evaluation.
