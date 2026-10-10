# Concurrent GC parity and evaluation 10 October 2026

Both compiler implementations support the Windows background collector and
produce identical executables for the configurations checked below. Python
previously lacked ML's new collector, barriers, options and asynchronous
builtin. This report records the development verification above 1.2.18, before
the release version bump. Release-stamped binaries, hashes and validation are
documented separately in the [1.2.19 release notes](../../RELEASE_NOTES_1.2.19.md).

## Implementation and corrections

Python now emits the same SATB worker, request/completion protocol, recursive
heap-lock handoff, overflow retention, free-list publication, thread context
layout, statistics and write barriers as ML. Barriers cover array/member stores,
captured-variable boxes, Thread references and `copyArray`. Helper ordering and
relocations preserve monolithic/MLO parity.

`gc_collect_async()` supports direct and first-class calls. Concurrent builds
coalesce requests with an active cycle; otherwise each call performs one
synchronous collection, on Windows and Linux. Incorrect direct-call arity is
now rejected by Python at compile time, matching ML, instead of falling through
to an indirect runtime call. Log-size limits use the shared checked size syntax
and clamp to 64 bytes through 64 MiB.

Python's ordinary call hook spills expression roots relative to RSP. SATB
barriers temporarily push registers, so using that hook inside a barrier would
address the wrong stack slots. The nonallocating, register-preserving leaf call
bypasses only that hook, retains helper tracking, and restores the hook even on
emission failure. Dedicated unit tests cover these invariants. Generic
RIP-relative LEA has independent low/high-register and relocation tests in
addition to the synchronized 233-vector opcode catalog.

The collector remains optional and Windows-target-only. Both compilers reject
Linux/concurrent and heap-shrink/concurrent combinations. Linux-hosted ML can
generate concurrent Windows programs. Native writes into managed reference
slots remain unsupported; byte-buffer I/O is unaffected. Collection still needs
cooperative handshakes and memory headroom while old free blocks are hidden.
A saturated deletion log retains the snapshot rather than reclaiming live data.

## Regression and binary checks

- Python full suite: 167 passed, zero failed or skipped.
- ML full suite: 136 core cases plus the runner's CLI, Linux, assembler,
  compiler-internal and historical checks passed. The final rebuilt compiler
  passed the complete runner again in 203.148 seconds.
- Default memory parity: 228 images across Python, Windows ML and Linux ML,
  both target formats and both pipeline settings. Each per-target group is
  byte-identical. The separate native memory matrix and Python CLI memory
  contract checks also passed.
- Concurrent matrix: 18 fixture configurations, two pipelines and three
  compiler hosts, or 108 executed Windows images. Twelve additional fallback
  images cover both targets. Another 36 executed images check minimum/maximum
  log-capacity clamps and ignored limits when disabled. These groups match
  byte-for-byte. Invalid arity, platform/shrink combinations and malformed
  sizes are rejected without creating output images.
- Twenty repeated 64-MiB pressure runs and ten forced-overflow runs passed.
  Ordinary reference-transfer cases require zero overflows, preventing
  conservative retention from concealing missing barriers.
- SATB emitter tests: 3 passed. Python assembler tests: 9 passed; optional
  external NASM verification was not enabled.

The two comparison matrices cover 384 images, not all possible programs.
Equality is per target: Windows PE and Linux ELF are different formats.

## Self-hosting

The final documented source was built with Python and rebuilt by ML. Windows
monolithic/bootstrap and object-pipeline outputs match. Linux outputs from
Python, Windows-hosted ML/MLO and native Linux ML/monolithic also match.
Comments affect embedded debug line numbers; these final hashes belong to the
documentation-complete source rather than the earlier checkpoint.

| Target | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows x64 | 56,266,752 | `8a627dce1536a526e927f34583e6be36fc13432f3662cf9dfbaefe22e2a8b1d2` |
| Linux x64 | 56,267,008 | `e3d91f8f262b775f1cbbda52ee7be4db6638d216103eca4618e7de69586c7183` |

At the end of this pre-release verification, local `build/mlc_win64.exe` and
`build/mlc_linux_x64` contained these verified development images. Their predecessors remain in the same directory with the
`before-parity-2026-10-10` suffix. No version bump, commit, push or release was
performed in this verification pass.

Before the documentation-only edits, native Linux MLO self-hosting and three
successive Windows bootstrap/self-host stages also matched. An additional
Windows compiler built with `--gc-concurrent` successfully rebuilt itself with
the same option to a byte-identical 59,820,032-byte executable.

## Pause and memory measurements

Five rotating-order runs per image used `benchmarks/concurrent_gc_pauses.ml`,
after one warm-up each and with compiler/test processes idle. The fixture
retains 800,000 nodes, collects twelve times on a worker and verifies the final
payload. Python and ML generated identical benchmark images in both modes.
The baseline was the preserved published 1.2.18 Windows compiler.

| Image | Median maximum main-thread interval | Median whole-process time | Median peak RSS | File size |
| --- | ---: | ---: | ---: | ---: |
| Published 1.2.18 default | 12.3299 ms | 232.6 ms | 69.53 MiB | 111,104 bytes |
| Current default | 12.7113 ms | 233.4 ms | 69.53 MiB | 111,104 bytes |
| Current concurrent | 0.3761 ms | 403.6 ms | 69.55 MiB | 114,176 bytes |

The current default's total median differs by about 0.4% from the baseline;
this short benchmark does not establish a general performance change.
Concurrent mode reduces the observed maximum main-thread interval by about
97% relative to the current default. Its maximum internal handshake timer is
0.0842-0.0992 ms across the five runs; the main loop advances roughly two
million times while marking. Observed intervals include OS scheduling and
counter-call overhead and are not worst-case latency bounds.

This is a latency trade-off, not a general throughput win: the complete fixture
takes about 73% longer in concurrent mode while the main thread continues to
run. This largely read-only retained graph does not fill the deletion log;
its similar RSS does not mean concurrent collection has no memory cost under
write-heavy workloads. The default 8-MiB log and floating garbage still require
headroom. Raw samples and image hashes are in the ML build directory's
`concurrent-parity-pauses.json` and `concurrent-parity-pauses.log`.

## Documentation and standard library

Both READMEs describe the same API, options, statistics and limitations.
Declaration comments added or corrected during verification restore strict
MiniDoc generation to 38 compiler files, 3,308 symbols and zero warnings.
The standard libraries remain identical: 53 source modules and 351 generated
documentation files, compared by relative path and SHA-256.

## Reproducing the checks

From either compiler repository on Windows with WSL Ubuntu:

```powershell
python tests/check_concurrent_gc.py ../MiniLangCompilerPy/mlc_win64.py --reference ../MiniLangCompilerML/build/mlc_win64.exe --linux-reference ../MiniLangCompilerML/build/mlc_linux_x64 --output build/concurrent-matrix.json
python tests/check_memory_compiler_parity.py ../MiniLangCompilerPy/mlc_win64.py ../MiniLangCompilerML/build/mlc_win64.exe ../MiniLangCompilerML/build/mlc_linux_x64 --output build/memory-parity.json
python tests/check_memory_runtime.py ../MiniLangCompilerPy/mlc_win64.py
```

Python emitter checks are `python tests/test_concurrent_gc_codegen.py` and
`python tests/test_asm_opcodes.py`. Default suites remain
`python tests/run_tests.py` in Python and `scripts/run_tests.ps1` in ML.
Raw logs and JSON are under Python's `build/concurrent-parity-2026-10-10/`
directory and ML's `build/concurrent-parity-*.log` files. Benchmark compilation
and comparison instructions are in [the benchmark guide](../../benchmarks/README.md).
