# MiniLang Compiler 1.2.19

This patch release brings the optional Windows background garbage collector to
both compiler implementations with matching generated executables. The default
collector remains synchronous. Both CLI version flags (`--version`, `-version`)
and compile-time `MINILANG_VERSION` report **1.2.19**.

## Optional background GC

- `--gc-concurrent` enables cooperative handshakes and background marking for
  Windows x64 output. Linux targets and combining it with `--heap-shrink` are
  rejected. The Linux-hosted compiler can cross-compile concurrent Windows code.
- `gc_collect_async()` supports direct and first-class calls. Requests coalesce
  with an active concurrent cycle. Without the option, each call performs one
  synchronous collection on either target; existing `gc_collect()` remains usable.
- `--gc-satb-limit` uses checked heap-size syntax. Its default is 8 MiB and its
  effective capacity is clamped to 64 bytes through 64 MiB. The deletion log is
  outside the managed heap. A saturated log conservatively retains the snapshot.
- GC statistics 16-21 expose completed background cycles, phase, pause timers,
  overflow and marked-object counters. Reference-write barriers, thread roots,
  nested heap-monitor ownership and sweep publication are covered by regressions.
- Python now rejects incorrect direct-call arity consistently with ML. Leaf
  write barriers preserve registers without invoking a transient-root spill hook
  against their temporarily adjusted stack pointer.

This is not a moving or fully concurrent collector. Cooperative handshakes and
memory headroom are still required. Native code must not write managed reference
slots directly; byte-buffer I/O is unaffected.

## Performance and limitations

The [audit and measurements](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.19/docs/reports/CONCURRENT_GC_PARITY_2026-10-10.md)
describe five rotating-order runs of a retained-graph benchmark before the
version bump. Concurrent mode reduced the median maximum main-thread polling
interval from 12.7113 ms to 0.3761 ms (about 97%), while whole-process time rose
from 233.4 ms to 403.6 ms (about 73%). The current default was close to the
published 1.2.18 baseline in this fixture.

This is a latency/throughput trade-off, not a universal speedup or a worst-case
latency guarantee. Similar observed RSS in this mostly read-only fixture does
not establish memory neutrality for write-heavy workloads or a full deletion
log. The release version bump is not a separate performance experiment.

## Release validation

- Python full suite: **167 passed, 0 failed, 0 skipped**.
- Native full suite: **136 core cases** and all outer integration checks passed,
  including Windows/Linux runtime, assembler and compiler-internal regressions.
- **228 default-memory images** have six-way per-target byte parity across
  Python, Windows ML and Linux ML with both pipeline options.
- The concurrent matrix executes **108 Windows images**, **12 synchronous
  fallback images** across both targets and **36 SATB capacity images**. Matching
  configurations produce identical bytes. Invalid arity/options are rejected.
- Windows Python bootstrap, MLO stage 2 and monolithic stage 3 match exactly.
  Python Linux output, Linux-native monolithic selfbuild and Windows MLO
  crossbuild also match exactly.
- Twelve additional version/runtime images have six-way per-target parity;
  both CLI version flags and compile-time version checks pass on all hosts.
- All **53 std modules** and **351 std reference files** match between repos.
  MiniDoc regenerates 3,308 compiler symbols in 38 files without warnings.
- SATB emitter tests, 233 opcode vectors and the canonical Linux runtime blob
  pass. Optional external NASM verification was not enabled.

Python accepts the object-pipeline option but emits its monolithic equivalent;
ML exercises distinct monolithic and MLO implementations. These checks cover
selected programs and configurations, not all possible inputs. Windows PE and
Linux ELF files are not expected to equal each other.

Evidence: [version/self-host manifest](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.19/docs/reports/release-1.2.19-version-matrix.json),
[default-memory parity](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.19/docs/reports/release-1.2.19-memory-parity.json),
[concurrent parity](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.19/docs/reports/release-1.2.19-concurrent-parity.json).
The concurrent manifest records one hash per fixture/pipeline, compared across
three compiler hosts; fallback and capacity execution counts are separate.

## Compiler checksums

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows `mlc.exe` | 56,266,752 | `6ECC7B00933257A68E6FD6F6F9F443928DEFEF567AA590A958231050F107ADD5` |
| Linux `mlc` | 56,267,008 | `A7B9A353530080AC23FBB3B245107B739E63F31A414E325B4721B3EB9C9A93D4` |

These hashes identify the native compilers, not the compressed archives.
Archive checksums are supplied as separate `.sha256` downloads.

## Downloads

This repository publishes the Python compiler as a source release. Run
`python mlc_win64.py --version` to verify the version. Matching ready-to-run
[Windows and Linux native compiler packages](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.19)
are published by MiniLangCompilerML; those packages do not require Python.
