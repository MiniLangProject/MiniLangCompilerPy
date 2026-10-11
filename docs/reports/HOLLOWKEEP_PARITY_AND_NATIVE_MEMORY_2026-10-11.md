# Hollowkeep compiler parity and native memory

Date: 11 October 2026. Unreleased development work after 1.2.19.

Both compilers now produce the same full Hollowkeep executable. The differences
were in code generation, independently of the concurrent allocator fixes.
The remaining private-memory endpoint changes must be distinguished from
managed-heap growth: native graphics allocations are repeatedly committed and
released, and a positive endpoint delta alone does not demonstrate a leak.

## Compiler fixes

- ML method `global` declarations now resolve existing root/package globals
  instead of silently creating bindings under the struct's method prefix.
  Shared tests cover existing and newly declared root/module globals.
- Both backends use the same bounded loop-unroll cost. Python no longer skips
  nested nodes of the same AST class or counts primitive literal payloads.
  ML visits coalescing children and call callees consistently. Boundary,
  deeply nested and structural emitted-label regressions cover the budget.
- Value-flow analysis resolves typed callees in the function's own file and
  namespace. A stale previous module context made ML miss the integer contract
  of `alphaBounds` in `trimSpriteImage`. Integer `div` facts now match too.
- Return contracts are used only for unshadowed callable bindings that cannot
  be rebound by the program. A replacement function may return a different
  type; original bodies must not be inlined after such a rebinding. Parameters,
  locals and captured callables retain dynamic behavior.
- Python forwards the selected PE subsystem to runtime generation, not just
  the PE header. GUI `input()` returns an empty string and omits unreachable
  console-reading code, matching ML.

No language feature or ordinary console-input behavior is removed.

## Exact binary comparisons

All game builds use the same frozen source tree, with source manifest SHA-256
`0ee4e048f8e15ae38397590eaca41679b026ce549fccf275f0a85a42881ee909`,
the same std sources, includes and Windows GUI/concurrent-GC options.

| Compared outputs | Bytes | Shared SHA-256 |
| --- | ---: | --- |
| Hollowkeep Python and Windows ML object pipeline | 86,633,472 | `C0EC23FB3780655405B7AC9FFB85813395CE0CE5C30EC4C534E49C83C0200499` |
| Windows compiler Python bootstrap and ML object selfbuild | 57,280,512 | `90BDC48EA2F2980492093F3152C8EEE06D3A2A56D537707D4A29A37504D59C94` |
| Linux compiler Windows ML crossbuild and Linux-native monolithic selfbuild | 57,278,800 | `033353EE91DBB595614B26645CE1DFE0D6081F0E020951976C93B0DFE8266437` |

The full game takes 168.61 seconds with Python and 304.59 seconds with Windows
ML in this verification run. These builds overlap other verification work;
they are build observations, not isolated speed comparisons. The full-game
comparison specifically covers Python versus ML's object pipeline; the shared
regression matrix below additionally checks monolithic ML.

The verified local `build/mlc_win64.exe` and `build/mlc_linux_x64` are updated.
Previous installed images are preserved under the ignored
`build/gc-growth-2026-10-11/previous-parity-installed/` directory.
Version strings remain 1.2.19. Published releases, checksums and Git remotes
are not changed by this task.

## Tests

- Python full suite: **175 passed**, zero failures or skips.
- ML full suite: **136 core tests and 220 outer checks**, all passed.
- Context, globals, unroll and GUI matrix: **60 generated images**, with exact
  equality across Python, Windows ML and Linux ML, both pipeline flags and
  Windows/Linux targets. GUI and concurrent-GUI cases apply only to Windows.
  One image per case/target is executed, not merely compared.
- Concurrent-GC matrix: **180 generated images**, including fallback APIs and
  SATB-capacity boundaries, with no exclusions. Generated runtime fixtures
  execute as part of that matrix.
- **140 repeated GC stress runs**, five unroll-model tests and four native
  emitted-GC-helper tests passed.
- All **53 std source modules and 351 std reference files** remain identical.
  MiniDoc rebuilt the compiler reference: 38 files, 3,321 symbols, zero warnings.

The context regressions are mirrored in both repositories:
`method_globals.ml`, `type_flow_context.ml`, `type_flow_rebinding.ml`,
`gui_input.ml`, and the extended `for_unroll_budget.ml`.
Support modules and `check_codegen_context_parity.py` are also identical.

## Native memory evidence

The earlier size-class run reproduced +21.77 MiB private process memory with
unchanged managed commitment. External virtual-memory censuses reveal
non-monotonic commitment changes in many native reservations, not additional
commitment inside MiniLang's reserved heap.

A debugger attached only to an isolated copied game process captured calls
through NVIDIA's OpenGL driver and Windows graphics allocation services. A
12-second dense sample observed 436 graphics calls and 51 private-commitment
changes across 20 reservations: **4.0625 MiB committed and 19.1875 MiB released**.
Changes were sampled around graphics-system-call returns; other process threads
can run between stops. This attributes substantial native churn to the graphics
path, not every byte of the original endpoint difference to a single owner.

An independently repeated diagnostic game run with the corrected executable
completed all 600 gameplay seconds, 51 waves, 408 kills, 658 successful casts
and 20 autosaves. All 13 validation checks passed. Warm managed commitment was
constant at **1,200.80 MiB**; private memory changed from **2,391.64 to
2,368.78 MiB**, or **-22.86 MiB**. Live managed objects increased by 0.509 MiB
and retained texture payload by 1.814 MiB. Debugger stops and overlapping builds
make this run unsuitable as a latency/performance baseline.

The sample does not establish a zero-native-growth guarantee or prove that the
entire application is leak-free. No native renderer or graphics-driver change
is claimed as a memory fix here. The compiler's proven heap-reuse fixes and the
native fluctuations are separate findings.

### Final run without debugger or concurrent compiler builds

A fresh ten-minute run of the byte-identical final image passes all 13 checks:
600 gameplay seconds, 51 waves, 408 kills, 658 successful casts and 20 autosaves.
The original user save is unchanged.

| Warm measurement | First | Last | Change |
| --- | ---: | ---: | ---: |
| Managed committed heap | 1,194.75 MiB | 1,194.75 MiB | 0 MiB |
| Private process bytes at logged endpoints | 2,386.40 MiB | 2,378.99 MiB | -7.41 MiB |
| Private bytes, 60-second window medians | 2,373.49 MiB | 2,373.08 MiB | -0.41 MiB |
| Live managed objects | 824.784 MiB | 825.285 MiB | +0.502 MiB |
| Retained texture payload | 82.693 MiB | 84.506 MiB | +1.814 MiB |

Private bytes fluctuate between 2,357.41 and 2,402.56 MiB during the warm interval.
The window comparisons use the first and last 60 seconds of each run's own
post-retirement interval, with 111 and 113 process samples in the final run.
They do not discard positive samples or select minima:

| Run | Private endpoint change | Private window-median change |
| --- | ---: | ---: |
| Earlier executable, external census | +21.77 MiB | +3.62 MiB |
| Earlier executable, native diagnostic | +14.23 MiB | -1.52 MiB |
| Corrected executable, native diagnostic | -22.86 MiB | +1.08 MiB |
| Corrected executable, final run | -7.41 MiB | -0.41 MiB |

Managed commitment remains constant in all four warm intervals. This supports
native fluctuation rather than a repeatable additional 22 MiB leak over this
workload; it does not prove that every native cache is bounded for arbitrarily
long runs. No additional GC or renderer mutation was justified by these samples.

The final run averages **291.20 FPS**, with a frame-histogram P99 upper bound of
**7.04 ms**. It contains 174,209 warm frames, 297 at least 16 ms, and a maximum
frame of 242.76 ms. Concurrent GC completes 752 cycles without SATB overflow;
the maximum measured handshake is 21.74 ms. These are absolute observations,
not an A/B speedup or a claim of unchanged frame tails. Debugger runs above are
excluded from performance comparisons.

### Measurement safeguards

Game sources, assets, DLLs and the input save are frozen or copied into an
isolated runtime. The actual user save is hash-checked before and after every
run. Native tracing is diagnostic-only and never included in shipped binaries;
hardware breakpoint state is restored before detaching.

Session logs must be selected by **PID and process start time**. PID-only
selection initially picked an old log from a different day after Windows
reused a process ID. Selecting the verified current log restored agreement
between all gameplay counters; the stale diagnostic copy remains preserved.
A missing or mismatched log must fail validation rather than silently passing.

Private process bytes and the sum of private committed virtual regions are
different measurements. Each is reported as observed; a virtual-memory census
is not treated as an exact replacement for the process counter. Warm-window
medians supplement endpoint comparisons, and debugger-instrumented frames are
not used to claim runtime speedups.

## Reproduction

From either compiler repository on Windows with WSL Ubuntu:

```powershell
python tests/check_codegen_context_parity.py ..\MiniLangCompilerPy\mlc_win64.py ..\MiniLangCompilerML\build\mlc_win64.exe --linux-compiler ..\MiniLangCompilerML\build\mlc_linux_x64 --output build/codegen-context-parity.json
python tests/check_concurrent_gc.py ..\MiniLangCompilerPy\mlc_win64.py --reference ..\MiniLangCompilerML\build\mlc_win64.exe --linux-reference ..\MiniLangCompilerML\build\mlc_linux_x64 --output build/concurrent-parity.json
```

Sanitized measurements are in
[the evaluation data](hollowkeep-parity-native-memory-evaluation-2026-10-11.json).
Complete logs, frozen game inputs, candidate images and diagnostic tools remain
under ignored `MiniLangCompilerML/build/gc-growth-2026-10-11/`.
Game source, saves and native driver data are not added to the compiler repos.
