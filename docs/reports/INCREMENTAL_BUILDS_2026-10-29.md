# Incremental native builds — implementation and evaluation

Date: 2026-10-29. Sources: the changes following Python `b71a6577` and
self-hosted `1186fa18` (both version 1.2.23).

## Result and scope

Both compilers now reuse validated native function fragments after source
changes. Enable this through an incremental project manifest, or add
`--incremental-cache build/compiler-cache` to a direct compiler invocation.
The native monolithic and MLO pipelines both support it. Windows-x64 and
Linux-x64 retain the same clean-build output within each target.

An unchanged manifest build can still restore the final executable directly.
A changed build reparses the import graph, recomputes global analysis, reuses
compatible native fragments and links a new executable. There is no change to
the language, runtime, optimization settings or standard library.

This is conservative reuse, not independent compilation of every module.
Changing a module invalidates its functions; declaration and inline changes
can invalidate callers or the entire stream. Shared labels, pools, section
offsets and inline budgets also participate in validation. A layout-changing
edit can invalidate subsequent fragments in unchanged modules. Parsing and
global analysis are not cached yet.

## Correctness

The following checks completed successfully:

| Check | Result |
| --- | --- |
| Existing Python test runner | 179 passed, 0 failed, 0 skipped |
| Existing self-hosted PowerShell suite | Complete suite passed; its core runner reports 138 passed, 0 failed |
| Changed-build driver, Windows host → PE | 96 recorded compilation checks across Python, native monolithic and native MLO |
| Changed-build driver, Windows host → ELF | Same 96 checks |
| Changed-build driver, Linux host → ELF | Same 96 checks, including native Linux cache publication |
| Existing language/runtime fixtures, Windows images | 153 images executed successfully; all nine clean/cold/warm/backend variants of each fixture byte-identical |
| Existing language/runtime fixtures, Windows host → Linux images | 135 images executed under WSL; the same nine-way byte comparisons passed |
| Existing language/runtime fixtures, Linux host → Linux images | Another 135 images executed; all nine variants per fixture byte-identical |
| Primitive cache codecs and frontend dependency | Python: 6 focused checks; native: round-trip and malformed-input checks executed on Windows and Linux |
| Native AST projection schema | Generator `--check` passed |
| Compiler MiniDoc | 43 source files, 3,434 symbols, 0 warnings |

The changed-build driver covers integer and control-flow edits, changed
strings and pooled constants, inline bodies, global declarations, debug source
locations, compiler options and conditional definitions. It also exercises
truncated cache entries, explicit cache bypass, concurrent publishers and new
compile errors. The three expected diagnostic compilations in each set of 96
exit with code 2; they are assertions of correct rejection, not test failures.
Additional manifest checks verify exact artifact hits, partial reuse after an
edit, clean-build parity and propagation of cache bypass to MLO children.
The Python-specific checks also replace a selected external parser while
keeping the MiniLang source unchanged. Both function and final-artifact caches
invalidate correctly. The complete 32-check Python changed-build set was
repeated after adding this dependency guard.

The runtime fixtures include closures and default lambdas, variadic escape
lifetimes, optional values, pattern matching, overloaded operators, defer,
optimizer safety, ordered comparisons, threads, synchronization and pools.
The Windows set additionally exercises the broad language suite and concurrent
GC/dead-function interaction.

Compiler bootstrap, native self-compilation and cached self-compilation
produced the same 57,805,824-byte Windows executable:

```text
SHA-256: 9b4ef78179b0e3d3eef0e87d98af6704c6ac43537d141979521ad1e735a915e1
```

## Measurements

Machine: Windows x64, AMD Ryzen 9 9900X; Linux validation uses Ubuntu on
WSL2, kernel `6.6.87.2-microsoft-standard-WSL2`. These are local development
measurements, not isolated laboratory results or a Hollowkeep benchmark.

### Large self-build

The current native compiler compiled itself through the MLO pipeline with a
new function cache, then repeated the same direct invocation. Direct mode
forces the frontend and linker to run, so the second row is function reuse,
not restoration of a previously finished executable.

| Mode | Wall time | Sampled peak private memory, process tree | Reused / compiled functions |
| --- | ---: | ---: | ---: |
| Initial build and cache population | 123.17 s | 2,463 MiB | 0 / 2,081 |
| Repeated build with populated cache | 45.20 s | 1,226 MiB | 2,081 / 0 |

This repeat used 63.3% less elapsed time and approximately half the sampled
private memory. The first row includes cache population; it is **not** a
measurement of an uncached baseline. Both outputs match the bootstrap hash
above. Other development work was active on the shared machine during this
measurement, so these values should not be treated as guaranteed speedups.

### Controlled module edits

`tests/bench_incremental.py` generates 16 modules with 16 functions each,
plus the entry function. It alternates backend order across three repetitions
and compares every result to a clean build of the same source. An edit in an
early or late module preserves 241 functions and rebuilds that module's 16
functions. Warm unchanged builds reuse all 257 functions.

Median wall time in seconds, three repetitions:

| Backend | Clean, no cache | Initial cache population | First cache read | Repeated cache read |
| --- | ---: | ---: | ---: | ---: |
| Python | 1.856 | 2.395 | 2.187 | 0.684 |
| Native monolithic | 1.080 | 1.898 | 0.669 | 0.625 |
| Native MLO | 1.058 | 1.709 | 0.728 | 0.625 |

The Python compiler's first cache read was slower than its clean build in
these runs; the next read was substantially faster. This first-read cost is
reported rather than excluded. Its cause has not been isolated.

Each edit below is compared with a clean build of the **same edited source**:

| Backend | Early edit: clean → incremental | Time saved | Late edit: clean → incremental | Time saved |
| --- | ---: | ---: | ---: | ---: |
| Python | 1.775 → 0.759 s | 57.3% | 1.762 → 0.886 s | 49.7% |
| Native monolithic | 1.051 → 0.677 s | 35.5% | 1.063 → 0.726 s | 31.7% |
| Native MLO | 1.054 → 0.696 s | 34.0% | 1.043 → 0.710 s | 31.9% |

Median sampled peak private memory in MiB:

| Backend | Clean, no cache | Initial cache population | Repeated cache read | Early edit |
| --- | ---: | ---: | ---: | ---: |
| Python | 55.5 | 61.8 | 79.4 | 78.7 |
| Native monolithic | 115.8 | 197.2 | 115.3 | 115.8 |
| Native MLO | 133.0 | 198.1 | 133.0 | 133.0 |

This small fixture does not show a memory reduction: Python retains additional
decoded cache data, and native cache population temporarily allocates more.
The large self-build above benefits more from skipping function lowering.
Our other validation jobs had finished before this final timing round; normal
desktop and operating-system activity was not disabled.

The raw measurements are in
[`INCREMENTAL_BUILDS_2026-10-29.json`](INCREMENTAL_BUILDS_2026-10-29.json).
Cache population has an explicit time and memory cost. It is beneficial for
repeated builds with reusable fragments; one-off builds can omit the cache
flag or use `--no-incremental`.

Memory measurements sample private bytes for the whole compiler process tree
every 40 ms. They include the native MLO subprocess and are not live-object
sizes, resident-set sizes or an exact OS-maintained peak. Small-build timings
are sensitive to file-system caching, scanning and other system activity.

## Reproduction

See [`../INCREMENTAL_BUILDS.md`](../INCREMENTAL_BUILDS.md) for the shared
commands and cache behavior. The three cross-compiler drivers are identical
in both repositories. The native codec fixture additionally runs with:

```text
mlc_win64.exe tests/incremental_codec.ml build/incremental-codec.exe -I . --no-asm
build/incremental-codec.exe
python tools/generate_incremental_ast.py --check
```

The Python-specific codec checks run with
`python tests/check_incremental_codec.py` in the Python repository.

For Hollowkeep, the compiler invocation can now opt in directly. The build
script must also stop regenerating its encrypted asset package and random key
module on code-only builds if those inputs are meant to remain reusable.
This compiler change does not modify game assets, saves or build scripts.
