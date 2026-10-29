# MiniLang Compiler 1.2.24

This release adds persistent native-function reuse after source edits to both
the Python and self-hosted compilers. Windows x64 PE and Linux x64 ELF remain
supported. Both version flags (`-version`, `--version`) and compile-time
`MINILANG_VERSION` report **1.2.24**.

## Incremental builds

- Incremental project manifests enable function reuse automatically. Exactly
  unchanged builds retain the existing final-artifact cache.
- Direct builds can opt in with `--incremental-cache DIR`; no manifest is
  required. The native monolithic and MLO pipelines both support the cache.
- `--no-incremental` bypasses cache reads and writes, including in native
  child emitters. Assembly listings and label dumps compile normally.
- Cache keys cover compiler content, target/options/defines, parsed module
  contents, declarations, inline dependencies, body-derived global facts and
  incoming native layout. Python also fingerprints the selected parser when
  a project supplies an external frontend.
- Replay restores machine code, labels, relocations, constant-pool changes,
  helper reachability, binding/label counters and inline budgets. Incremental
  output retains the canonical clean-build instruction stream.
- Records contain bounded, checksummed data. Damaged entries become misses;
  optional cache publication failures do not fail compilation. Atomic writes,
  parsed-source snapshots and whole-build fingerprint rechecks protect reuse
  during concurrent builds and editor saves.

The frontend, global analysis and linker still run after an edit. Global
declarations, inline bodies or layout changes can invalidate additional
functions in unchanged modules. This is conservative function reuse, not
fully independent per-module compilation. Python and native cache formats are
separate; old compiler generations are invalidated automatically.

See the [incremental build guide](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.24/docs/INCREMENTAL_BUILDS.md).
Build scripts must also preserve generated inputs when their own dependencies
are unchanged: rebuilding an encrypted asset package and random key module on
every code-only build still invalidates compiler inputs.

## Performance evidence

The [development evaluation](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.24/docs/reports/INCREMENTAL_BUILDS_2026-10-29.md)
includes raw measurements and limitations. In its 16-module fixture, edits
reused 241 of 257 functions: Python took 50–57% less build time and native
mono/MLO took approximately 32–36% less than clean builds of the same edits.
The native self-build reused all 2,081 functions: 123 seconds including initial
cache population versus 45 seconds on the repeated build.

Cache population costs time and memory. The first Python cache read was also
slower than a clean build in the measured runs. The small fixture did not
reduce memory usage; the large self-build did. These timings predate the
version bump and are not new full-game or application-throughput benchmarks.

## Release validation

The release-stamped 1.2.24 builds pass:

- Python suite: **179 passed, 0 failed, 0 skipped**, plus six cache codec and
  selected-frontend dependency checks.
- Native suite: **138 core tests and 237 outer checks passed**.
- **Six full compiler builds** reach identical Windows and Linux fixed points:
  Python bootstrap, native mono/MLO self-hosting and cross-host builds.
- **Twelve executed version/runtime images** have six-way byte parity per
  target. CLI flags and compile-time version constants agree on all hosts.
- **288 changed-build compilation checks** across Python, native mono and MLO,
  targeting PE and ELF on Windows and ELF on Linux. These include cache
  corruption, parallel publication, new diagnostics, manifest exact hits,
  partial reuse and cache bypass in child processes.
- Primitive native cache codecs execute successfully on Windows and Linux;
  native Linux permission, case-sensitive import and project-cache checks pass.
- Strict MiniDoc: **43 files / 3,434 symbols** for Windows and
  **44 files / 3,436 symbols** for Linux, with **zero warnings**.
- All **53 std modules** and **351 std reference files** remain byte-identical
  between repositories.

See the [release verification manifest](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.24/docs/reports/release-1.2.24-version-matrix.json).
The development evaluation separately records 423 executed language/runtime
images and the timings above. Equality is per target/configuration; PE and
ELF files are not expected to match each other.

## Distribution

The Python repository remains source-only. Ready-to-run Windows and Linux
packages are published in the
[ML compiler release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.24).
They contain the matching standard library, native-media bridge, example,
licenses/notices, incremental-build guide and evaluation, release validation
manifest and a tagged source-revision manifest. Each archive has a SHA-256
sidecar. Published compilers are unpacked; optional UPX packing remains opt-in.

These hashes identify the unpacked compiler executables:

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows `mlc.exe` | 57,805,824 | `2F8C660872C5052A808E0C21A4936F04FA7FF1B4B0787343CAB5A508CD1A5027` |
| Linux `mlc` | 57,820,288 | `512D1B5DA682BD93DF605A0FDBE7595EC5DE34B1106D9F2AD0AB0FA868D55DA8` |
