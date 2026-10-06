# MiniLang Compiler 1.2.18

This patch release repairs memory and thread lifetimes, improves fragmented
allocation and GC bitmap processing, and closes CLI and native string-return
differences between the two compiler implementations. Both CLI version flags
and compile-time `MINILANG_VERSION` report **1.2.18**.

## Memory and runtime fixes

- GC-managed Thread control records and a weak registry reclaim abandoned
  inactive threads and terminated native handles. Active workers remain
  protected until native termination; reachable results and identity survive.
- Closing a never-started thread is atomic. Completed thread-pool jobs and
  obsolete allocation handoff roots no longer retain their payload graphs.
- An invalidation-aware free-list cursor avoids repeated exact-size scans.
  Heap growth respects reservation ceilings, page alignment and full-width
  growth values. Optional heap shrinking also trims excess GC metadata.
- First-class `gc_collect` calls have the correct native call frame. The Linux
  thread-wait adapter preserves the required nonvolatile registers.
- Aligned runtime entries and qword bitmap BT/BTS operations reduce GC work
  while retaining pointer, tag and bounds validation.

## Compiler consistency

Heap-size options now share checked ASCII decimal syntax, ignored underscores
and case-insensitive binary suffixes `b`, `k/kb/kib`, `m/mb/mib`, `g/gb/gib`,
and `t/tb/tib`. Values must be positive and no greater than
`1152921504606781440` bytes. Overflow and non-ASCII lookalikes are rejected;
this numeric limit is not a guarantee that the OS can reserve that memory.

Both native pipelines generate requested Linux assembly listings. Listings
honor data sections and loaded virtual addresses, preserve hidden and
extensionless default filenames, and report output failures. Conflicting
`--asm` and `--no-asm` options are rejected.

Native `cstr` return lowering now matches the Python compiler byte-for-byte,
including null, empty and concurrent conversions across collections. This
resolves the historical `cstr` code-generation parity exception.

## Evaluation

The [memory follow-up report](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.18/docs/reports/MEMORY_FOLLOWUP_2026-10-06.md)
contains the completed pre-version-bump audit and raw A/B measurements against
1.2.17. The version bump itself is not a new performance experiment.

- Four-worker allocation time fell by 20.42% on Windows and 25.67% on Linux.
- A fragmented 4,000-allocation case reduced search probes from 8,002,000 to
  7,999; abandoned-thread retention and registry growth were removed.
- The compiler qualification fixture improved from 40.19 to 38.19 seconds,
  with essentially unchanged peak working set (about 1.15 GiB).
- Performance is workload-dependent: Linux string join remained about
  1.8–2.3% slower and Windows string multi-repeat about 2.2–4.3% slower in the
  selected independent controls. This is not a universal speedup claim.

## Validation

- The release-stamped Python full suite passes **166 cases**, with no failures
  or skips. The native suite passes **136 core cases** and its outer integration
  checks, including Windows and Linux runtime tests.
- **228 memory images** match exactly per target/configuration across Python,
  Windows ML and Linux ML hosts, with both pipeline options.
- CLI/version/runtime fixtures report 1.2.18 and have six-way per-target parity.
- Windows Python bootstrap, native stage 2 and stage 3 are byte-identical.
  Python Linux output, Windows ML crossbuild and Linux-native selfbuild are
  byte-identical as well.
- All **53 standard-library modules** and **351 generated reference files**
  match between repositories. MiniDoc reports 1,930 std symbols and 3,290
  compiler symbols, without warnings.
- Structural code-generation and canonical Linux runtime-blob checks pass.
  The preceding audit also passed 146 stress executions and both 72-image
  memory runtime matrices.
- Extracted Windows and Linux packages pass version, standard-library and
  memory/FFI smoke tests; executable, bridge and archive checksums are verified.

Python accepts the object-pipeline option but emits its monolithic equivalent;
the ML compiler exercises distinct monolithic and MLO implementations.
See the [release version and self-host manifest](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.18/docs/reports/release-1.2.18-version-matrix.json)
and [memory parity manifest](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.18/docs/reports/release-1.2.18-memory-parity.json).

## Compiler checksums

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows `mlc.exe` | 55,379,968 | `D2C03E5C02BFC5F455FE1078EDBCD6FD7A34A4C3130E6D4F1E570749719B30AA` |
| Linux `mlc` | 55,382,096 | `730F85B06CA42833B0C15560256607E97AC3D0BDE950273836C3357B47EB2F38` |

Archive checksums are supplied as separate `.sha256` downloads.

## Downloads

This Python release provides GitHub source archives. Ready-to-run Windows and
Linux packages are available in the [matching self-hosted release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.18).
