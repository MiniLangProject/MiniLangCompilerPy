# MiniLang - Python Reference Compiler for Windows and Linux x64

Current stable release: **1.2.0**. See the [changelog](CHANGELOG.md) and
[release notes](RELEASE_NOTES_1.2.0.md).

Supported native targets: **Windows x64 (PE32+)** and **Linux x64 (ELF64)**.

Release 1.0.0 and later are source-only: generated `.exe` files are not
tracked in Git and are not attached to GitHub releases.

MiniLang (`.ml`) is a small, dynamically typed language that compiles with
`mlc_win64.py` to native Windows x64 (PE32+) or Linux x64 (ELF64) images.
Windows is the default target; `--subsystem windows` emits a Windows GUI image.

This Python implementation is the bootstrap/reference compiler. Its normal
monolithic build path is kept byte-for-byte output-compatible with the
self-hosted MiniLang compiler in `MiniLangCompilerML`; see
[Compiler parity and self-hosting](COMPILER_PARITY.md).

Both compiler implementations and their documentation were developed with the
assistance of generative AI.

---

## Contents

- [1. Quickstart](#1-quickstart)
- [2. Files & Running](#2-files--running)
- [3. Comments](#3-comments)
  - [3.1 Newlines & statement separators](#31-newlines--statement-separators)
- [4. Types & Literals](#4-types--literals)
- [5. Variables & Assignments](#5-variables--assignments)
- [6. Operators & Expressions](#6-operators--expressions)
- [7. Arrays](#7-arrays)
- [8. Control Flow](#8-control-flow)
  - [8.1 if / else if / else](#81-if--else-if--else)
  - [8.2 while](#82-while)
  - [8.3 loop ... while ... end loop (do-while)](#83-loop--while--end-loop-do-while)
  - [8.4 for ... to](#84-for--to)
  - [8.5 for each ... in](#85-for-each--in)
  - [8.6 break / continue](#86-break--continue)
  - [8.7 switch / case](#87-switch--case)
- [9. Functions](#9-functions)
  - [Modern language extensions](#modern-language-extensions)
  - [Deferred cleanup (`defer`)](#deferred-cleanup-defer)
  - [Inline functions (`inline`)](#inline-functions-inline)
  - [9.1 Native threads & synchronization](#91-native-threads--synchronization)
  - [9.2 Thread-safe standard-library types](#92-thread-safe-standard-library-types)
  - [9.3 Managed thread pools](#93-managed-thread-pools)
- [10. struct](#10-struct)
- [11. enum](#11-enum)
- [12. Modules, namespace & import](#12-modules-namespace--import)
- [13. Standard Library & Builtins](#13-standard-library--builtins)
  - [13.1 Stdlib modules (std.*)](#131-stdlib-modules-std)
  - [13.2 Builtins: basics](#132-builtins-basics)
  - [13.3 Bytes / Encoding / File I/O](#133-bytes--encoding--file-io)
  - [13.4 Heap / GC debug](#134-heap--gc-debug)
  - [13.5 Call profiling (optional)](#135-call-profiling-optional)
- [14. extern](#14-extern)
- [15. Error handling: `error` & `try`](#15-error-handling-error--try)
- [16. Syntax Reference (short)](#16-syntax-reference-short)
- [17. Examples](#17-examples)
- [Native compiler status](#native-compiler-status)
- [Compiler parity and self-hosting](#compiler-parity-and-self-hosting)

---

## 1. Quickstart

**Hello World**

```ml
print "Hello MiniLang!"
```

**Variables and math**

```ml
x = 10
y = 5
print x + y
```

**If/then**

```ml
age = 18
if age >= 18 then
  print "ok"
else
  print "nope"
end if
```

Inline form also works:

```ml
if age >= 18 then print "ok" else print "nope" end if
```

Program entry via `main(args)`:
```ml
function main(args)
  print "argc=" + len(args)
  if len(args) > 0 then
    print "first=" + args[0]
  end if
  return 0
end function
```

---

## 2. Files & Running

- Source files use the extension: `.ml`

### Compile to native Windows or Linux x64

```bash
python mlc_win64.py input.ml output.exe [options]
python mlc_win64.py input.ml output --target linux-x64 [options]
python mlc_win64.py -version
```

Notes:
- Flags can appear before or after the positional arguments.
- `windows-x64` is the default and emits PE32+; `linux-x64` emits ELF64.
- A Linux image created on Windows can be copied to Linux or run through WSL
  after `chmod +x output`. A Linux-hosted Python compiler adds the executable
  permission bits without widening the caller's `umask`; exact project-cache
  restores preserve that mode.

Common options:

**Import / modules**
- `-I <dir>` / `--import-path <dir>` add an import search path (repeatable). The directory of `input.ml` is always an implicit import root.

**Listings / diagnostics**
- `--asm` write a combined `.asm` listing (default: off)
- `--asm-out <path>` override listing path (default: output basename + `.asm`)
- `--asm-cols addr,opcodes,code` choose columns (default: all)
  - or `--asm-no-addr`, `--asm-no-opcodes`, `--asm-no-code`
- `--asm-data` include `.rdata/.data/.idata` dumps (**constants and imports**)
- `--asm-pe` include a PE32+ header + section table dump in the listing
  (Windows target only)
- `--dump-labels <path>` write a raw section/helper/label dump for parity
  debugging

**Diagnostics**
- `--keep-going` continue after the first error and report multiple diagnostics
- `--max-errors <n>` cap the number of diagnostics when using `--keep-going` (default: 20)

**Conditional compilation**
- `-DNAME[=VALUE]` / `--define NAME[=VALUE]` override a typed source option;
  an omitted value means `true`

**Heap / GC tuning (native runtime)**
- `--heap-reserve <size>` reserve heap address space (e.g. `256m`)
- `--heap-commit <size>` initial committed heap bytes (e.g. `16m`)
- `--heap-grow <size>` minimum commit growth step when the heap needs to grow (e.g. `1m`)
- `--heap-shrink` enable decommit after GC (trim-from-top). Default: off
- `--heap-shrink-min <size>` minimum committed heap when shrinking (default: initial commit)
- `--gc-limit <size>` bytes allocated between periodic GC runs (default: backend constant)
- `--no-gc-periodic` disable periodic GC trigger (collect only on OOM)

**Profiling / tracing**
- `--profile-calls` instrument user functions with call counters; enables `callStats()`
- `--trace-calls` print each entered function name to stderr (runtime trace)

**Output**
- `--target windows-x64` emits a PE32+ image (default)
- `--target linux-x64` emits an ELF64 image
- `--subsystem console` / `cui` selects the default Windows console subsystem
- `--subsystem windows` / `window` / `gui` selects the Windows GUI subsystem;
  subsystem selection does not apply to Linux

**Cross-compiler build compatibility**
- `--object-pipeline` is accepted so project commands can be shared with the
  self-hosted compiler. Python emits the equivalent monolithic image; the
  self-hosted canonical `.mlo` pipeline produces the same final Windows PE or
  Linux ELF bytes.
- `--no-object-pipeline` is also accepted for command/manifest parity. Python
  code generation remains serial; this switch does not alter its output bytes.

`python mlc_win64.py -version` and `--version` both print
`MiniLang Compiler 1.2.0`. `python mlc_win64.py --help` prints the full option
list.

Notes (current implementation):
- Targets Windows x64 (PE32+) and Linux x64 (ELF64); Windows remains the
  backward-compatible default.
- Heap parameters can be configured via `--heap-*` flags (reserve/commit/grow/shrink).
- If a top-level `function main(args)` exists, the native entrypoint will call it after module initialization has completed. Imported module initializers and the entry file's top-level initialization run automatically before `main`. `args` is `argv[1..]` as an array of strings. The returned int becomes the process exit code (void -> 0).
- Both runtimes use one process-wide, thread-safe managed heap with per-thread
  stacks and TLABs. Windows reserves/commits with `VirtualAlloc`; Linux uses
  `mmap`, `mprotect` and `madvise`.
- Linux images without external native imports are static. A source containing
  `extern function ... from "lib.so..."` gets a minimal dynamic ELF image using
  the x64 System V ABI and the glibc interpreter `/lib64/ld-linux-x86-64.so.2`.
- Listing order is stable; PE header dumps are available only for Windows.
- The compiler uses the shared MiniLang frontend for parsing (tokenizer/parser).


### Project manifests and incremental builds

Larger programs can keep their entry point, output path and compiler options in
a TOML manifest and build it with one command:

```bash
python mlc_win64.py --project minilang.toml
```

```toml
[project]
entry = "src/main.ml"
output = "build/app.exe"
include = ["src", "vendor"]
target = "windows-x64"
subsystem = "console"
object_pipeline = true
incremental = true
cache_dir = ".minilang-cache"
compiler_args = ["--heap-reserve", "1g"]

[defines]
FEATURE_TLS = true
SERVER_NAME = "example"
WORKER_LIMIT = 8
```

All paths are relative to the manifest. The supported project fields are:

| Field | Meaning |
| --- | --- |
| `entry` / `input` | required entry `.ml` file |
| `output` | required native image path |
| `include` / `import_paths` | array of import roots |
| `target` | `windows-x64` (default) or `linux-x64` |
| `subsystem` | Windows only: `console` or `windows` (aliases accepted by the CLI) |
| `object_pipeline` | optional force switch for the self-hosted compiler; omit it for automatic selection |
| `incremental` | enable the exact-hit artifact cache (default `true`) |
| `cache_dir` | cache directory (default `.minilang-cache`) |
| `compiler_args` | array of additional compiler arguments |

The optional top-level `[defines]` table accepts booleans, integers and
strings. These values are passed to conditional compilation before any module
is parsed. Explicit `-D` arguments after `--project` take precedence. The
effective definitions and the manifest contents are included in the
incremental-cache fingerprint.

Unknown project fields and wrong field types are errors. Command-line
arguments after the manifest are appended; use `--no-incremental` to bypass
the cache for one build. Python 3.11 or newer is required for `--project`.

For manifests that must work with both compilers, use the conservative TOML
subset shown above: a `[project]` table, quoted strings, booleans, and
single-line arrays of quoted strings. Keep comments on their own lines. The
Python implementation uses `tomllib`; the self-hosted implementation has a
small purpose-built parser for this shared subset and preserves commas inside
quoted array strings.

The incremental cache is deliberately conservative. Its fingerprint covers the
manifest, effective compiler arguments, content-based compiler identity, every
`.ml` source below the entry/include roots, and recursively quoted imports which
escape those roots. An exact hit verifies the content-addressed executable and
preserves its POSIX mode while restoring it. Any relevant change performs a
full build; this is artifact caching, not per-module incremental compilation.
Listing and label-dump builds bypass
the cache. The Python compiler accepts `object_pipeline` for manifest
compatibility and emits the equivalent monolithic image; the self-hosted
compiler automatically selects its retained `.mlo` pipeline for large Windows
or Linux import graphs when the field is omitted. An explicit `true` forces
`.mlo`; an explicit `false` forces monolithic mode. The Python compiler accepts
both values without changing its serial output.
Per-process temporary artifacts are published before one atomic state-pointer
update, so interrupted or concurrent generations cannot pair one input digest
with another executable. Damaged cached executables fail checksum validation.

### Conditional compilation

Conditional compilation is line-oriented and happens before tokenization and
import resolution. It can therefore remove platform code, optional imports or
entire declarations without changing source positions used by diagnostics.

```ml
#option TRACE_HTTP: bool = false
#option MAX_WORKERS: int = 8
#option PRODUCT: string = "server"
#const LARGE_POOL = MAX_WORKERS >= 16

#if TARGET_OS == "windows" and (TRACE_HTTP or LARGE_POOL)
  import diagnostics.http_trace
#elif PRODUCT == "server"
  import server.logging
#else
  #error "unsupported product configuration"
#endif
```

`#option NAME: bool|int|string = expression` declares a per-file typed option.
Its default is used unless a project/CLI definition with that name exists.
`#const NAME = expression` defines an immutable compile-time value for the
remainder of that file. Compile-time values are available only in directives;
they are not runtime variables and are not substituted into ordinary code.

The supported directives are `#option`, `#const`, `#if`, `#elif`, `#else`,
`#endif` and `#error`. Conditions must produce `bool`. Expressions support
bool/int/string literals, declared values, `defined(NAME)`, `not`, `and`, `or`,
comparisons, integer arithmetic/bitwise/shift operations and string `+`.
Inactive branches are blanked before lexing, so their imports and syntax are
not processed. Directives may be nested.

The immutable target values are `TARGET_OS`, `TARGET_ARCH`, `TARGET_ABI`,
`TARGET_FORMAT`, `POINTER_SIZE` and `MINILANG_VERSION`. Windows selects
`"windows"`, `"x64"`, `"win64"`, `"pe"`, `8` and `"1.2.0"`; Linux selects
`"linux"`, `"x64"`, `"sysv"`, `"elf"`, `8` and `"1.2.0"`. No
compiler-implementation value is exposed: the Python and self-hosted compilers
must select the same source for identical inputs.

Examples of CLI overrides:

```bash
python mlc_win64.py app.ml app.exe -DTRACE_HTTP -DMAX_WORKERS=32
python mlc_win64.py app.ml app.exe --define PRODUCT=desktop
```

Each source file starts with the target values plus the same external
definitions, then evaluates its own `#option` defaults and `#const` values.
Declare every externally configurable name with `#option`; `defined(NAME)` is
useful for optional externally supplied flags. This is intentionally not a
textual macro system: directives cannot rewrite tokens or inspect which
compiler implementation is running.

### Formatting (mlfmt)

There is a small auto-formatter written in MiniLang: `tools/mlfmt.ml`.

Compile it once:

```bash
python mlc_win64.py tools/mlfmt.ml mlfmt.exe -I .
```

Format a single file:

```bash
mlfmt.exe src.ml --inplace
mlfmt.exe src.ml out.ml --indent 2 --max-blank 2
```

Format a whole tree (recursive, **in-place**):

```bash
mlfmt.exe .
```

Insert an Apache 2.0 header (only if missing):

```bash
mlfmt.exe . --apache "Authorname"
# or:
mlfmt.exe . --author "Authorname"
```

Notes:
- `--max-blank -1` allows unlimited blank lines.
- Directory formatting uses Win32 directory enumeration (so it is meant to run on Windows / Wine).
- When `<path>` is a directory, `mlfmt` formats all `*.ml` files recursively **in-place** (the optional `output.ml` argument is only valid for single-file formatting).
- `--apache/--author` uses the local year (via `std.time.win32.GetLocalTime()` in the compiled binary).
- The formatter is intentionally conservative (it does not change program semantics).


### Run

```bash
./output.exe [args...]
```

Running tests:

```bash
python tests/run_tests.py
python tests/run_tests.py --verbose
python tests/run_tests.py --only import
python tests/run_tests.py --allow-skip
```

Notes:
- The test runner compiles a set of `.ml` programs to Windows `.exe` files and executes them.
- On Windows, `.exe` runs natively; on non-Windows you need `wine` to execute the produced binaries.
- `--only PAT` filters by substring, `--verbose` prints full stdout/stderr, and `--allow-skip` exits with code 0 even if some tests were skipped (e.g. no Wine).
- Latest complete run for this revision: **115 passed, 0 failed, 0 skipped**.

### Compiler parity and self-hosting

For identical source files, include roots and compiler options, this compiler
and the self-hosted compiler's normal monolithic path emit byte-identical PE
files. The current 25-program parity matrix covers the language/standard-library
suites, GC stress, compiler-GC liveness, extern/native interop, global rebinding,
native threads and managed thread pools; every pair matches by SHA-256.

The production self-build uses the MiniLang-only `.mlo` object pipeline. Its
canonical layout is covered by automated byte-identity gates against both the
normal self-hosted path and the Python bootstrap. Exact hashes, test counts,
boundaries and reproduction commands are recorded in
[COMPILER_PARITY.md](COMPILER_PARITY.md).

Current audited Windows fixed point (2026-08-31): with a warm filesystem cache
and fresh object directories, this Python compiler produced Stage 1 in 60.398
seconds at 1,100.8 MiB process-tree working set / 1,090.3 MiB private commit.
The sibling native bootstrap produced Stage 2 in 99.976 seconds at 1,787.1 /
2,005.9 MiB, and that generated compiler produced Stage 3 in 130.402 seconds at
1,778.8 / 1,893.6 MiB. All three are byte-identical 62,788,096-byte images with
SHA-256
`EDA1417DD6B2D88B9DB3643189275CB1AB2B92BE65C4037428A98890746334D7`.
One repeated Stage 3 probe exited transiently at support-tail emission after 318
function objects; an isolated retry completed with the exact fixed-point image.
The sibling build script now omits its self-host-only `--mem-probe` diagnostic
flag automatically when selecting a clean Python bootstrap.

#### Historical performance record

The measurements below preserve the chronology of earlier optimization passes;
the audited fixed-point values above describe the current trees.

The self-hosted pipeline writes MLO v2 objects and now resolves same-fragment
`rel32`/`rip32` fields directly in each materialized text fragment. Local
control-flow labels and relocations are therefore absent from normal object
tables; only named cross-fragment/cross-section patches remain. Its reader is
compatible with retained v1 and earlier numeric-target v2 objects. This Python
compiler does not write `.mlo` files; accepting `--object-pipeline` still emits
the equivalent monolithic Windows PE or Linux ELF. Direct parity checks after
the folding change remain byte-identical on the language suite, optimizer
suite and Linux target smoke.

The self-hosted writer now also traverses its fixed-size patch groups directly
instead of flattening every local patch into a second managed array before
folding. This is an implementation-only throughput/memory change: MLO remains
at version 2, the Python `--object-pipeline` compatibility behavior is
unchanged, and current Windows optimizer, Linux static and Linux FFI fixtures
are byte-identical across all three compiler paths.

The sibling compiler now also reuses one fully materialized semantic fragment
state throughout its serial function-object stream instead of cloning global
scope/maps for every batch. It resets binding ids and batch-local state to the
historical values, so Python target generation and MLO v2 remain unchanged.
The resulting self-host Stages 1-3, all 297 compiler MLOs and all 497
MiniQuake MLOs are byte-identical to the preceding pipeline. The self-host
object-emission median improved by 20.77%, and the clean MiniQuake median by
10.07%, while sampled private compiler memory fell by about 49 MiB.

The sibling compiler now additionally reuses one compiler-local analysis
workspace across serial functions. Its capacity-backed worklists and
epoch-cleared fact/dependency/promotion maps reduce short-lived allocation
without adding fields to generated codegen state. A controlled self-build
median improved from 130.483 to 110.108 seconds (15.61%), sampled process-tree
private peak fell by 32.3 MiB, and a controlled MiniQuake build improved from
283.945 to 224.695 seconds (20.87%) while retaining the exact target bytes.

The self-hosted heap-shrink emitter is synchronized with this reference
backend as well: both emit the post-GC decommit path and use the same 4 MiB
default threshold. Python bootstrap, self-hosted Stage 2 and Stage 3 now emit
the same 60,660,224-byte compiler image with SHA-256
`344CE78BB6C03307A594FB4843642669083432AD2FF744772CE6086BA4A7629E`.
Dedicated Windows and Linux runtime tests verify decommit and the configured
minimum.

The sibling self-hosted compiler now stores its internal `FastMap` slot
generations in byte buffers instead of tagged arrays and grows those maps only
after reaching 80% occupancy. This does not change Python code generation or
target bytes. An adjacent self-build reduced private peak memory from 1,944.2
to 1,823.9 MiB (6.19%), working set from 1,904.3 to 1,792.1 MiB (5.89%) and
object-emission time from 107.143 to 104.266 seconds (2.68%). Python Stage 1
and self-hosted Stages 2/3 converge to the same 60,690,432-byte image with
SHA-256
`5E2518E16AC783F90F8E72E353338629088035D35A7870A15DEA283D7C605E20`.

The sibling self-hosted compiler also supports `--profile-compiler` for
wall-clock phase timings. Its `.mlo` pipeline uses capacity-backed internal
vectors, isolated semantic function batches and shared append-only section
builders while spilling completed assembler fragments. Canonical section order
keeps the linked image inside the normal cross-compiler target-byte contract.

For very large monolithic programs the profiler additionally reports text-label
and deferred-patch counts and whether direct section lookup was selected. The
self-hosted assembler omits unused full call histories during code generation,
resolves text labels through its existing map and materializes only section/IAT
overrides; the `.mlo` linker preallocates its object-patch index. These are
compiler-throughput changes only and do not affect target bytes.

For the 1.1.0 acceptance pass, a 142-file snapshot of the current MiniQuake
worktree at commit `1036b1c3b551d00de777c67293d262a6cc5c2739` plus 18 dirty
entries was built through all three paths. This compiler took 67.528 seconds,
the self-hosted monolithic compiler took 2,024.375 seconds and the canonical
self-hosted `.mlo` build took 431.789 seconds. The `.mlo` run emitted 494
function fragments in 361.500 seconds, runtime helpers in 3.781 seconds and
linked in a fresh process in 42.375 seconds. All three builds produced the same
57,005,568-byte PE with SHA-256
`3071B78B6F2C72B8C3036E5D62010831758F6EA3E7FFA3F6AF908BB9756003B3`.
Retail Quake data passed a 120-frame runtime smoke and deterministic trace; a
1,000-frame E1M1 baseline measured about 1,404.5 headless frames/s and 166.8
rendered FPS. The object writer preserves the stream-wide inline budget across
fragments and filters local return/defer labels out of helper discovery.

The current reviewed 1.1.0 self-host source reaches a binary fixed point:
Stage 2 and Stage 3 are byte-identical 56,743,936-byte compiler images with
SHA-256
`E85E3A6EE515DC8605A10752DA953E0FBF92C5992CC354179CA7A471E11AFFEF`.
The Python-built Stage 1 has the same size and SHA-256
`5E84848F01D6147C1EE0D7BA47FE610DBF9093E05299AF2EF029B34B594B26D2`;
Stage 2 and Stage 3 took 283.065 and 304.742 seconds. This fixed point includes
guarded specialization for fallible byte-buffer accesses, deterministic
16-byte user-function alignment across monolithic and `.mlo` builds, and a
dependency-driven type-flow worklist plus indexed package-aware integer flow.
The parity report therefore
distinguishes the bootstrap image, the measured self-hosted fixed point and
byte-identical target output explicitly.

The subsequent large-label throughput pass converges at Stage 2. Its Stage 2
and Stage 3 images are byte-identical 59,923,456-byte compilers with SHA-256
`FB6D921349BBE248A88726910CE72396651B2372179ADC36D7913FC7240ECF3D`;
the stages completed in 357.656 and 258.750 seconds through the canonical
object pipeline. On clean MiniQuake commit
`b5fe23f17bd5e861f22afd72b2e83aa4b73b9bd5`, this Python compiler completed
in 77.757 seconds, the optimized self-hosted monolith in 874.519 seconds and
`.mlo` in 351.937 seconds. All three builds emitted the same 57,197,056-byte PE
with SHA-256
`8E5D38689481FC7D0FC6CACD6FFD015EEBA3C2B875A9B19E0CC790A142970E63`.


---

## 3. Comments

### Line comment

```ml
// this is a comment
print "hi" // comment at end of line
```

### Block comment

```ml
/*
  Multi-line comment
  is ignored
*/
print "ok"
```

### 3.1 Newlines & statement separators

MiniLang is newline-oriented, but supports a few "robust syntax" rules to make formatting easier:

#### Statement separators
- Newlines separate statements.
- `;` can also separate statements (useful for single-line / inline code).

```ml
a = 1; b = 2; print a + b
```

#### Where newlines are optional / ignored
Newlines are allowed (and ignored) in common "continuation" positions:

- **After operators** (and after unary operators):
  ```ml
  x = 1 +
      2 +
      3

  y = -
      5

  z = not
      false
  ```

- **Inside bracketed lists and calls** (after `[` / `(`, after commas, and before the closing `]` / `)`):
  ```ml
  a = [
    1, 2, 3,
    4, 5, 6,
  ]

  print add(
    1,
    2,
    3,
  )
  ```

- **Inside indexing** (after `[` and before `]`):
  ```ml
  v = a[
    0
  ]
  ```

#### Trailing commas
Trailing commas are allowed in array literals and call argument lists:

```ml
a = [1, 2, 3,]
print add(1, 2, 3,)
```

---

## 4. Types & Literals

MiniLang values:

### Numbers
- Int: `1`, `-42`
- Hex int: `0xabc`, `-0x10`
- Binary int: `0b10101`, `-0b10`
- Float: `3.14`, `-0.5`

```ml
a = 10
b = -3.5
h = 0xFF
m = 0b1010
```

Note: the tokenizer currently treats a leading `-` as part of a numeric literal. In expressions like `a-1`, write spaces (`a - 1`) to ensure `-` is parsed as an operator.

### Strings
- Strings use double quotes: `"Text"`
- Common escapes are supported, e.g. `\n`, `\t`, `\"`, `\\`

```ml
s = "Hello\nWorld"
print s
```

### Booleans
- `true`
- `false`

```ml
flag = true
```

### Arrays
- Literals: `[1, 2, 3]`, `["a", "b"]`
- Trailing commas are allowed: `[1, 2, 3,]`
- Multiline literals are allowed (see section 7).

```ml
arr = [1, 2, 3]
```

### Bytes

`bytes` is a mutable raw byte buffer (values `0..255`). You create it with `bytes(...)` (or legacy `byteBuffer(...)`).

- Indexing returns an `int` byte value.
- Assignment `buf[i] = n` expects `n` in `0..255`.

See [13.3](#133-bytes--encoding--file-io) for details and file / encoding examples.

### void
`void` is the “no value” literal.

You get `void` when a function ends without `return`, or explicitly via `return void`. It is a real runtime value, so it can be assigned:

```ml
function maybeGetName()
  if input() == "" then
    return void
  end if
  return "Nina"
end function

x = maybeGetName()
if x is void then
  print "no name"
else
  print x
end if
```

**Strict void handling (runtime):** using `void` in most operations produces a runtime `error(...)`:

- calling it: `void()` or `x()` when `x` is `void`
- member access: `void.field`
- indexing: `void[i]` or `a[void]`
- arithmetic / bitwise ops: `+ - * / % & | ^ ~ << >>`
- ordered comparisons: `< <= > >=`
- boolean ops: `and` / `or` / `not` (if an operand is `void`)
- as a condition in `if` / `while` / `loop ... while`
- `len(void)`

For type checks, prefer:

- `x is void` / `x is not void`
- `x is int`, `x is string`, etc. (primitive type checks; sugar for `typeof(x) == "..."`)
- `x is Thread` / `x is thread` (the native thread category; both spellings
  are equivalent)
- `x is Thing`, `x is Color`, etc. (concrete struct/enum type checks; compares the internal type id)

Equality/inequality (`==`, `!=`) still works with `void` (e.g. `void == void`).

> Note: `print void` (and printing unsupported heap objects) raises a runtime `error(...)`.

#### Legacy note
Older MiniLang versions treated `void` as an internal-only value that was not directly writable (e.g. assignment and printing were rejected). With strict void handling, `void` is writable, but *using it as a real value in operations* now fails loudly as described above.

---

## 5. Variables & Assignments

### Assignment

```ml
name = "Max"
score = 100
```

Variables do not need to be declared.

### Synchronized variables

Use `synchronized` for a shared global binding:

```ml
synchronized counter = 0
```

Synchronized variables may only be declared at top level or in a namespace.
Every read and write uses the runtime's process-wide recursive monitor. For an
assignment such as `counter = counter + 1`, the lock covers the complete
read/modify/write operation.

The binding may contain any MiniLang value, including strings, arrays, bytes,
structs, functions and thread objects. The monitor protects access to the
binding; it does not automatically protect later mutations of an object stored
in it. Wrap compound object operations in a synchronized function or use a
thread-safe collection.

### const (write-once bindings)

Supported at top level, in namespaces, and inside functions.

```ml
const PI = 3.14159
const NAME = "MiniLang"
```

Rules:
- A `const` binding can only be assigned **once**.
- At **top-level / in namespaces**, the initializer must be `constexpr` (compile-time evaluable).
  Typical `constexpr` expressions include literals, arithmetic/bitwise operations on constexpr values, references to other `const`s, and enum values.
- Inside **functions**, the initializer may be any expression, but the name is still write-once.

Note: `const` makes the **binding** immutable (you can’t reassign the name). It does not deep-freeze objects like arrays/bytes.

### What counts as a statement?
Allowed standalone statements are:

- assignments (e.g. `x = 1`)
- function calls (e.g. `foo(1,2)`)
- `print <expr>`

Not allowed, for example:

```ml
1 + 2    // invalid: expressions alone are not statements
```

Statements can be separated by **newlines** or by **`;`**.

---

## 6. Operators & Expressions

### Arithmetic

| Operator | Meaning |
|---------:|---------|
| `+` | add / string concat / array concat / bytes concat |
| `-` | subtraction |
| `*` | multiplication |
| `/` | division |
| `%` | modulo |

Important:
- `-`, `*`, `/`, `%` work only with numbers (not `bool`).
- `+` is special:
  - number + number -> number
  - array + array -> array concatenation
  - bytes + bytes -> bytes concatenation
  - otherwise -> string concatenation (both sides are converted to strings automatically)

Use `str(value)` when an explicit string conversion is clearer.

### Comparisons

| Operator |
|---------:|
| `==` |
| `!=` |
| `>` |
| `<` |
| `>=` |
| `<=` |
| `is <type>` | type check (runtime categories such as `int`/`thread` via `typeof`, struct/enum via internal id) |
| `is not <type>` | negated type check |

### Logic
- `and`, `or` (short-circuit)
- `not` (unary)

```ml
if not (x == 10) and true then
  print "ok"
end if
```

### Bitwise (integers)
- shifts: `<<`, `>>`
- bitwise AND: `&`
- bitwise OR: `|`
- bitwise XOR: `^`
- bitwise NOT: `~x`

### Operator precedence (low -> high)
1. `or`
2. `and`
3. `|`
4. `^`
5. `&`
6. `==`, `!=`, `is`
7. `>`, `<`, `>=`, `<=`
8. `<<`, `>>`
9. `+`, `-`
10. `*`, `/`, `%`
11. unary: `not`, `-x`, `~x`

Parentheses override precedence.

Newlines may appear after operators (see [3.1](#31-newlines--statement-separators)).

---

## 7. Arrays

### Create arrays

```ml
a = [1, 2, 3]
b = ["x", "y"]
c = array(4)         // [void, void, void, void]
d = array(3, "hi")   // ["hi", "hi", "hi"]
```

`array(size[, fill])` initializes a new array with `size` elements.  
If `fill` is omitted, elements are initialized with `void`.
Invalid `size` (non-int, negative, or too large) returns a runtime `error`
(catchable via `try(...)`).

### Multiline literals + trailing commas

```ml
a = [
  1, 2, 3,
  4, 5, 6,
]
```

### Indexing

```ml
arr = [10, 20, 30]
print arr[0] // 10
```

Multiline indexing is allowed:

```ml
print arr[
  2
] // 30
```

Index must be an int (not bool).

Out of bounds indexing (or indexing a non-indexable value) raises a runtime `error`
that you can catch with `try(...)`.

### Assigning to an index

```ml
arr = [1, 2, 3]
arr[1] = 99
print arr // [1, 99, 3]
```

Invalid index assignment (wrong target type, non-int index, out of bounds, invalid byte value)
raises a runtime `error` (catchable via `try(...)`).

### Concatenation

```ml
x = [1,2]
y = [3,4]
z = x + y
print z // [1,2,3,4]
```

---

## 8. Control Flow

### 8.1 if / else if / else

Block form:

```ml
if <cond> then
  ...
else if <cond> then
  ...
else
  ...
end if
```

Inline form (single-line / compact):

```ml
if <cond> then <stmt> end if
if <cond> then <stmt> else <stmt> end if
```

Use `;` to put multiple statements on one line:

```ml
if x > 0 then a = 1; b = 2; print a + b end if
```

### 8.2 while

```ml
while <cond>
  ...
end while
```

### 8.3 loop ... while ... end loop (do-while)
Body executes at least once.

```ml
loop
  ...
while <cond>
end loop
```

### 8.4 for ... to

```ml
for <var> = <start> to <end>
  ...
end for
```

- `start` and `end` must be int
- runs automatically up or down (step +1 or -1)

### 8.5 for each ... in
Iterates over arrays, strings, or bytes.

```ml
for each <var> in <iterable>
  ...
end for
```

### 8.6 break / continue

#### continue
Jumps to the next loop iteration.

```ml
i = 0
while i < 5
  i = i + 1
  if i == 3 then
    continue
  end if
  print i
end while
```

#### break
Exits the current loop or a `switch`.

```ml
while true
  print "once"
  break
end while
```

#### break with a counter: `break n`
`break 2` breaks two nested levels (e.g. inner + outer loop).

```ml
while true
  while true
    print "stop"
    break 2
  end while
  print "never reached"
end while
```

Note: `break`/`continue` should only be used inside matching constructs (loops, and `switch` for `break`).

### 8.7 switch / case

```ml
switch <expr>
  case <value>
    ...
  end case

  case <value1>, <value2>, <value3>
    ...
  end case

  case <start> to <end>
    ...
  end case

  case default
    ...
  end case
end switch
```

- `case X, Y, Z` = multiple values
- `case A to B` = range (mainly useful for ints)
- `case default` = fallback
- When a case matches, its body runs and the switch is exited afterwards.
- `break` inside a case also exits the switch.

Robust syntax for value lists:
- Trailing commas are allowed before the case body: `case 1, 2, 3,`
- Value lists can span multiple lines:

```ml
switch x
  case 1, 2, 3,
       4, 5, 6
    print "hit"
  end case
end switch
```

---

## 9. Functions

### Definition

```ml
function <name>(a, b, c)
  ...
  return <expr>
end function
```

- parameters are names (identifiers)
- `return` is optional
- without `return`, the function returns `void`
- `return;` is allowed and is equivalent to `return`
- Robust syntax: a bare `return` can appear directly before a block terminator in inline forms, e.g. `if cond then return end if`

Example:

```ml
function add(a, b)
  return a + b
end function

print add(2, 3)
```

Multiline parameters are allowed (trailing comma optional):

```ml
function add3(
  a,
  b,
  c,
)
  return a + b + c
end function
```

### Modern language extensions

MiniLang remains dynamically typed, but declarations may add runtime-checked
contracts. A failed parameter, return, annotated initializer or typed
struct-constructor field
contract produces error `1308` and propagates like every other MiniLang error;
wrap an operation in `try(...)` when the error is expected.

```ml
function sum(first as int, second as int = 0, rest...) returns int
  total = first + second
  for each value in rest
    total = total + value
  end for
  return total
end function

maybeName as string? = void
print sum(second = 2, first = 1)
print sum(1, 2, 3, 4)
```

The optional marker follows the type (`Person?`). `void` is accepted only by
an optional contract. Default and named arguments are available for directly
resolved MiniLang functions and methods; struct constructors accept field names.
A final `name...` parameter receives surplus positional arguments as an array.
Dynamic callable values intentionally do not accept named arguments because
their runtime representation has no parameter-name metadata.

Non-optional annotations also feed the optimizer after their entry guard has
succeeded. Proven integer, float, boolean, string, array, bytes and concrete
struct values can therefore use the same specialized machine-code paths as
locally inferred values. A proven primitive return expression also omits its
otherwise redundant return-contract check; entry guards remain the dynamic
call boundary.

Expression lambdas use the existing closure implementation and may capture
lexical variables:

```ml
factor = 4
multiply = function(value as int) returns int => value * factor
print multiply(3)
```

Lambda calls are positional. Lambda parameters support type annotations, but
defaults and variadic tails are intentionally reserved for declared functions,
whose signatures the compiler can resolve at the call site. Small expression
lambdas and fully typed expression functions are automatically considered for
the same bounded inliner as explicit `inline` declarations; every function
still retains its normal callable body when the budget or eligibility check
requires a fallback.

Optional access and fallback expressions avoid manual `void` checks. `?.`
short-circuits both field access and method calls, and `??` evaluates its right
side only when the left side is `void`:

```ml
label = user?.profile?.displayName ?? "anonymous"
```

`match` provides deterministic value, list and inclusive-range matching. It is
the pattern-oriented spelling of `switch`; cases do not fall through and the
current version deliberately has no destructuring or guard clauses.

```ml
match status
  case 0
    print "idle"
  end case
  case 1 to 3
    print "busy"
  end case
  case default
    print "unknown"
  end case
end match
```

Iterator functions collect yielded values into an array with geometric buffer
growth. Prefixing the declaration with `lazy` instead returns a zero-argument
pull closure: each call produces one value and exhaustion returns `void`.
`for each` accepts both eager arrays and these pull closures, so a lazy iterator
does not materialize an intermediate collection. In both forms, `returns T` is
the yielded-value contract and explicit `return` statements are rejected.
Lazy state machines currently support `yield` in straight-line code, `if`,
`while`, `do while`, `for` and `for each`; `yield` inside `match`/`switch` or
`synchronized`, `defer`, and multi-level `break` are rejected at compile time.

```ml
iterator function numbers(limit as int) returns int
  for i = 0 to limit
    yield i
  end for
end function

lazy iterator function largeNumbers(limit as int) returns int
  for i = 0 to limit
    yield i
  end for
end function
```

For a directly resolved variadic call, the compiler proves whether the tail can
escape the callee. Read-only, call-scoped tails use an immutable stack array
view; returned, captured, mutated or forwarded tails keep the normal managed
heap array. This optimization does not change source semantics.

Interfaces are compile-time structural contracts. `implements` verifies every
required instance method and its complete parameter/variadic/optional/return
signature. Interfaces do not allocate runtime objects, provide default methods
or add a separate dynamic-dispatch mechanism.

```ml
interface Named
  function name() returns string
end interface

struct Person implements Named
  value as string
  function name() returns string
    return this.value
  end function
end struct
```

Async functions use one compiler-managed four-worker `ThreadPool` per program
and are available on Windows and Linux. Calling one submits a job and returns a
`ThreadPoolJob` immediately instead of creating a native thread per call.
`await` accepts pool jobs, ordinary `Thread` handles and non-thread values;
`select` accepts jobs and threads and returns the zero-based index of the first
completed item (`-1` for an empty list). Async declarations are currently
limited to module or namespace scope; async struct methods and combined
`async iterator` declarations are rejected. Workers retain MiniLang's shared
GC heap and private-stack model. A retained async handle owns native
synchronization resources; call `Dispose()` after its result is no longer
needed, as with an explicitly submitted `ThreadPoolJob`.

```ml
async function fetch(id as int) returns string
  return "item-" + id
end function

first = fetch(1)
second = fetch(id = 2)
winner = select(first, second)
print await first
print await second
```


### Deferred cleanup (`defer`)

Inside a function, `defer` registers a function or method call for execution
when that function leaves:

```ml
function saveFile(path, data)
  handle = openFile(path)
  defer closeFile(handle)
  writeFile(handle, data)
  return true
end function
```

- Deferred calls execute in reverse registration order (LIFO) on `return`,
  normal fall-through and automatic `error` propagation.
- The callee/receiver and all arguments are captured when `defer` is reached;
  later variable assignments do not change the queued call.
- A `defer` in a branch is registered only if that branch executes.
- If a deferred call returns an `error`, it becomes the pending function result;
  older deferred calls still run.
- The current implementation accepts call expressions only and rejects `defer`
  directly inside loops. Put one iteration in a helper function when per-item
  cleanup is needed.

### Inline functions (`inline`)

You can mark **top-level functions** and **struct methods** as `inline`:

```ml
function inline clamp01(x)
  if x < 0 then return 0 end if
  if x > 1 then return 1 end if
  return x
end function
```

For an eligible **direct** call such as `clamp01(v)`, the compiler expands the
callee body at the call site (no call/ret overhead). `inline` is a bounded
optimization request, not a guarantee. Small fully typed expression functions
and generated expression lambdas are also eligible automatically; explicit
`inline` remains useful for larger hand-selected bodies.

Current behavior / limits:
- Only supported for **top-level functions** and **struct methods** (`function inline ...`).
- `inline` and `synchronized` are mutually exclusive on the same function.
- Only **direct calls** are inlined. Calls through a variable (e.g. `f = clamp01; f(v)`) are not inlined.
- Inline bodies must not capture variables (no closures / env hops / boxed captures).
- Bodies containing loops, `switch`, nested functions, or `defer` are not
  eligible and use the normal callable body instead.
- Inline recursion / mutual recursion is rejected.
- `return <expr>` returns from the *inline call* (the call yields the return value).
- The inline expansion uses an isolated scope so it won't clobber caller locals.
- Eligibility is deliberately cost-bounded, and each callee has a 4096-byte
  native expansion budget. Later call sites fall back to its normal callable
  body instead of allowing unbounded code growth.
- Caller stack sizing includes the widest call inside every eligible inline
  body. Such a call is hidden from the caller's own AST, but still needs the
  same outgoing-argument and GC-rooted call-temp space after expansion.
- Every inline function retains a normal callable body. This deliberately
  trades a small amount of executable size for relocation safety across
  imported aliases, first-class callable values and late budget fallbacks.


### Function calls

```ml
print add(2, 3)
```

Multiline call arguments are allowed (trailing comma optional):

```ml
print add3(
  1,
  2,
  3,
)
```

### 9.1 Native threads & synchronization

`Thread(function[, logicalId])` creates a real native Windows/Linux thread object without
starting it. Its entry point must be a top-level, capture-free function with
zero or one parameter. A one-parameter worker receives the exact managed value
passed to `Start(value)`:

```ml
synchronized jobsDone = 0

function worker(data)
  global jobsDone
  // allocations enter the process-wide managed heap
  scratch = array(1024, data)
  jobsDone = jobsDone + 1
  return scratch
end function

t = Thread(worker, "request-worker-1")
print t.Status()  // Created
print t.Start(42) // true
print t.Join()    // true; waits indefinitely
print t.Status()  // Completed
print t.Result()  // the returned array
print t.Close()   // closes the native thread handle
```

Threads are a first-class runtime category. Both constructor-style and
lowercase checks are accepted, including their negated forms:

```ml
print t is Thread      // true
print t is thread      // true
print t is not Thread  // false
```

Thread methods:

- `Start()` or `Start(value)` starts a newly created thread once and returns
  `bool`. Its argument count must match the entry function's zero/one arity.
- `Stop()` atomically requests cooperative cancellation and returns whether a
  running thread changed to `StopRequested`.
- `Join()` waits indefinitely; `Join(timeoutMs)` waits at most the given number
  of milliseconds. Both return `true` only when the thread terminated.
- `Status()` returns `Created`, `Running`, `StopRequested`, `Completed`,
  `Stopped`, or `Failed`.
- `IsAlive()` is true for `Running` and `StopRequested`.
- `Id()` returns the native thread id (`0` before a successful start).
- `LogicalId()` returns the user-defined logical id. `SetLogicalId(value)` can
  replace it while the thread is still in `Created`; the constructor's optional
  second argument sets the initial value. Logical ids do not change the native
  Win32 id.
- `Result()` returns the worker's result (`void` until it publishes one). Use
  `try(t.Result())` when a failed worker returned an `error` value.
- `Close()` closes the native handle after termination. Status metadata remains
  valid; its small control page is retained until process exit.

Worker helpers:

- `threadStopRequested()` reports whether the current worker was asked to stop
  (and returns `false` on the main thread).
- `threadLogicalId()` returns the logical id of the current worker (`void` on
  the main thread).
- `threadSleep(milliseconds)` calls the native sleep primitive.

`Stop()` is safe and cooperative: the compiler inserts cancellation checks at
statement boundaries. It never uses asynchronous thread termination. Long
native calls may finish before cancellation is observed, but a thread in a
blocking native call does not prevent another thread from collecting garbage.

All threads allocate into one process-wide, non-moving managed heap. Each OS
thread owns only its native stack, a private GC root chain, temporary root slots
and a 64 KiB thread-local allocation buffer (TLAB) carved from that shared heap.
Objects up to 256 bytes including their GC header use a lock-free cursor fast
path; larger objects, TLAB refills, heap growth and free-list access use the
serialized central allocator. A TLAB is only an allocation reservation, never a
private object heap, so references can be published between threads unchanged.

Collection is cooperative stop-the-world: generated function and loop
safepoints park managed threads, while threads inside known native calls publish
a stable root chain. The collector traces global roots and every registered
thread context, retires all TLAB ownership, and then sweeps the ordinary shared
heap block chain. A terminating worker returns its unused TLAB tail to the
central free list.

When collections arrive back-to-back, a worker that observes the next request
while resuming reacquires the coordination monitor and republishes `Parked`
before waiting again. This keeps the collector's context scan and the worker's
wait state consistent even during sustained allocation churn at full hardware
thread concurrency.

Each thread context also retains its four most recent allocation results as
handoff roots. This closes the short lifetime gap while nested object graphs
are being assembled, before a precise stack or global root owns them. These
slots are GC metadata; they are not a private managed heap.

Consequently, an object created by a worker remains valid after that worker
terminates whenever it is still reachable from a global, another live object,
a thread result or another registered root. `heap_bytes_used()`,
`heap_bytes_committed()` and `heap_bytes_reserved()` report the same global heap
from every thread. `Thread.Close()` releases the native handle and clears roots
owned by the thread object; it does not invalidate objects published elsewhere.

Use a synchronized function when a whole critical section must be serialized:

```ml
import std.threading as threading

function synchronized updateSharedState()
  global jobsDone
  jobsDone = jobsDone + 1
end function

guard = threading.Lock.new()
synchronized(guard)
  // Only code using this guard is serialized.
  updateOneSharedObject()
end synchronized
```

Synchronized variables and synchronized functions share the recursive
process-wide monitor for backward compatibility. `synchronized(lock)` instead
uses the supplied `std.threading.Lock`, evaluates that expression exactly once
and releases it on fall-through, `return` and propagated `error` exits. A failed
acquire propagates error `1101`; `break` and `continue` cannot leave this block.
Independent locks allow unrelated critical sections to proceed concurrently.

Managed object identity is shared across threads; no copy is made when a
reference is published. Concurrent writes to the same object, array slot or
unsynchronized global are data races. Use the appropriate synchronized form or
the primitives/collections in the next section to define the required critical
section. Console and other process-wide I/O should also be serialized when
multiple workers can use it.

For closed programs that never reference `Thread`, the compiler selects a
single-thread fast path. Generated hot code then omits cancellation and GC
safepoint polls, thread-local root/debug handoffs, managed/native transition
wrappers and allocator/world-lock traffic. Programs that can construct a
`Thread` retain the fully synchronized shared-heap runtime above; after all
workers have exited, uncontended allocation also bypasses the heap lock again.
This selection is automatic and does not change source semantics.

### 9.2 Thread-safe standard-library types

`std.threading` exposes native process-wide synchronization objects:

- `Lock.new()` creates a recursive Win32 mutex. Methods are `acquire()`,
  `tryAcquire()`, `acquireFor(timeoutMs)`, `release()`, `isClosed()` and
  `close()`. `Acquire`, `TryAcquire`, `AcquireFor` and `Release` aliases are
  also available.
- `Semaphore.new(initialCount, maximumCount)` provides `acquire()`,
  `tryAcquire()`, `acquireFor(timeoutMs)`, `release()`,
  `releaseMany(count)`, `isClosed()` and `close()`.
- `Event.new(manualReset, initialState)` provides `wait()`, `tryWait()`,
  `waitFor(timeoutMs)`, `set()`, `reset()`, `isClosed()` and `close()`.

All waits return `bool`; a timeout is reported as `false`. A lock acquired after
`WAIT_ABANDONED` is treated as successfully acquired and must be released.

The collection modules serialize access to managed backing arrays in the global
heap:

- `std.ds.concurrent_list.ThreadSafeList`: `new`, `withCapacity`, `fromArray`,
  `add`/`push`, `addAll`, `get`, `set`, `insert`, `removeAt`, `pop`, `popOr`,
  `first`, `last`, `len`/`count`, `reserve`, `clear`, `toArray`, `close`.
- `std.ds.concurrent_hashmap.ThreadSafeHashMap`: `new`, `withCapacity`, `set`,
  `get`, `getOr`, `has`, `remove`/`delete`, `count`/`len`, `clear`,
  `keysArray`, `valuesArray`, `entriesArray`, `increment`, `close`.
  `increment(key, delta)` is an atomic integer read/modify/write and initializes
  a missing key with `delta`.

Collection values may be arbitrary MiniLang values, including nested arrays and
structs, and retain object identity instead of being deep-copied. Map keys may
be `int`, `string` or `bytes`; unsupported key types return `false` from
mutating methods. Snapshot methods return ordinary managed arrays. As with any
container, a lock protects the collection operation, not an unsynchronized
mutation later performed through an object reference returned by `get()`.

```ml
import std.threading as threading
import std.ds.concurrent_list as concurrentList
import std.ds.concurrent_hashmap as concurrentMap

gate = threading.Semaphore.new(0, 1)
jobs = concurrentList.ThreadSafeList.new()
counts = concurrentMap.ThreadSafeHashMap.new()

function worker()
  gate.acquire()
  jobs.add("done")             // same managed value is visible to all threads
  counts.increment("done", 1) // atomic
end function

t = Thread(worker)
t.Start()
gate.release()
t.Join()
print jobs.get(0)
print counts.get("done")
t.Close()

// Only after all operations and waiters are finished:
jobs.close()
counts.close()
gate.close()
```

Create shared objects before starting their users and keep their global
references alive. `close()` is a lifecycle operation, not a concurrent method:
call it only after all worker operations, lock holders and waiters have ended.
Because cancellation is cooperative, a worker blocked in a native wait can
observe `Stop()` only after that wait returns.

### 9.3 Managed thread pools

`std.concurrent.thread_pool` provides reusable GC-registered workers for
request-oriented workloads such as web servers. Jobs accept one managed data
value, retain its identity in the shared heap, and expose completion, failure
and cancellation without terminating the reusable worker:

```ml
import std.concurrent.thread_pool as threadPool

function handleRequest(request)
  return "handled " + request
end function

pool = threadPool.ThreadPool.withQueueCapacity(8, 1024)
job = pool.Submit(handleRequest, "/status")

if typeof(job) == "void" then
  // bounded queue is full or shutdown has begun: apply backpressure
  return 503
end if

job.Wait()
print job.GetStatus() // Completed, Failed, or Cancelled
print job.GetResult()
job.Dispose()

pool.Shutdown()             // graceful: drain accepted jobs
pool.AwaitTermination()
pool.Dispose()
```

- `ThreadPool.new(workerCount)` uses an unbounded queue.
- `ThreadPool.withQueueCapacity(workerCount, capacity)` bounds waiting jobs;
  capacity `0` is unbounded. Worker counts must be between 1 and 256.
- Pending jobs use a geometrically growing circular buffer, keeping total queue
  growth linear even when producers temporarily outrun every worker.
- `Submit(function, data)` returns a `ThreadPoolJob`, or `void` after shutdown
  or when a bounded queue is full.
- `PendingCount()`, `WorkerCount()` and `IsShutdown()` expose pool state.
- `Shutdown()` stops accepting work and drains the queue.
- `ShutdownNow()` cancels queued jobs; currently running callbacks finish
  cooperatively.
- `AwaitTermination()` / `AwaitTerminationFor(timeoutMs)` join all workers.
- `Dispose()` performs graceful shutdown if needed and closes native handles.
- Jobs provide `Cancel`, `Wait`, `WaitFor`, `GetStatus`, `GetResult`, `IsDone`,
  `IsCancelled` and `Dispose`.

Pool workers receive stable logical ids such as `thread-pool-0`. Callbacks may
allocate, trigger GC and return arbitrary managed values. A `Failed` job stores
the callback's `error`; retrieve it with `try(job.GetResult())`. Pool disposal
and job disposal are lifecycle operations and must not race their active users.

### 9.4 Tasks, cancellation and bounded channels

`std.concurrent.task` layers `Future` values over an existing thread pool.
`run(pool, callback, data)` schedules a conventional callback;
`runCancellable` calls `callback(data, token)`. Futures provide `Wait`,
`WaitFor`, `IsDone`, `Cancel`, `Dispose` plus lowercase `status()` and
`result()`. `whenAll` preserves input order, while `whenAny` and `whenAnyFor`
return the first completed index.

`std.concurrent.cancellation` provides `CancellationTokenSource` and its
read-only `CancellationToken`. Cancellation is idempotent and cooperative:
`IsCancellationRequested`, `Wait`/`WaitFor` and `Check` let running code observe
the request; `Check` returns error `1650`. Cancelling a queued future removes
the job directly, whereas running work must inspect its token.

`std.concurrent.channel.Channel.new(capacity)` creates a bounded,
multi-producer/multi-consumer FIFO with backpressure. `Send`/`Receive` wait,
`SendFor`/`ReceiveFor` use millisecond timeouts and `TrySend`/`TryReceive` do not
block. A receive returns `ChannelReceive(received, value)`, so a valid `void`
message remains distinguishable from a closed and drained channel. `close()`
seals the writer side; queued values remain readable. Call `Dispose` only after
blocked users have returned and the channel has drained.

```ml
import std.concurrent.channel as channels
import std.concurrent.task as tasks
import std.concurrent.thread_pool as threadPool

function work(value, token)
  if token.IsCancellationRequested() then return token.Check() end if
  return value * 2
end function

pool = threadPool.ThreadPool.withQueueCapacity(4, 128)
future = tasks.runCancellable(pool, work, 21)
future.Wait()
print future.result() // 42
future.Dispose()

channel = channels.Channel.new(64)
channel.Send("ready")
item = channel.Receive()
if item.received then print item.value end if
channel.close()
channel.Dispose()

pool.Shutdown()
pool.AwaitTermination()
pool.Dispose()
```

### Function values (function pointers)

Functions are **first-class values**. A function name evaluates to a pointer to that function and can be:

- assigned to a variable
- stored in arrays / structs
- passed to other functions
- called indirectly via `fn(...)`

```ml
function add(a, b)
  return a + b
end function

fn = add
print fn(2, 3) // 5
```

Passing a function:

```ml
function apply(fn, a, b)
  return fn(a, b)
end function

print apply(add, 2, 3) // 5
```

Storing in an array (dispatch table):

```ml
function sub(a, b)
  return a - b
end function

ops = [add, sub]
print ops[0](10, 4) // 14
print ops[1](10, 4) // 6
```

Notes:
- `typeof(add)` is `"function"`.
- Inline expansion applies only to **direct** calls (e.g. `add(1,2)`), not to indirect calls like `fn(1,2)`.

Direct **and** indirect calls are supported.


### Program entry: main(args)

If a top-level function named `main` exists with exactly one parameter, it is treated as the program entrypoint:

```ml
function main(args)
  // args is an array of strings (argv[1..], without the program path)
  if len(args) > 0 then
    print args[0]
  end if
  return 0
end function
```

Rules:
- `main` must be declared at top-level (not inside a `namespace`).
- Signature must be `main(args)` (exactly 1 parameter).
- `args` contains `argv[1..]` (arguments after the executable name), parsed with Windows quoting rules.
- If `main` returns an `int`, it becomes the process exit code. If it returns `void` (no return), the exit code is `0`.
- The entrypoint call happens **after** module initialization has executed. Imported modules are initialized automatically before the entry file continues, and all module-init blocks run at most once.


### Recursion

```ml
function fact(n)
  if n <= 1 then
    return 1
  else
    return n * fact(n - 1)
  end if
end function

print fact(5)
```

### Scoping

- Lexical block scopes inside functions (variables are introduced on first assignment in the current block; shadowing is allowed).
- Functions are first-class values (you can store them in variables, pass them around, and call indirectly).
- Nested functions + closures are supported (captured vars are boxed and stored in an environment frame).
  - Current limitation: shadowing of a **captured** name is rejected by the compiler.
- Reading a name that has never been assigned in any visible scope is a compile error (“undefined variable”).
- Writing to a global from inside a function requires an explicit `global` declaration.
  - Unqualified names resolve to the active `package` / `namespace` context of the file.
  - If the global does not exist yet (no prior top-level initialization), the compiler creates it automatically and initializes it to `void`.
  - Globals are keyed by fully-qualified name, so `package Bar` + `Fu` is different from `package Bar2` + `Fu`.

`global` inside functions:

```ml
package demo

function inc()
  global counter
  if typeof(counter) == "void" then counter = 0 end if
  counter = counter + 1
end function

inc()
inc()
print counter // 2
```

You can also declare a qualified global explicitly:

```ml
function setOther()
  global other.pkg.counter
  other.pkg.counter = 123
end function
```

Robust syntax: trailing commas are allowed in `global` declarations:

```ml
function f()
  global counter, total,
  counter = 1
end function
```

---

## 10. struct

```ml
struct Person
  name
  age
end struct

p = Person("Alice", 30)
print p.name
p.age = p.age + 1
print p.age
```

### Methods (OOP-style)
**Inline methods:** You can also write `function inline name(...)` inside a
`struct` to request the same bounded direct-call expansion described in
[9. Functions](#9-functions).


You can define **instance methods** and **static methods** inside a struct.

- Instance methods get an implicit first parameter `this` (the instance).
- Access fields via `this.field`.
- Call instance methods via `obj.method(...)`.
- Call static methods via `StructName.method(...)`.

```ml
struct Box
  value

  function show()
    print this.value
  end function

  static function make(v)
    return Box(v)
  end function
end struct

b = Box.make(123)
b.show()
```

Notes:

- Struct constructors are calls: `Person(arg0, arg1, ...)` (argument count must match the field count).
- Field reads/writes are supported: `p.name`, `p.age = ...`.
- Statically known constructor, method, and field mistakes are diagnosed during
  compilation; dynamic invalid operations follow the runtime's normal
  `error`/`void` behavior.

---

## 11. enum

Ordinal enums currently support up to **65536 variants per enum** and up to **65535 ordinal-enum types** in one program.

Basic form:

```ml
enum Color
  Red
  Green
  Blue
end enum

c = Color.Red
print c
```

### Explicit values

Enum variants can optionally have `= <constexpr>` values (ints, strings, etc.). If a variant has **no** explicit value, the native compiler will:
- auto-increment by `+1` if the previous value is an `int`, otherwise
- require an explicit value (compile error).

```ml
enum Http
  Ok = 200
  Created      // 201
  Accepted     // 202
  NotFound = 404
end enum
```


---

## 12. Modules, namespace & import

### Overview
The native compiler supports **compile-time** composition:
- `namespace` groups declarations under a qualified name.
- `import` merges other `.ml` files into the program before code generation.


### namespace

```ml
namespace geom
  function add(a, b)
    return a + b
  end function

  struct Point
    x
    y
  end struct
end namespace
```

How to use it:
- Calls / constructors can be qualified: `geom.add(1,2)`, `geom.Point(1,2)`.
- In the native compiler, namespaces are **not runtime objects**; they are only used to qualify symbol names.

### import (top-level only)

```ml
import "path/to/other.ml"
```

Module-style form (syntactic sugar):

```ml
import foo.bar   // resolves to "foo/bar.ml"
```

Example with an include root:

```bash
python mlc_win64.py main.ml out.exe -I src
```

You can add multiple search roots by repeating the flag. The compiler also always treats the **directory of the entry file** as an implicit import root.

```bash
# repeat -I / --import-path (recommended)
python mlc_win64.py main.ml out.exe -I src -I std -I vendor
```

Notes:
- `-I` is repeatable. The current CLI does **not** split platform path lists like `src;std;vendor` automatically.

Rules:
- Paths are resolved relative to the importing file’s directory (absolute paths are also allowed).
- If the file is not found there, the compiler also searches the include roots in order: **entry file directory (implicit)** first, then the `-I/--import-path` directories (in the order provided).
- If an import matches multiple files across the search paths, compilation fails with an **ambiguous import** error listing the matches.
- Diagnostics prefer short, stable paths (relative to the entry file directory) when possible.
- Imported modules remain **declaration-oriented**. At top-level (and inside `namespace` blocks) the supported forms are:
  - `package`, `import`, `namespace`
  - `function`, `struct`, `enum`
  - `extern function` / `extern struct`
  - global `const` (initializer must be `constexpr`)
  - global assignments (runtime initializers are allowed)
  - enum variants with explicit `= <value>` must also be `constexpr`
- Imported top-level global assignments are compiled as internal **module initialization** code. They run automatically before `main(args)` and each module-init block runs at most once.
- Side-effectful top-level statements other than global assignments are still rejected in imported modules (for example `print`, top-level `if/while/for`, or arbitrary expression statements).
- Harmless import cycles are supported, and self-imports are ignored. Cycles that create unsafe cross-module initialization reads are diagnosed at runtime during module initialization.
- `import ... as <alias>` is supported: it creates a compile-time alias for the imported module’s `package` name, so you can write e.g. `g.add()` instead of `geom.vec.add()`. The imported file must declare `package ...`.
- Alias names must be valid identifiers and must not be reserved (`try`, `error`).
- If an imported file declares `package foo.bar`, its location must match that package when resolved via a stable root (importing directory or `-I` root): the file should be found as `foo/bar.ml` under that root. Absolute-path imports and aliased explicit file imports (`import "path/file.ml" as X`) skip this location check, which is useful for code-behind files.


### package (top-level only)

A file can declare its *package name* once at the very top:

```ml
package foo.bar
```

This is used by the native compiler’s import system (for `import ... as <alias>` and for verifying that a module’s file path matches its declared package when resolved via an import root).

Notes:
- `package` must be the **first** statement in the file (before `import`, `namespace`, `function`, etc.).
- It is compile-time only (no runtime effect).

### Module initialization

Imported modules may contain top-level global assignments such as:

```ml
package demo

players = [void, void, void, void]
count = len(players)
```

These assignments are compiled into internal module-init code. The compiler/runtime ensures that:

- imported modules initialize automatically before `main(args)`
- each module is initialized at most once
- self-imports are ignored
- simple cyclic imports are allowed
- unsafe cross-module reads during initialization are reported instead of silently using half-initialized state

Top-level `const` still stays compile-time only:

```ml
const Answer = 42
```

---

## 13. Standard Library & Builtins

### 13.1 Stdlib modules (std.*)

MiniLang ships with a source-based standard library in `std/`. You import it the same way you import your own modules:

```ml
import std.string as s
import std.time as t
import std.fs as fs
```

The stdlib is compiled together with your program (there is no separate link
step). Its public modules work on both supported targets. `std.fs`, `std.net`,
`std.time`, `std.threading` and the shared-value helpers select Win32 or
glibc/POSIX implementations at compile time while keeping one MiniLang API.
Cryptography uses Windows CNG on Windows and OpenSSL 3 (`libcrypto.so.3`) on
Linux. TLS uses Schannel on Windows and OpenSSL 3 (`libssl.so.3`) on Linux.
Linux images that use only libc-backed modules need no dependency beyond the
normal x64 glibc runtime; importing `std.crypto` or `std.tls` additionally
requires the OpenSSL 3 runtime package.

The current library contains 46 source modules, byte-for-byte identical in both
compiler repositories:

- **Core:** `std.core`, `std.assert`, `std.array`, `std.sort`, `std.math`,
  `std.random`, `std.fmt`
- **Text and bytes:** `std.string`, `std.string_builder`, `std.bytes`,
  `std.encoding.hex`, `std.encoding.base64`
- **System APIs:** `std.platform`, `std.path`, `std.process`, `std.console`,
  `std.time`, `std.fs`, `std.io.file`, `std.net`, `std.uuid` and `std.tls`
- **Collections:** `std.ds.list`, `std.ds.stack`, `std.ds.queue`,
  `std.ds.hashmap`, `std.ds.set`
- **Concurrency:** `std.threading`, `std.concurrent.thread_pool`,
  `std.concurrent.task`, `std.concurrent.cancellation`,
  `std.concurrent.channel`, `std.ds.concurrent_list`,
  `std.ds.concurrent_hashmap`
- **Native primitives:** `std.cpu`, `std.checksum.crc32c`,
  `std.checksum.crc32`, `std.crypto`, `std.crypto.aes_gcm`,
  `std.crypto._cng`, `std.crypto._openssl`, `std.tls._schannel` and
  `std.tls._openssl` (internal platform backends)
- **Compatibility helpers:** `std.result` provides `Option` and `Result`;
  `std.concurrent.shared_value` provides a legacy unmanaged snapshot codec;
  `std._linux_fs` is the internal POSIX filesystem backend.

`std.io.file` is the durable random-access API intended for databases and
servers: it provides positional reads/writes, truncation, flush, whole-file
advisory locks, atomic replacement and directory synchronization. `std.tls`
provides a built-in target-native Schannel/OpenSSL transport through
`connect(socket, options)` and `accept(socket, options)`. The original
provider-neutral callback contract remains available for custom transports.
See [Platform services](docs/PLATFORM_SERVICES.md) for certificate references,
trust behavior, socket ownership and the native integration test.

New code should normally use native `error(...)` propagation with `try(...)`
instead of `std.result.Result`. Managed objects already share one process-wide
heap, so `std.concurrent.shared_value` is not needed for ordinary communication
between MiniLang threads.

Stdlib APIs that can fail (I/O, networking, parsing, …) use MiniLang's native `error(...)` system. In practice this means a function either returns its normal value or an `error` value that automatically propagates unless you intercept it with `try(...)`.

```ml
import std.fs as fs

w = try(fs.writeAllText("demo.txt", "hello\n"))
if typeof(w) == "error" then
  print "write failed: " + w.message
end if
```

### 13.2 Builtins: basics

#### len(x)
Length of arrays, strings, or bytes.

```ml
print len([1,2,3]) // 3
print len("abc")   // 3
print len(bytes(4)) // 4
```

Current runtime behavior: unsupported types return `0`.

#### array(size[, fill])
Creates an array with a fixed size and optional fill value.

```ml
a = array(5)       // 5x void
b = array(5, 42)   // 5x 42
```

Invalid `size` (non-int, negative, or > `2147483647`) returns a runtime `error`
(catchable via `try(...)`).

#### input() / input(prompt)
Reads one line from stdin.

```ml
name = input("Name: ")
print "Hello " + name
```

#### toNumber(x)
Converts string -> int/float (or returns numbers unchanged).

```ml
a = toNumber("123")     // 123 (int)
b = toNumber("3.14")    // 3.14 (float)
c = toNumber(10)        // 10
```

Current runtime behavior: invalid inputs return `void`.

Not allowed:
- `toNumber(true/false)`
- `toNumber(void)`
- non-parsable strings

#### toFloat(x)

Converts an int, float, or numeric string to a float. Invalid inputs return
`void`. Unlike `toNumber`, an integral input still produces a `float`.

```ml
print typeof(toFloat(2))     // "float"
print toFloat("3.5")         // 3.5
```

#### str(x)

Converts a printable MiniLang value to a string. String concatenation uses the
same conversion implicitly.

```ml
print str(123)   // "123"
print str(true)  // "true"
```

#### typeof(x)
Returns a string describing the type of `x`.

Type strings: `int`, `float`, `bool`, `string`, `array`, `bytes`, `void`,
`function`, `enum`, `struct`, `error`, `thread`, `unknown`.

```ml
print typeof(123)      // "int"
print typeof("hi")     // "string"
print typeof([1,2,3])  // "array"

// error values
err = error(2, "bad input")
print typeof(err) // "error"
```

#### typeName(x)
Returns a concrete type name for structs/enums.

- For struct instances (and struct constructor values), returns the struct name.
- For enum values, returns the enum name.
- For all other values, behaves like `typeof(x)`.

Note: `typeof(x)` intentionally stays coarse (`"struct"` / `"enum"`) for backward compatibility.

```ml
struct Animal
  name
end struct

enum Color
  Red
end enum

a = Animal("Fay")
print typeof(a)      // "struct"
print typeName(a)    // "Animal"

print typeof(Color.Red)   // "enum"
print typeName(Color.Red) // "Color"
```

#### error(code, message) -> error value

Constructs an `error` value (fields: `.code` and `.message`).  
See **Chapter 15** for full semantics (automatic propagation and `try(...)`).

#### try(expr) -> value

Stops automatic error propagation for the given expression and returns either the normal value or the `error` value.  
See **Chapter 15** for full details.

### 13.3 Bytes / Encoding / File I/O

File I/O is provided via the stdlib module `std.fs` (see “File I/O” below).

#### bytes(...) / byteBuffer(...)
Creates a mutable `bytes` buffer.

- `bytes(size[, fill])` and `byteBuffer(size[, fill])` allocate `size` bytes, filled with `fill` (default 0).

- `bytes(...)` supports additional forms: `bytes()` (empty), `bytes(string)`
  (UTF-8), `bytes(array<int>)`, and `bytes(bytes)` (copy).
- `byteBuffer(size)` is a legacy alias (1 argument only). Use `bytes(size[, fill])` if you need a fill value.

```ml
buf = bytes(8)
print typeof(buf) // "bytes"
print len(buf)    // 8
buf[0] = 255
print buf[0]      // 255
```

#### decode(bytes[, encoding]) -> string
Decodes a byte buffer to a string.

- Expects a `bytes` object and decodes its complete payload as UTF-8.
- If `encoding` is provided it must be a string, but its content is currently
  ignored. Encodings other than UTF-8 are not implemented.

```ml
b = bytes(3)
b[0] = 65
b[1] = 66
b[2] = 67
print decode(b)           // "ABC"
print decode(b, "utf-8")  // "ABC"
```


#### decodeZ(bytes) -> string
Decodes a `bytes` object as UTF-8, but stops at the first NUL byte (`0x00`).  
Returns `void` on type errors.

#### decode16Z(bytes) -> string
Interprets a `bytes` object as UTF-16LE and stops at the first UTF-16 NUL (`0x0000`).  
Returns `void` on type errors.

Typical use: converting `wstr` data coming from `extern` calls into a MiniLang string.


#### hex(bytes) -> string
Encodes a `bytes` object as a lowercase hexadecimal string.

```ml
b = bytes(4)
b[0] = 0
b[1] = 17
b[2] = 170
b[3] = 255
print hex(b) // "0011aaff"
```

#### fromHex(string) -> bytes
Parses a hexadecimal string into a `bytes` object. Accepts an optional leading `0x` / `0X` prefix,
case-insensitive hex digits, and ignores common separators: spaces, tabs, newlines, `_`, `-`, `:`.
Current runtime behavior: invalid input returns `void`.

```ml
b = fromHex("00 11 aa ff")
print len(b) // 4
print hex(b) // "0011aaff"
```



#### std.encoding.base64

The stdlib module `std.encoding.base64` provides Base64 encode/decode:

```ml
import std.encoding.base64 as b64

b = b64.fromBase64("SGVsbG8=")   // bytes("Hello")
if typeof(b) == "bytes" then
  print decode(b)                // "Hello"
  print b64.toBase64(b)          // "SGVsbG8="
end if
```

Notes:
- `fromBase64(text)` ignores whitespace and returns `bytes` on success, `void` on invalid input.
- `toBase64(bytes)` returns a string on success, `void` on invalid args.


#### slice(bytes, offset, length) -> bytes
Returns a new `bytes` object containing a copy of `length` bytes starting at `offset`.

Rules:
- `offset` and `length` must be integers.
- `offset` may be negative (like indexing): `offset < 0` means `offset += len(bytes)`.
- Bounds are **strict** (no clamping): requires `0 <= offset <= len(bytes)` and `0 <= length` and `offset + length <= len(bytes)`.
- On any type/bounds error, returns `void`.


```ml
b = fromHex("00 11 22 33 44 55")
print hex(slice(b, 2, 3))   // "223344"
print hex(slice(b, -2, 2))  // "4455"
```

#### copyBytes(dst, dstOff, src, srcOff, len) -> void
Copies raw bytes from one `bytes` object into another.

Rules:
- `dst` and `src` must be `bytes`.
- `dstOff`, `srcOff`, and `len` must be non-negative integers.
- The effective copy length is clamped to the remaining tail room of both buffers:
  `min(len, len(dst) - dstOff, len(src) - srcOff)`.
- If an offset is already at or past the end of its buffer, or any argument is invalid, the call is a no-op and still returns `void`.
- Treat source/destination ranges as non-overlapping; overlap behavior is not guaranteed.

```ml
src = fromHex("00 11 22 33 44")
dst = bytes(5, 0)
copyBytes(dst, 1, src, 2, 3)
print hex(dst) // "0022334400"
```

#### copyArray(dst, dstOff, src, srcOff, len) -> void
Copies tagged values between arrays in one native operation. The copy is
shallow: strings, nested arrays, structs, and other managed objects remain the
same shared objects.

Rules:
- `dst` and `src` must be arrays.
- `dstOff`, `srcOff`, and `len` must be non-negative integers.
- The effective length is clamped to the remaining tail room of both arrays.
- Invalid arguments or offsets at/past an array end are a no-op.
- Treat source and destination ranges as non-overlapping; overlap behavior is
  not guaranteed.

```ml
src = [10, "twenty", true]
dst = array(5, 0)
copyArray(dst, 1, src, 0, len(src))
print dst // [0, 10, "twenty", true, 0]
```

#### fillBytes(dst, off, len, fill) -> void
Fills a range inside a `bytes` object with a repeated byte value.

Rules:
- `dst` must be `bytes`.
- `off` and `len` must be non-negative integers.
- `fill` must be an integer in the range `0..255`.
- The effective fill length is clamped to the remaining tail room of `dst`.
- If `off` is at/past the end, or any argument is invalid, the call is a no-op and still returns `void`.

```ml
b = bytes(6, 0)
fillBytes(b, 2, 10, 0xAB)
print hex(b) // "0000abababab"
```

#### Low-level string and bytes helpers

The runtime also exposes the primitives used to implement `std.string`,
`std.string_builder`, `std.bytes`, and hash maps: `stringHash`, `bytesHash`,
`stringSlice`, `stringIndexOf`, `stringLastIndexOf`, `stringStartsWith`,
`stringEndsWith`, `stringRepeat`, the ASCII trim/case/reverse helpers,
`stringEqualsIgnoreCaseAscii`, `stringJoin`, `bytesStartsWith`, `bytesEndsWith`,
`bytesIndexOf`, `bytesLastIndexOf`, `bytesCompare`, and `copyStringBytes`.
Application code should normally prefer the checked wrappers in the
corresponding `std.*` modules.

#### File I/O
The native runtime currently does not expose low-level file-handle builtins.

File I/O is provided by the **standard library** module `std.fs`, with convenience helpers like:
- `writeAllText`, `readAllText`, `readAllLines`, `appendAllText`
- `writeAllBytes`, `readAllBytes`
- `exists`, `delete`, `fileSize`, `copyFile`, `moveFile`

Most functions that can fail return either their normal value or `error(...)`.
A few APIs return plain `bool` (e.g. `exists`, `delete`).

Example:

```ml
import std.fs as fs
import std.string as s

p = "hello.txt"
chk = try(fs.writeAllText(p, "hello\nworld\n"))
if typeof(chk) != "error" then
  r = try(fs.readAllText(p))
  if typeof(r) != "error" and s.startsWith(r, "hello") then
    print "ok"
  end if
end if
```

### 13.4 Heap / GC debug

These builtins are intended for debugging and validating the generated runtime.

#### heap_count()
Returns the number of *currently live* heap blocks (objects that are not marked as `free`).

#### heap_bytes_used()
Returns the current bump pointer offset: `heap_ptr - heap_base`.
Note: after GC + optional shrink, `heap_ptr` may move backwards (trim-from-top).

#### heap_bytes_committed()
Returns the currently committed heap bytes: `heap_end - heap_base`.

#### heap_bytes_reserved()
Returns the reserved heap address space: `heap_reserve_end - heap_base`.

#### heap_free_bytes()
Returns the total number of bytes in the free-list (sum of free blocks).

#### heap_free_blocks()
Returns the number of blocks currently in the free-list.

#### gc_collect()
Runs the mark/sweep collector and returns `void`.

#### gc_set_limit(limitBytes)
Sets the allocation threshold for the **periodic** GC trigger and returns
`void`.

- A positive integer enables periodic collection with that byte limit.
- Zero, a negative value, or a non-integer disables the periodic trigger.
- The allocation-failure/OOM retry collector remains enabled.
- The current periodic-allocation counter is reset when the limit changes.
- The calling thread's current TLAB is retired, so a new positive limit applies
  to its next allocation rather than its next buffer refill.

Notes (when does GC run?):
- The GC runs **automatically** when an allocation cannot be satisfied and the heap can’t grow further; the runtime triggers a `fn_gc_collect` once and retries the allocation.
- You can also trigger it manually via `gc_collect()`.

Notes:
- Small objects in threaded programs use 64 KiB TLABs; the whole refill is
  charged to periodic/young-allocation pressure once.
- The central allocator reuses freed blocks via a free-list and falls back to
  bump allocation.
- If the bump pointer would exceed the committed end, the runtime commits more pages (up to the reserved limit).
- If `--heap-shrink` is enabled, the runtime may decommit unused pages at the top of the heap after GC (trim-from-top).

---


### 13.5 Call profiling (optional)

When compiling with `--profile-calls`, the compiler instruments **user functions** with call counters.
At runtime you can query them via `callStats()`.

```ml
stats = callStats()
if typeof(stats) == "array" then
  for each s in stats
    // each entry is a small struct-like record; print it to inspect fields
    print s
  end for
end if
```

Notes:
- Without `--profile-calls`, `callStats()` is not meaningful (and may return `void`).
- Instrumentation adds overhead; use it for profiling/debugging, not for release benchmarking.


## 14. extern

The native compiler can generate PE imports from `extern` declarations.


### extern function

Syntax:

```ml
extern function <Name>(<params...>) from "<dll>" [symbol "<exportedName>"] [returns <type>]
```

Parameter forms:
- `<type>` (type-only)
- `<name> as <type>` (named, type-checked)
- `out <type>` / `out <name> as <type>` (**experimental**, see below)

Supported ABI types for direct-call inputs:
- `int` / `i64` / `u64` / `i32` / `u32`
- `double`
- `bool` (accepts `bool` or `int` at the call site)
- `ptr` / `pointer` (accepts a native pointer value, `int`, or `void`;
  `void` becomes `NULL`)
- `cstr` / `cstring` (MiniLang `string` → `char*` UTF-8; `void` becomes `NULL`)
- `wstr` / `wstring` (MiniLang `string` → `wchar_t*` UTF-16LE; `void` becomes `NULL`)
- `bytes` / `buffer` / `bytebuffer` (MiniLang `bytes` → pointer to its
  mutable payload; `void` becomes `NULL`)

Supported return types:
- `void` / `none`
- `int` / `i64` / `u64` / `i32` / `u32`
- `ptr` / `pointer`
- `double`
- `bool`
- `cstr` (reads a NUL-terminated `char*` and converts to a MiniLang `string`; `NULL` → `void`)
- `wstr` (reads a NUL-terminated `wchar_t*` and converts to a MiniLang `string`; `NULL` → `void`)

Notes:
- Arity mismatches are a **compile error**.
- Type mismatches at runtime currently return `void` (no exceptions yet).
- `wstr` arguments use a fixed temporary UTF-16 buffer. Very long strings may fail and return `void`.
- If the DLL or symbol can’t be resolved, Windows will usually refuse to start the program (loader error) because imports are resolved by the OS loader.

Example: MessageBox

```ml
extern function MessageBoxW(hwnd as ptr, text as wstr, caption as wstr, style as int)
  from "user32.dll" symbol "MessageBoxW" returns int

MessageBoxW(void, "Hello from MiniLang!", "MiniLang", 0)
```

Example: GetTickCount

```ml
extern function GetTickCount() from "kernel32.dll" returns u32
print GetTickCount()
```

### Native callbacks

`nativeBytesPtr(bytes)` returns a native pointer to the payload of a MiniLang
`bytes` value. The result is represented as a MiniLang `int` so it can be passed
to `ptr` extern parameters or stored in native interop structures. For non-bytes
arguments it returns a null pointer value.

`nativeRawValue(value)` returns a MiniLang `int` containing the raw tagged
MiniLang value. `nativeValueFromRaw(int)` performs the inverse conversion.
These are low-level interop helpers for native APIs that store an opaque
application value and later return it unchanged.

`nativeCallback(fn, "wndproc")` returns a native Win64 callback pointer for a top-level MiniLang function.
The supported mode currently targets Win32 `WNDPROC` callbacks:

```ml
extern function CallWindowProcW(prev as ptr, hwnd as ptr, msg as u32, wParam as ptr, lParam as ptr) from "user32.dll" symbol "CallWindowProcW" returns ptr

function myWndProc(hwnd, msg, wParam, lParam)
  return msg
end function

cb = nativeCallback(myWndProc, "wndproc")
print CallWindowProcW(cb, 0, 1024, 0, 0)
```

Rules:
- The first argument must be a top-level MiniLang function.
- `"wndproc"` callbacks must accept exactly four parameters: `hwnd`, `msg`, `wParam`, `lParam`.
- The callback return value is converted back to native `LRESULT`; `int` and `bool` are supported, other values return `0`.

### extern struct (experimental)

The frontend also accepts `extern struct` declarations to describe an ABI layout:

```ml
extern struct POINT
  x as i32
  y as i32
end struct
```

Layouts use Win64 C-style sequential placement, natural field alignment and a
maximum alignment of eight bytes. Supported fields are `i8/u8`, `i16/u16`,
`i32/u32`, `i64/u64`, `int`, `bool` (Win32 `BOOL`) and `ptr/pointer`. Structs returned
through an implicit `out` parameter are copied into a normal GC-managed
MiniLang struct, so they remain valid after the native call returns. Automatic
managed-field marshaling currently supports `int/i64/u64`, `i32/u32`,
`bool`, and `ptr`; for layouts containing `i8/u8` or `i16/u16`, pass
an explicit `bytes` buffer and decode those fields in MiniLang.

### out parameters (experimental)

You can mark trailing parameters as `out`:

```ml
extern function GetCursorPos(out p as POINT) from "user32.dll" returns bool
```

Rules:
- `out` parameters must appear **at the end** of the parameter list (so they can be implicitly handled at call sites).
- A direct call may omit all trailing `out` arguments. Storage is allocated in
  the current thread's stack frame and is therefore thread-safe and valid for
  the duration of the native call.
- One omitted `out` value becomes the call result. Multiple omitted values are
  returned as a MiniLang array in declaration order.
- If such a call has native return type `bool`, a false result becomes a
  catchable MiniLang `error`; otherwise the native status/result is discarded
  in favor of the marshaled out value(s).
- Full-arity calls remain accepted for backward compatibility. Automatic out
  allocation/marshaling is enabled by omission at a direct call site; indirect
  extern function values retain their declared full arity.

---

## 15. Error handling: `error` & `try`

MiniLang uses **error values** for lightweight error handling (no exception mechanism).  
An error is a normal value with:

- `.code` (int)
- `.message` (string)

### 15.1 Creating an error value

Use the builtin `error(code, message)`:

```ml
return error(2, "bad input")
```

You can also construct and return errors from within helper functions and stdlib code.

### 15.2 Automatic propagation (implicit bubbling)

If a **function call** evaluates to an `error` value, the caller will **automatically return that error** immediately (as if an implicit `return <that error>` happened).

This continues up the call stack until the error is handled or it reaches top-level.

```ml
function parseInt(s)
  // ... on failure:
  return error(100, "not a number")
end function

function loadConfig(path)
  // If parseInt(...) returns an error, loadConfig(...) returns it automatically.
  port = parseInt("oops")
  return port
end function

// If unhandled, an error that reaches top-level terminates the program.
loadConfig("cfg.txt")
```

### 15.2.1 Optional APIs (`void` as absence/failure)

Some builtins intentionally return `void` to indicate failure/absence, e.g.:
- `fromHex(str)`
- `slice(bytes, off, len)`
- `decode(bytes, encoding)`

If you prefer strict behavior, use the stdlib wrappers that return `error(...)` instead:
- `std.encoding.hex.decodeOrError(s)`
- `std.bytes.fromHexOrError(s)`
- `std.bytes.subOrError(b, off, len)`
- `std.bytes.decodeUtf8OrError(b)`

### 15.3 Catching propagation with `try(expr)`

Use `try(expr)` to **stop** the automatic propagation and get back either the normal value or the `error` value.

`try(...)` is a **special form** (its argument is evaluated lazily so it can intercept the propagation).

```ml
e = try(loadConfig("cfg.txt"))

if typeof(e) == "error" then
  print "config error: " + e.message
else
  print "config ok, port=" + e
end if
```

Typical pattern:

- call with `try(...)`
- check `typeof(x) == "error"`
- handle / recover, or re-`return x` to propagate manually

### 15.4 Toolchain diagnostics

The toolchain reports errors with:

- filename
- line/column (when available)
- the relevant source line
- a `^` marker (when available)

#### Parse errors (frontend)
- `ParseError` (syntax / parsing)

#### Compile errors (native backend)
- `CompileError` (code generation / backend validation)

Example (schematic):

```
ParseError: unexpected token
  at main.ml:3:10
  x = 5 / ?
           ^
```

---

## 16. Syntax Reference (short)

### Compile-time directives
- `#option NAME: bool|int|string = <compile-expression>`
- `#const NAME = <compile-expression>`
- `#if <bool-expression>` / `#elif` / `#else` / `#endif`
- `#error <string-expression>`
- CLI override: `-DNAME[=VALUE]` or `--define NAME[=VALUE]`

### Statements
Statements are separated by newlines or `;`.

- `print <expr>`
- `const <ident> = <expr>` (top-level/namespace requires `constexpr`)
- `synchronized <ident> = <expr>` (top-level/namespace shared binding)
- `<lvalue> = <expr>`
  - `<ident> = ...`
  - `<expr>.<field> = ...`
  - `<expr>[<index>] = ...` (multiline indexing allowed)
- `function name(a,b) ... end function` (multiline params allowed, trailing comma optional)
- `function name(a as int, b as string? = void, rest...) returns int ... end function`
- `async function name(...) ... end function` / `[lazy] iterator function name(...) ... end function`
- `interface Name ... end interface`; `struct Name implements Interface ... end struct`
- `function synchronized name(a,b) ... end function` (process-wide recursive monitor)
- optional entrypoint: `function main(args) ... end function`
- `return` / `return <expr>` / `return;` (and bare `return` directly before `end/else/case` in inline blocks)
- `defer <call-expression>` (inside functions; LIFO cleanup on every function exit)
- `global x, y, z` (inside functions; trailing comma optional; names may be qualified like `foo.bar.x`)
- `if <expr> then ... end if` (block or inline)
- `while <expr> ... end while`
- `loop ... while <expr> end loop` (legacy: `loop ... end loop while <expr>`)
- `for i = <expr> to <expr> ... end for`
- `for each x in <expr> ... end for`
- `break` / `break <int>`
- `continue`
- `switch <expr> ... end switch`
- `match <expr> ... end match` (value/list/range/default cases)
- `struct Name ... end struct` (optional legacy `are` after the name)
- `enum Name ... end enum` (optional legacy `are` after the name; native supports optional `= <constexpr>` values)
- `namespace Name ... end namespace` (top-level or nested in namespaces; imported modules remain declaration-oriented, but top-level global assignments are allowed; native compiler)
- `package foo.bar` (top-level only; must be the first statement; native compiler)
- `import "relative/or/absolute/path.ml" [as <alias>]` (top-level only; native compiler)
- `import foo.bar [as <alias>]` (module-style import; resolves to `foo/bar.ml`; native compiler)
- `extern struct Name ... end struct` (native compiler; experimental)
- `extern function Name(...) from "dll" ...`

### Expressions
- literals: number, string, `true/false`, `[ ... ]` (multiline + trailing comma allowed)
- variable: `name`
- call: `f(a,b)` or `f(second = 2, first = 1)` (multiline args + trailing comma allowed)
- lambda: `function(x as int) returns int => x + 1`
- optional access/fallback: `value?.member`, `value?.method()`, `left ?? fallback`
- async wait: `await handle`; first completion: `select(handle1, handle2)`
- native thread: `Thread(topLevelFunction)`; methods `Start`, `Stop`, `Join`, `Status`, `IsAlive`, `Id`, `Close`
- index: `arr[i]`
- member: `obj.field`
- unary: `-x`, `not x`, `~x`
- binary: `+ - * / % == != > < >= <= and or`
- bitwise: `<< >> & | ^`

Newlines are allowed after operators/unary operators and in common "list" positions (see [3.1](#31-newlines--statement-separators)).

---

## 17. Examples

### 17.1 FizzBuzz

```ml
for i = 1 to 30
  if i % 15 == 0 then
    print "FizzBuzz"
  else if i % 3 == 0 then
    print "Fizz"
  else if i % 5 == 0 then
    print "Buzz"
  else
    print i
  end if
end for
```

### 17.2 Functions + array processing

```ml
function sum(arr)
  total = 0
  for each x in arr
    total = total + x
  end for
  return total
end function

nums = [1,2,3,4]
print sum(nums)
```

### 17.3 Struct + switch

```ml
struct User
  name
  role
end struct

u = User("Nina", "Admin")

switch u.role
  case "Admin"
    print u.name + " is admin"
  end case

  case default
    print u.name + " is user"
  end case
end switch
```

### 17.4 Enum

```ml
enum Role
  Admin
  Guest
end enum

r = Role.Admin
print r
```
## Native compiler status

The native x64 backend generates deterministic Windows PE32+ images (console by
default, optionally GUI) and deterministic Linux ELF64 images. The language
runtime, global GC heap, TLAB allocator, native threads and synchronization are
implemented on both targets.

What works:
- core types: int, float, bool, string, array, bytes, void
- control flow: `if/else`, `while`, `loop ... while ... end loop`, `for ... to`, `for each ... in`, `switch/case`, `break`/`break n`, `continue`
- LIFO deferred cleanup with `defer`, including return/fall-through/error exits
- bounded source-level `inline` functions with callable fallback bodies
- first-class functions: user functions and many builtins are values; direct **and** indirect calls are supported
- gradual runtime-checked type contracts, optional values/access, default/named/variadic calls and expression lambdas
- value/range `match`, eager/lazy `iterator function`/`yield`, structural compile-time interfaces and pooled `async`/`await`/`select`
- real native threads on Win32 and Linux with cooperative cancellation, data/result handoff,
  native and logical ids, status/join APIs, private stacks, a process-wide
  thread-safe GC heap, synchronized globals/functions, fine-grained
  `synchronized(lock)` blocks and managed thread pools;
  Linux workers use pthread creation/join so libc TLS, malloc, synchronization
  and native providers remain valid on every worker
- futures/tasks with cooperative cancellation, ordered/all-or-first completion
  helpers and bounded multi-producer/multi-consumer channels
- nested functions + closures (captured vars are boxed and stored in an environment frame)
- `main(args)` entrypoint (argv[1..] as `array<string>`, `return int` -> process exit code)
- `global` declarations inside functions (required for accessing globals from a function; resolves to package/namespace-qualified globals; missing globals are auto-created as `void`)
- `struct` (constructors + field read/write)
- `enum` (values like `Color.Red`, comparisons, printing, `switch`)
- `namespace` blocks (compile-time name qualification)
- `package` + `import` (compile-time multi-file merge; imported modules support runtime-initialized globals, self-import ignore, and harmless import cycles)
- `const` (write-once bindings; top-level/namespace consts are evaluated at compile time)
- `enum` explicit values (constexpr) + auto-increment for missing int values
- `extern function` via the PE import table (IAT) on Windows or ELF dynamic
  imports on Linux, ABI-layout `extern struct` and omitted trailing `out`
  parameters; native Win64 callback pointers remain Windows-specific
- TOML project manifests with conservative exact-hit artifact caching
- typed conditional compilation with CLI/project definitions and target values
- builtins / special forms: `len`, `input`, `toNumber`, `toFloat`, `str`,
  `typeof`, `typeName`, `error`, `try`, `array`, `bytes`/`byteBuffer`,
  `decode`, `decodeZ`, `decode16Z`, `hex`, `fromHex`, `slice`, `copyBytes`,
  `copyArray`, `fillBytes`, native string/bytes helpers, `Thread` and its worker
  helpers,
  `nativeBytesPtr`, `nativeRawValue`, `nativeValueFromRaw`, `nativeCallback`,
  plus debug helpers: `heap_count`, `heap_bytes_used`, `heap_bytes_committed`, `heap_bytes_reserved`, `heap_free_bytes`, `heap_free_blocks`, `gc_collect`, `gc_set_limit`, `callStats`

Debugging / listings:
- `--asm` writes a combined `.asm` listing
- `--asm-pe` prepends a PE header + section table dump for Windows targets
- `--asm-data` appends `.rdata/.data/.idata` dumps (useful to inspect constants and imports)

Heap sizing flags:
- `--heap-reserve <size>`: reserved address space
- `--heap-commit <size>`: initial committed bytes
- `--heap-grow <size>`: minimum commit growth step
- `--heap-shrink`: enable decommit after GC (trim-from-top)
- `--heap-shrink-min <size>`: minimum committed heap when shrinking

Optimizations (always-on, conservative):
- **Constant pooling**: identical `.rdata` constants are stored once and referenced by multiple sites.
- **Bounded inlining with safe fallback bodies**: eligible direct calls expand
  up to 4096 generated native bytes per callee; every function retains a normal
  callable body so imported aliases, data references and later calls remain
  valid.
- **Local representation type flow**: locals whose complete write set proves a
  stable `int`, `float`/number, `bool`, string, array, bytes or concrete struct
  representation bypass the corresponding dynamic dispatch. This includes
  direct tagged integer operations, numeric-only float arithmetic, bool
  conditions, fixed-offset struct fields and type-specialized indexing.
  Parameters, captured/boxed, synchronized, global or otherwise ambiguous
  values retain the generic checked path. Fallible division, modulo, shifts
  and byte-buffer construction receive facts only when their runtime validity
  is statically proven.
- **Known-receiver method devirtualization**: a method call on a local whose
  concrete struct type is proven becomes a direct call. Eligible `inline`
  methods can then expand at the call site; ambiguous receivers retain the
  checked polymorphic inline-cache path.
- **Hot primitive register homes**: up to two uniquely named `int`/`bool`
  locals written inside loops are mirrored in nonvolatile XMM6/XMM7 registers.
  Their stack slots remain canonical for diagnostics and interop, and the full
  128-bit caller register values are preserved according to the Win64 ABI.
- **Constant integer strength reduction**: tagged additions/subtractions use
  immediates, constant multiplication uses zero/identity/negation/shift or
  immediate multiply forms, positive power-of-two modulo uses a mask, and
  constant shifts avoid the CL setup. Dynamic or otherwise unproven cases
  retain the generic checked code paths. Compile-time integer evaluation wraps
  after every operation to the signed 61-bit payload and masks nonnegative x64
  shift counts exactly like generated code.
- **Loop specialization and bounds-check elimination**: small constant `for`
  loops can be unrolled; larger constant-bound loops avoid dynamic end/direction
  state. For a fixed-length local array or bytes value, an inclusive range
  proven inside `0..len(value)-1` loads the container base once and removes the
  per-iteration target, index-tag and bounds checks. Negative or unproven
  indices retain normalization and full bounds validation.
- **GC-root liveness and prologues**: expression roots are unpublished as soon
  as their lifetime ends, call spills are sized to actual arity, and tiny root
  frames use straight-line initialization.
- **Thread-local allocation buffers**: small managed objects use a lock-free
  per-thread cursor inside 64 KiB ranges of the shared heap. Refill, retirement,
  large objects and collection remain serialized and preserve one global object
  identity space.
- **Branch/peephole optimization**: resolved backward edges use x64 short
  branches when in range, jumps to the immediately following label disappear,
  and local redundant instruction patterns are folded.
- **Helper pruning**: only referenced `fn_*` runtime helpers are emitted.

GC flags:
- `--gc-limit <size>` overrides the periodic GC threshold (default: `1m` in the current backend).
- `--no-gc-periodic` disables periodic GC triggering (GC runs only on allocation failure / OOM path).

## Native checksums, cryptography, and SIMD search

The standard library includes reusable CRC-32C/CRC-32, platform-native
cryptography, and CPU-dispatched byte/string search. Public wrappers live in
`std.checksum.*`, `std.crypto`, `std.crypto.aes_gcm`, and `std.cpu`;
checksum helpers and their lookup tables are emitted only when referenced,
while search accelerates the existing first-class string/bytes builtins.

CRC-32C uses SSE4.2 when available and a bit-identical software fallback.
Search uses AVX2, SSE2, or scalar candidate scans while preserving byte-indexed
string semantics. Cryptography is backed by Windows CNG or Linux OpenSSL 3 and includes
AES-256-GCM, SHA-256/384, HMAC, HKDF, X25519, system CSPRNG,
constant-time byte comparison, and best-effort secure erasure.

See [the native primitives guide](docs/NATIVE_PRIMITIVES.md) for API details,
polynomials, dispatch controls, and security assumptions. Focused tests live in
`tests/checksum_runtime.ml`, `tests/crypto_cng.ml`, and
`tests/simd_search.ml`; reproducible measurements live in `benchmarks/`.
