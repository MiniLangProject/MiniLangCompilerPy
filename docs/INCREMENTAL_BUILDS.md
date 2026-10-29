# Incremental builds

Both compilers can reuse native functions after source edits. They preserve
the canonical clean-build instruction stream: incremental and clean output,
Python and native output, and native monolithic and object-pipeline output
must remain byte-identical for the same target, inputs and options.

## Enable it

An existing project manifest needs no migration:

```toml
[project]
entry = "src/main.ml"
output = "build/app.exe"
incremental = true
cache_dir = ".minilang-cache"
```

```text
python mlc_win64.py --project minilang.toml
mlc_win64.exe --project minilang.toml
```

Build scripts that directly invoke the compiler can opt in without a manifest:

```text
python mlc_win64.py src/main.ml build/app.exe --incremental-cache build/compiler-cache
mlc_win64.exe src/main.ml build/app.exe --incremental-cache build/compiler-cache
mlc_win64.exe src/main.ml build/app --target linux-x64 --incremental-cache build/compiler-cache
```

`--no-incremental` bypasses reads and writes, including when a cache directory
is explicitly supplied. Assembly listings and label dumps bypass function
reuse so their requested diagnostic output is generated normally. A manifest
with `incremental = false` also disables reuse in native child emitters.

## What is reused

1. An exactly unchanged manifest build restores its checksum-validated final
   executable. The native compiler can also relink its existing validated
   complete object set if the final artifact is missing.
2. After edits, both compilers parse the current import graph and recompute
   global semantic/optimization decisions. They then reuse compatible
   functions' machine code, labels, relocations and section changes.
3. Changed modules' functions are lowered again. A fragment whose declaration,
   inline dependency, body-derived global facts or incoming layout has changed
   is also lowered again. Linking always runs for a changed build.

The report `[incremental] reused=N compiled=M invalid=K` counts actual native
function reuse, regular function lowering, and rejected damaged entries.
The native object emitter reports its own counts; a coordinator that only
links does not report a second set of function counts.

This is intentionally conservative. Global declarations and inline bodies can
invalidate many functions. Labels, section offsets, constant pools and inline
budgets currently belong to one canonical stream. A size/layout change can
therefore invalidate later fragments even when their source files are
unchanged. Same-layout edits often preserve those later hits. This does not
yet cache parsing or provide fully independent per-module object code.

## Correctness and cache lifetime

Keys include compiler content, effective target/options/defines, declaration
and inline dependencies, and the exact module text read by the frontend.
The Python compiler also fingerprints a selected external parser override.
File modification times alone are never sufficient. Constant-pool aliases,
helper reachability, binding/label counters and inline budgets are restored
alongside the emitted bytes. Cached unused functions have already undergone
semantic checking; changed source and semantic context invalidate that proof.

Entries are bounded, checksummed primitive data with explicit schemas.
Corruption or an unsupported record becomes a cache miss. Publication uses
per-process temporary files and atomic replacement. A failed function-cache
write, including a Windows sharing conflict with another reader, does not
fail compilation. Whole-build fingerprints are rechecked before publication
to avoid storing an artifact under inputs changed during the build.

Python and native cache records use separate subdirectories and are not an
interchange format. Each function slot keeps its latest generation. Removing
the cache directory is safe when builds are stopped; a subsequent build
recreates it. Renamed/removed functions can leave unused slots until cleanup.

## Integrating asset pipelines

The compiler caches compiler inputs. A build script that regenerates an
encrypted asset package and its random key module on every invocation still
changes those inputs and can invalidate global declarations. Reuse that
package/key module when its asset inputs are unchanged, then pass
`--incremental-cache` at the existing compiler invocation. Asset encryption
keys must continue to follow the application's existing lifecycle.

## Verification and measurement

Both repositories contain the same validation and measurement drivers:

```text
python tests/check_incremental.py --ml-compiler PATH_TO_NATIVE_COMPILER --report build/incremental.json
python tests/check_incremental.py --ml-compiler PATH_TO_NATIVE_COMPILER --target linux-x64 --report build/incremental-linux.json
python tests/check_incremental_regressions.py --ml-compiler PATH_TO_NATIVE_COMPILER --report build/incremental-regressions.json
python tests/bench_incremental.py --ml-compiler PATH_TO_NATIVE_COMPILER --report build/incremental-benchmark.json
```

The regression driver executes Linux images through WSL Ubuntu when run on
Windows, or directly when run on Linux. Use `--target linux-x64` on Linux.
The benchmark currently measures Windows builds on a Windows host. It uses
isolated generated modules, alternating compiler order, repeated runs, and
clean-build byte comparisons after every edit.
Windows memory numbers sample private bytes of the complete compiler process
tree; they are not live-object sizes. Run timing measurements without other
builds or tests competing for CPU and memory.

See the [implementation and measurement report](reports/INCREMENTAL_BUILDS_2026-10-29.md)
for the test results, edit benchmarks, self-build timings and memory costs.
