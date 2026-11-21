# Fixed variable type contracts (2026-11-21)

`var name as Type = expression` opts into a checked binding. This preserves
the behavior of existing programs that use `name as Type = expression` for
a single write and later assign values of a different type. Both compilers
lower fixed local writes before inlining and analysis. A module slot's
contract follows qualified writes and function object emission. Changing a
module contract invalidates dependent native fragments in both caches.

The runtime checks a fixed binding's actual tagged value. A mismatch produces
error 1308 before the store. The compiler diagnoses incompatible primitive
literals and conflicting annotations. It elides checks for proven primitive
copies and supported integer expressions. The runtime Value layout and call
ABI are shared with ordinary MiniLang.

## Runtime measurements

Windows x64, ten interleaved process runs per image after discarding the
first run. The existing syntax column uses the same source with `var` removed.
The checked column uses fixed declarations with the two new check elisions
disabled in the Python compiler for the measurement. All images in each row
produced the same output.

| Benchmark | Existing syntax | Fixed, checks retained | Fixed, optimized |
| --- | ---: | ---: | ---: |
| [Integer loop](../../benchmarks/typed_binding_loop.ml), 30 million iterations | 84.79 ms | 86.60 ms | 84.32 ms |
| [String copy](../../benchmarks/typed_binding_copy.ml), 30 million iterations | 76.34 ms | 71.44 ms | 76.71 ms |

The optimized integer case matched the existing syntax within observed run
variation. Its executable is 81,408 bytes versus 81,920 bytes with checks
retained. The string case removed the copy check from the loop but showed no
runtime win. Its three executables are 81,920 bytes each. These timings include
process startup and describe the two measured programs.

## Verification

The executable hashes below are from the development builds before the
version bump. See the [release verification matrix](release-1.3.10-version-matrix.json)
for the tagged 1.3.10 binaries.

- The Python suite passed all 257 tests. The self-hosted suite passed all
  173 inner tests and completed its additional platform and library tests.
- The Windows and Linux parity matrix covered seven fixtures per target with
  Python, self-hosted monolithic, and self-hosted object builds. Each set of
  three images was byte-identical. The seven Windows programs and both new
  Linux runtime fixtures passed.
- A cross-module cache probe changed a declaration from a single-write
  annotation to a fixed binding. Both compilers rejected the previously
  allowed write on the next build and agreed byte for byte after a cache hit.
- Windows self-hosting reproduced the Python bootstrap exactly.
  SHA-256 `70471F7FE3A1066461BC2219D49287E4D52F7E1B25B7A7B575C99E7EE2FDCD17`.
- The Linux compiler images produced by Python and ML are byte-identical.
  SHA-256 `94A5F0EDE0C344190AC8C6BC799D70B440A50A9145F3D71346E65EC504911FA8`.
  The Linux compiler also built and ran the fixed binding fixture under WSL.
