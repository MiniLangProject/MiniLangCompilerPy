# OOP method dispatch: correctness and measurements — 14 November 2026

The Python and self-hosted compilers now emit a checked direct call when a
dynamic method name and arity have one or two implementations in the complete
program. The existing two-entry inline cache remains for larger method sets.
Both backends also propagate an exact local type fact from a required typed
parameter whose class has no descendants. A polymorphic base remains virtual,
and incompatible local writes invalidate the fact. The Python backend now
preserves outgoing stack arguments on dynamic method calls with more than eight
total arguments, matching the native backend and fixing an existing parity and
stack-lifetime discrepancy.

The [JSON record](OOP_DISPATCH_2026-11-14.json) includes every sample, image
hashes and memory measurements. The before compilers are the released 1.3.5
builds; both versions compile identical benchmark source.

## Correctness and byte parity

The new regression checks one and two candidate sets, calls with nine total
arguments, ordered argument side effects, wrong-class and nonobject receivers,
and a guarded final-class parameter. Existing class, interface, override and
constructor tests remain active. Results:

- Python integration: **228/228**; unit tests: **45 passed**, one optional skip.
- Native harness: **144/144**, with **259/259** additional steps.
- **144 OOP images byte-identical per target** across Python, Windows-native and
  Linux-native compilers and both object/monolithic pipelines. One canonical
  image for each fixture and target is executed.
- Python bootstrap and native self-build agree for Windows and Linux compiler
  images. Benchmark output images agree across both compilers per target.

Windows compiler SHA-256: `50ef95213edad3006e328f0e1b66dba64316701916ee08de820ba69d290632a8`.
Linux compiler SHA-256: `4343aab1a8100db95ba0c280aa262bbbaa6db511a619eba4c6250f54ad2f3fa1`.

## Compilation and generated size

`benchmarks/generate_oop_call_sites.py` creates 400 dynamic call sites. One
warm-up and nine alternating measured rounds use logical CPU 4. Time includes
compiler startup and complete output. Memory is peak private commitment of the
compiler process tree, rather than physical RAM.

| Compiler | Before median ms | After median ms | Time change | Peak commitment before / after |
| --- | ---: | ---: | ---: | ---: |
| ML compiler | 271.7 | 250.1 | -8.0% | 522.3 / 522.3 MiB |
| Python compiler | 337.0 | 320.7 | -4.8% | 31.8 / 30.8 MiB |

The generated Windows image falls from **634,368** to **562,688 bytes**
(-11.3%). The smaller method path also removes the
writable cache data at these call sites. The source stresses repeated calls to
the same method; compile-time results do not imply the same percentage for a
whole application.

## Generated-program runtime

`benchmarks/oop_dispatch.ml` calls methods 20 million times per case without
allocating in the loop. `mono` has one candidate, `typed` has a final-class
parameter, `poly` alternates two implementations, and `control` is an integer
loop. Each image is warmed once. The runner alternates before and after for
15 samples per case on CPU 4 and checks identical result checksums. Windows
uses QPC; Linux uses `CLOCK_MONOTONIC`.

| OS | Case | Before median ms | After median ms | Change | Heap delta before / after bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| Windows | mono | 95.49 | 81.99 | -14.1% | 208 / 208 |
| Windows | typed | 76.13 | 75.33 | -1.0% | 216 / 216 |
| Windows | poly | 85.98 | 83.00 | -3.5% | 208 / 208 |
| Windows | control | 44.61 | 44.76 | +0.3% | 224 / 224 |
| Linux | mono | 78.65 | 80.03 | +1.8% | 224 / 224 |
| Linux | typed | 78.70 | 77.58 | -1.4% | 224 / 224 |
| Linux | poly | 100.34 | 95.96 | -4.4% | 224 / 224 |
| Linux | control | 49.38 | 49.28 | -0.2% | 224 / 224 |

The two-candidate loop improves in both measurements. The mono and typed
differences are small or inconsistent. Windows mono samples include large
interruptions; the raw samples show this explicitly. The integer control
changes little. Managed heap deltas remain equal; the JSON also records peak
RSS. These microbenchmarks measure dispatch and do not establish whole-program
speedups.

## Reproduction

Generate the compile fixture with
`python benchmarks/generate_oop_call_sites.py build/oop_400_calls.ml`.
Use `tests/bench_compiler_optimization.py` with four commands for the preserved
before/after compilers and nine measured rounds. The compiler commands use
`<compiler> <fixture> <output> --no-object-pipeline --target windows-x64`;
Python commands additionally start with `python`. Compile
`benchmarks/oop_dispatch.ml` for each target with the before and after compilers,
then run `python benchmarks/compare_oop_dispatch.py <before> <after> --runs 15
--cpu 4 --output results.json` on the target OS. Run
`tests/check_oop_binary_parity.py` with Python, Windows-native and Linux-native
compilers to reproduce the parity matrix.
