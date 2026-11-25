# Native copy and UTF-8 length fixes

Validated on 2026-11-25 on Linux x86-64. The paired repositories are
`MiniLangProject/MiniLangCompilerPy` and `MiniLangProject/MiniLangCompilerML`.
The baseline revisions were respectively
`8e64c9cfda92199b68ac5d3974fea445f12f6c39` and
`127996e53a5908bdfc64d09ca8bea35011db58d6`.

## Behavior and implementation

- Public `copyBytes` and `copyArray` now support overlapping ranges with
  snapshot-equivalent `memmove` semantics. A dedicated `fn_move_bytes` helper
  selects the safe direction. It uses complete qword loads/stores and a bounded
  byte tail; aligned tagged array cells are never split into byte writes.
  Disjoint ranges retain the optimized scalar/SSE2/AVX/ERMS copy path. No
  temporary copy buffer is allocated. Direct and first-class calls are covered,
  and array copies preserve their existing SATB/GC write barrier.
- Native `len(string)` consistently counts UTF-8 bytes. Python constant folding
  now follows the same rule as runtime strings and the MiniLang compiler. For
  example, `"Grüße 🌍"` has length 12 in literals, variables, arguments and array
  elements. String headers, byte-based indexing, and StringBuilder allocation
  remain compatible. This change does not modify the separate Wasm compiler's
  code-point length policy.
- The ML compiler registers the move helper in the same canonical order as
  Python. Its dispatch group boundaries match all 111 entries, including
  `fn_decref`. The generic direct byte-copy path also preserves the source
  pointer before assigning the count register.
- Initializer shadowing and Boolean/integer equality retain their existing
  behavior and now have explicit shared regression coverage.

## Regressions and baseline evidence

The identical `tests/native_semantics_regression.ml` fixture in both repositories
contains **1,446 copy cases** across direct/indirect calls, byte buffers/arrays,
both overlap directions, identical ranges, clipping, invalid/zero-length
requests, aliases, and disjoint controls. CPU masks cover scalar, SSE2 and the
available feature set; tested sizes include boundaries around 64 KiB.
Additional checks cover Unicode byte lengths, embedded NULs, combining
sequences, astral characters, StringBuilder, outer-binding initialization,
Boolean/integer equality, and copied references surviving collection.

The unchanged Python baseline produced **404 failing checks** with this fixture.
Both corrected compilers pass against the fixed expected output, rather than
using each other as the sole correctness oracle.

Two native-helper tests add **8,820 comparisons** against an independent
snapshot model, including **900 guard-page cases**, plus zero-length calls.
They check complete buffers so writes outside the requested range are detected.

## Results

The Python unit command `python3 -m unittest discover -s tests -p 'test_*.py' -v`
completed **63 tests: 60 passed, 3 skipped, 0 failed**. The skips are two native
Windows-specific checks and optional NASM verification that was not enabled.
Two baseline verification issues were also cleaned up: a missing public parser
docstring and a test that incorrectly required aliases for namespace-only
standard-library modules. The import test still covers every public module and
retains all MinUX library/target assertions; packed-array production sources
were not changed. Its existing runtime fixture passed in both pipelines using
each repository's standard library.

The shared runner compiled the same input with Python and native ML, each in
monolithic and object-pipeline mode. All four images in each row are byte-identical.

| Target / option | Images | Executions | SHA-256 of each image |
| --- | ---: | ---: | --- |
| Linux x64 | 4 | 4 successful | `6158946e1dd2b6e60ebea286b031520fd18b03246d87e7de60249f01470371f7` |
| Windows x64 | 4 | 0, cross-compiled | `66e5793454d77f95efc5308a7445096ee9588f87336473599b58c91192c2ecd0` |
| MinUX x64 | 4 | 0, cross-compiled | `46c6b549acaff80e452c03d3d51857b16a8f205b3b9e67122ed3136c044a25f0` |
| Windows x64, `--gc-concurrent` | 4 | 0, cross-compiled | `4fa91805f59a5279827a723532da1103aa07a8f080917752f200c9262a509141` |

No Windows/Wine or booted MinUX runtime was available for execution. Compilation
and byte parity are reported separately from runtime validation.

## Self-hosting

The corrected Python compiler built the native Linux ML compiler. That compiler
then rebuilt itself through the canonical MLO pipeline. Both builds passed the
build script's direct/object/project smoke checks and produced exactly the same
68,044,016-byte compiler image:

`1d9eeea2259b9b3c61f47061344dff03a1c35541122e43c859ab119e5cb12920`

This establishes a byte-identical bootstrap/self-build fixed point for the tested
Linux build configuration.

## Reproduce

Check out the two repositories next to each other. From `MiniLangCompilerML`:

```sh
sh build.sh --compiler ../MiniLangCompilerPy/mlc_win64.py --output build/mlc_linux_x64
sh build.sh --compiler build/mlc_linux_x64 --output build/mlc_linux_x64.stage2
cmp build/mlc_linux_x64 build/mlc_linux_x64.stage2
```

From `MiniLangCompilerPy`:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 tests/check_native_semantics.py --python-compiler ./mlc_win64.py --native-compiler ../MiniLangCompilerML/build/mlc_linux_x64
python3 tests/check_native_semantics.py --python-compiler ./mlc_win64.py --native-compiler ../MiniLangCompilerML/build/mlc_linux_x64 --target windows-x64 --compile-only
python3 tests/check_native_semantics.py --python-compiler ./mlc_win64.py --native-compiler ../MiniLangCompilerML/build/mlc_linux_x64 --target minux-x64 --compile-only
python3 tests/check_native_semantics.py --python-compiler ./mlc_win64.py --native-compiler ../MiniLangCompilerML/build/mlc_linux_x64 --target windows-x64 --compile-only --compiler-arg=--gc-concurrent
```

The runner fails on a compile error, nonzero program exit, unexpected output,
compiler mismatch or pipeline mismatch. `--compile-only` is explicit and never
counts an image as an executed test. The fixture is also registered in each
repository's existing regression runner.
