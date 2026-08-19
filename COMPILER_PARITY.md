# Compiler parity and self-hosting

Verified on 19 August 2026 against the matching revisions of:

- `MiniLangCompilerPy`, the Python bootstrap/reference compiler; and
- `MiniLangCompilerML`, the compiler implemented in MiniLang.

## Compatibility result

There are two separate compatibility claims:

1. **Target-output parity:** for the same sources, include-root order and
   compiler options, both normal monolithic compiler paths emit byte-identical
   Windows x64 PE files.
2. **Compiler-image identity:** a compiler PE built by Python and a compiler PE
   built through the MiniLang-only `.mlo` self-build pipeline are not
   byte-identical. They remain behaviorally compatible and emit the same tested
   target files.

The second point is expected because Python has no `.mlo` object/link pipeline.
Intermediate `.mlo` files and the layout of the compiler linked from them are
therefore outside the cross-compiler byte-identity contract.

## Verified target binaries

The following files were rebuilt from scratch with both compilers. Each pair
had identical size and SHA-256, and both executables exited successfully.

| Program | Size | SHA-256 |
| --- | ---: | --- |
| `language_suite.ml` | 1,709,056 | `AAB134D37C8E44AC5EADF0E530DE15BF7FDE7646FF2058C85AE5148268416695` |
| `aes128_ecb_nist_kat.ml` | 444,416 | `9E5F4A95DC3EB3872CC1BD79EF45471F9A2FACE8277A3CE05C8882593B7CC788` |
| `native_raw_value_smoke.ml` | 82,432 | `978D4C0A80B08A23413AC5C3CD219845888BF6AC22317D96B5A9562635F397C7` |

This coverage includes imports and the standard library, closures, inline
functions, structs, enums, GC, extern declarations and native interop.

## Bootstrap and self-build stages

The same `MiniLangCompilerML/mlc_win64.ml` source tree was compiled with the
same heap and GC options for this comparison.

| Compiler image | Size | SHA-256 |
| --- | ---: | --- |
| Python-built MiniLang compiler (also the checked-in `MiniLangCompilerML/build/mlc_win64.exe`) | 50,200,576 | `DDC98FA7BD6D3101A9435FF5B5DF350D2FA65783F7EB56BCBA8B6D770071E5FB` |
| MiniLang self-build through `build.ps1` / `.mlo` | 50,602,496 | `6F5D0CF5AB24A12769F147CE294AB8B2EB08FF332DF3A3A8900362BDDD9D8946` |

The compiler images differ by 401,920 bytes. Both images subsequently compiled
`language_suite.ml` to the same 1,709,056-byte target with SHA-256
`AAB134D37C8E44AC5EADF0E530DE15BF7FDE7646FF2058C85AE5148268416695`.

A monolithic self-build was also attempted with the same options. It exhausted
the configured 4 GiB MiniLang heap before producing an executable. Self-builds
must therefore use `MiniLangCompilerML/build.ps1`, which deliberately enables
the memory-bounded object pipeline. A byte-identical monolithic bootstrap fixed
point is not currently claimed.

## Parity work included in this revision

No existing feature was removed. The synchronized surface includes:

- aliased explicit-file and relative imports;
- stricter extern ABI validation and positive/negative fixtures;
- native bytes pointers, raw-value conversion and callback smoke coverage;
- `array(size[, fill])` construction;
- global function-value rebinding;
- inline-function lowering and eligibility checks;
- closures, captures, boxed variables and environment hops;
- `foreach`, `switch`, namespaces and module initialization;
- explicit-value enums, struct construction and constant folding;
- call profiling/tracing;
- deterministic constant/data layout and canonicalized debug paths; and
- synchronized assembler coverage with 217 golden opcode vectors.

The self-hosted compiler additionally retains `.mlo` production/linking,
`--object-pipeline`, assembly/PE/data listings and its direct encoder helpers.

## Self-host performance work

The MiniLang implementation was optimized without changing target bytes. The
main changes are native string/bytes hashing for compiler-internal fast maps,
paged byte/array builders, direct 32/64-bit assembler emission, pre-sized label
maps and streaming object/link patch handling. These are implementation details
of the self-hosted compiler, not additions to the language-level compatibility
contract.

## Tests

Latest complete runs for this revision:

```text
Python harness:    PASS 76, FAIL 0, SKIP 0
MiniLang harness:  PASS 75, FAIL 0
Additional ML:     assembly-listing smoke and both sprite repros passed
```

The counters differ because the Python runner counts host-side tests
individually while the MiniLang harness groups several checks into compiled
programs.

## Reproducing target-output parity

From a workspace containing both repositories as siblings:

```powershell
cd MiniLangCompilerPy
python .\mlc_win64.py .\tests\language_suite.ml .\build\suite-py.exe -I .

cd ..\MiniLangCompilerML
.\build\mlc_win64.exe .\tests\language_suite.ml .\build\suite-ml.exe -I .

$pythonHash = (Get-FileHash ..\MiniLangCompilerPy\build\suite-py.exe -Algorithm SHA256).Hash
$miniLangHash = (Get-FileHash .\build\suite-ml.exe -Algorithm SHA256).Hash
$pythonHash -eq $miniLangHash
```

The final expression must be `True`. Equality is guaranteed only when source
contents, imported files, include-root order, compiler options and canonical
source names are equivalent.
