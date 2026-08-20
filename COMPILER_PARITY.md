# Compiler parity and self-hosting

Verified on 20 August 2026 against the matching revisions of:

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
| `language_suite.ml` | 1,830,400 | `28BCA6D90BBE7A849F2E076A4F834C02C3769528CC151ACB9C0C9116F4F1A14E` |
| `stdlib_unit_tests.ml` | 4,539,392 | `6947D8AFBD167CC1D7593801C71EAF4A9303F100EB03B4334641D58E47C626A6` |
| `gc_periodic_test.ml` | 172,032 | `CC4F1AC66700E79B1C9430D72A122022D184F8BB9A24F365501EDC7DF2F68248` |
| `gc_heap_stress.ml` | 86,016 | `D809B4B3BE971E0AE79C7CD26703E73682661931A9B55DC3DBB6CFCCDDE92063` |
| `aes128_ecb_nist_kat.ml` | 475,136 | `3DA3A2356E46E019942C466254B161A79FD35337E1557AF8FFE9BD5D3645658E` |
| `winapi_extern_smoke.ml` | 66,048 | `E6D38EBB8E6D71F852593F45ACF27D7FDC06373E8DA68F0D2AF6A8C14A6D2CFD` |
| `native_bytes_ptr_smoke.ml` | 87,552 | `858106F00FBC713544416D737783A55B44F20D33C7CECF0D4011142C00429F91` |
| `native_raw_value_smoke.ml` | 85,504 | `B2F59BA5DE2BC1B41BE23AD9D6F328B22FCCB4F260753519D53095683DBE328C` |
| `native_callback_wndproc_smoke.ml` | 91,136 | `13DB66FDAF3834BF3876DFD1A3D51A4B68D9D89E443062660B28A1B78AC60054` |
| `global_function_rebind.ml` | 71,680 | `B01D41ECB8359A006D63E97598E9310CAED025C52FEE3A025679CD77A031F8CF` |
| `thread_features.ml` | 226,304 | `86A82739C4A0F35A4880A0EFD9BF20CD76B2B133FD0196650F89D12577AABCDC` |
| `threading_stdlib.ml` | 978,944 | `9FF0FA670B357723068C88BF1F7A53BDC2C12A3606A3F026B727D493B9FB5A3D` |
| `extern_abi_validation_valid.ml` | 73,216 | `64B259E3F16329383B6848C6EB1F4BCD87B3CD9E6C3FC78EA1072B3BA1373ED2` |

This coverage includes imports and the standard library, closures, inline
functions, structs, enums, GC, extern declarations, native interop, real Win32
threads, one process-wide managed heap, per-thread stacks and GC root chains,
cooperative stop-the-world collection, synchronization primitives and
thread-safe collections that preserve shared object identity.

All 25 files below `std/` also have matching relative paths and byte-for-byte
identical contents in both repositories. This includes the new
`std.threading`, `std.concurrent.shared_value`,
`std.ds.concurrent_list` and `std.ds.concurrent_hashmap` modules.

## Bootstrap and self-build stages

The same `MiniLangCompilerML/mlc_win64.ml` source tree was compiled with the
same heap and GC options for this comparison.

| Compiler image | Size | SHA-256 |
| --- | ---: | --- |
| Python-built MiniLang compiler | 56,216,064 | `A063DABAC8D6DFF9DE5271C7885A77C8F7C486B06BE4DD7EC40E423F39C0A969` |
| MiniLang self-build through `build.ps1` / `.mlo` | 56,647,168 | `56E5B3C2DB7C157F8E325041EDD25C82DF9AF94649F5F3FDA2996D696C4E55FF` |

The compiler images differ by 431,104 bytes. Both images subsequently compiled
`language_suite.ml` to the same 1,830,400-byte target with SHA-256
`28BCA6D90BBE7A849F2E076A4F834C02C3769528CC151ACB9C0C9116F4F1A14E`.
Two consecutive MiniLang object-pipeline self-build stages were byte-identical
at 56,647,168 bytes with the hash shown above, so that supported self-host path
does reach a binary fixed point.

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
- real Win32 threads with cooperative stop/join/status operations;
- one global, thread-safe managed heap with private thread stacks and
  cooperative GC safepoints;
- synchronized globals of any value type and synchronized functions;
- native locks, semaphores and events plus thread-safe list/hash-map types;
- closures, captures, boxed variables and environment hops;
- `foreach`, `switch`, namespaces and module initialization;
- explicit-value enums, struct construction and constant folding;
- call profiling/tracing;
- deterministic constant/data layout and canonicalized debug paths; and
- synchronized assembler coverage with 221 golden opcode vectors.

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
Python harness:    PASS 80, FAIL 0, SKIP 0
MiniLang harness:  PASS 79, FAIL 0
Additional ML:     assembly-listing smoke and both sprite repros passed
Thread stress:     thread_features PASS 100/100 processes (1,000 publication/GC rounds)
                   threading_stdlib PASS 25/25 processes
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
