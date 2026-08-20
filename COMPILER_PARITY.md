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
| `language_suite.ml` | 1,763,328 | `3F25612629388AE6C62B8074C84A70C8BEADF636C41D527AE08DAC674BADA8C2` |
| `stdlib_unit_tests.ml` | 4,317,184 | `2A1A84CB0BD55FED6CA08B0529AC0201A12A39572BA7985717A884B8D222B43C` |
| `gc_periodic_test.ml` | 169,472 | `6989C9D7D4672C216250B080E75CABEF9417B80A061AB0EC735C088DE074192A` |
| `gc_heap_stress.ml` | 85,504 | `2880AB89CD1F3A0ECE7D58101D4297BC0BAEF84EB8D049EE90AA3A3BB47F64B7` |
| `aes128_ecb_nist_kat.ml` | 363,520 | `16265BADB43F3578FC7BA60B62CFFA1270BDF351F7819F6FC678E4ECAA958B76` |
| `winapi_extern_smoke.ml` | 65,536 | `C42A65E136A34D92B021F8EC965C416CFEF2D1118B9F14CF7DB2B9607C5BD6BE` |
| `native_bytes_ptr_smoke.ml` | 87,040 | `B6AFE1BDBD6D2F1C26387E5797B74EE635545D7F811CD3C33DE1544AA1B77CC8` |
| `native_raw_value_smoke.ml` | 84,992 | `53BA3465F1309DE7E8099159F6153F49E70A033E80732D4D3E0AD8A1F51E9B24` |
| `native_callback_wndproc_smoke.ml` | 90,112 | `63DFDF6DD8B0F3C41F4F42570A80CD42F3121C89ECC8E14A73C49C3D79F2726F` |
| `global_function_rebind.ml` | 71,168 | `6BFB533BCBE83FE0F7791DE072C1FB17BDF9B8B20CC2789C335AF410DE53779E` |
| `thread_features.ml` | 218,624 | `B1D6D80AFE2CF96F287F652A40F61C4955B6558CDC1A72268DC3093EF281D0A4` |
| `threading_stdlib.ml` | 942,592 | `EDE3694B5A3F39FFAE5A6449CF9712B6DC3254A4E61915EA15A8F45B05BAF919` |
| `extern_abi_validation_valid.ml` | 72,704 | `43EC5DC5985B58CBFEA268EDA5F090B81E47E315DB98827B64A16C6CAF9B2377` |
| `codegen_optimizations.ml` | 276,992 | `A8199F963C0F7D0D84D109F2FEEAE856A93EBF52719A0351095E948BBFC30982` |

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
| Python-built MiniLang compiler | 54,920,192 | `79C27CFD764EC4891BF229B00FF4F3CC445156CDE359D2EDA376FF7E3102C638` |
| MiniLang self-build through `build.ps1` / `.mlo` | 55,520,768 | `BE0F6005E8750D0514CFD166D85BA4F61FAF04B8320932052F9029411F4409C6` |

The compiler images differ by 600,576 bytes. Both images subsequently compiled
`language_suite.ml` to the same 1,763,328-byte target with SHA-256
`3F25612629388AE6C62B8074C84A70C8BEADF636C41D527AE08DAC674BADA8C2`.
Two consecutive MiniLang object-pipeline self-build stages were byte-identical
at 55,520,768 bytes with the hash shown above, so that supported self-host path
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
- synchronized assembler coverage with 222 golden opcode vectors.

Generated-code optimization is synchronized as part of the same parity
contract: both backends use the same inline expansion budget and conservative
inline-only reachability rules, local integer flow, constant-loop lowering,
GC-root/prologue sizing and short-back-edge selection. The shared
`tests/codegen_optimizations.ml` fixture covers optimized behavior and fallback
semantics; listing checks additionally verify which native bodies and loop/root
forms remain.

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
Python harness:    PASS 81, FAIL 0, SKIP 0
MiniLang harness:  PASS 80, FAIL 0
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
