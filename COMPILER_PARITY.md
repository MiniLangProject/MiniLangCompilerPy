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
| `language_suite.ml` | 1,763,328 | `C4AAFA667C147DA551B04585912B85FAC7CC8904A1CBDDB802B20CC1F8380ADD` |
| `stdlib_unit_tests.ml` | 4,317,696 | `CD38657FC31FE10BA3418B48865CB7F79566B314B21E4D7DB5557C45ADC86F97` |
| `gc_periodic_test.ml` | 169,984 | `64D0EC72ABE4AB2C100A0B84C4383C285A9D793C7EB10342BD8A5F3835AFAE74` |
| `gc_heap_stress.ml` | 85,504 | `44645F27BB592AD5B7862BFB6B93EFF099613B5CA85CE7CCD2C7B5C9DE1D8295` |
| `aes128_ecb_nist_kat.ml` | 363,520 | `1BA75EBC481FF6935BFC85CF78971A6EDC1AF36AC6479BBF0DEB1410CDEE2698` |
| `winapi_extern_smoke.ml` | 65,536 | `64DFFB4946312506D7159B4D89F6DB96C7F5626686419C0B7605B02116715E2A` |
| `native_bytes_ptr_smoke.ml` | 87,040 | `1F05701DD71853CC8314D204A8762E15D6BFCF472C21340ABFF366C5B428EBC9` |
| `native_raw_value_smoke.ml` | 84,992 | `65E7D56D77FC634A50B8C1E93E622AB4F59F82C02AB73D45C313F16C1FA7565A` |
| `native_callback_wndproc_smoke.ml` | 90,112 | `CC2E5146E088ADD1B2E414EE11D56E41D7C90FD905DBA6330B50C984939F6933` |
| `global_function_rebind.ml` | 71,168 | `15A512E964736C914337BDEB81D223D550B9A73F45A6643E359CD1279933133B` |
| `thread_features.ml` | 219,136 | `9483DFC07D22A29B186EDDD2D6F89FB199002671342133D17AB7A8904B49179F` |
| `threading_stdlib.ml` | 943,104 | `A7B1B39CBBA1A67A7915BD95FC35A5A984A6646C19A6093B407EF52A3B24F75D` |
| `extern_abi_validation_valid.ml` | 72,704 | `F11F9C6CB1FE673BDA524EC015FD49E8DFDE4AF420CD19C2B6056FA6C157D0D1` |
| `codegen_optimizations.ml` | 276,992 | `0317BBB0B4EC449EC4618269FDA57DE07D5A4133370BB682F57A08A8514AA7E1` |
| `thread_pool.ml` | 690,176 | `B1B37083DE44F9EDE55A168F241845CE659EAB885DD7F5897B3A338A9C99B200` |
| `type_checks.ml` | 144,896 | `61B6FED70395A88F4640823E6A55525AF95E83523C2B104D4877937FE7299E87` |

This coverage includes imports and the standard library, closures, inline
functions, structs, enums, GC, extern declarations, native interop, real Win32
threads, one process-wide managed heap, per-thread stacks and GC root chains,
cooperative stop-the-world collection, synchronization primitives and
thread-safe collections that preserve shared object identity, one-value thread
arguments, logical thread ids and managed worker pools with backpressure.
It also exhaustively covers every public `is` runtime category, including
case-insensitive `Thread`/`thread` checks and their negated forms.

All 26 files below `std/` also have matching relative paths and byte-for-byte
identical contents in both repositories. This includes the new
`std.threading`, `std.concurrent.shared_value`,
`std.concurrent.thread_pool`, `std.ds.concurrent_list` and
`std.ds.concurrent_hashmap` modules.

## Bootstrap and self-build stages

The same `MiniLangCompilerML/mlc_win64.ml` source tree was compiled with the
same heap and GC options for this comparison.

| Compiler image | Size | SHA-256 |
| --- | ---: | --- |
| Python-built MiniLang compiler | 55,112,192 | `0E6E2283186853BB30D5BD4D5BDF25262DE5631B2570F60B7B0B598D7B5B0362` |
| MiniLang self-build through `build.ps1` / `.mlo` | 55,714,816 | `E1A3D99E9A73E41147DC41AC53D3B684FE794B4ABEDFDCCF7FD4EB9CD63B3A4A` |

The compiler images differ by 602,624 bytes. Both images subsequently compiled
`type_checks.ml` to the same 144,896-byte target with SHA-256
`61B6FED70395A88F4640823E6A55525AF95E83523C2B104D4877937FE7299E87`.
Two consecutive MiniLang object-pipeline self-build stages were byte-identical
at 55,714,816 bytes with the hash shown above, so that supported self-host path
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
- real Win32 threads with cooperative stop/join/status operations, optional
  one-value arguments/results and separate native/logical ids;
- one global, thread-safe managed heap with private thread stacks and
  cooperative GC safepoints;
- synchronized globals of any value type and synchronized functions;
- native locks, semaphores and events plus thread-safe list/hash-map types;
- reusable managed thread pools with bounded/unbounded queues, job lifecycle,
  backpressure and graceful/immediate shutdown;
- `Thread` as a first-class, case-insensitive `is` runtime category, verified
  together with every other public primitive, struct and enum category;
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
Python harness:    PASS 83, FAIL 0, SKIP 0
MiniLang harness:  PASS 82, FAIL 0
ML opcode smoke:   synchronized golden vectors and direct encoder passed
Thread stress:     thread_pool PASS 60/60 processes (30 per compiler output)
                   managed argument publication/GC PASS 30/30 processes
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
