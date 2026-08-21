# Compiler parity and self-hosting

Verified on 21 August 2026 against the matching revisions of:

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
| `language_suite.ml` | 1,764,864 | `DA1412AD6C0D4D2AC3A61C89341EFE57632BAF56C8274D2E317484095B95A979` |
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
| `codegen_optimizations.ml` | 290,304 | `413B9766BE4888A55C34494DC4EDADD131AA52677A73C5207BE36F6FB77E6F74` |
| `thread_pool.ml` | 690,176 | `B1B37083DE44F9EDE55A168F241845CE659EAB885DD7F5897B3A338A9C99B200` |
| `type_checks.ml` | 144,896 | `61B6FED70395A88F4640823E6A55525AF95E83523C2B104D4877937FE7299E87` |
| `member_callable_direct.ml` | 75,776 | `EEF4C2042D24FFCC1CF579FAD38E4316F160049BFCADCEFB0316B97A10B695E4` |
| `codegen_phase_gc.ml` | 521,216 | `45D35160CDA2A587B04DE917EDD9A62C81EF2FB69D22A87F06402F023BE1A2C6` |
| `compiler_gc_liveness.ml` (`--gc-limit 1m`) | 209,408 | `1DF004B2CA8429CB7FBDA8BD7A84B73F3139F748FB9A4839ADE28C9B2DD6FA19` |

This coverage includes imports and the standard library, closures, inline
functions, structs, enums, GC, extern declarations, native interop, real Win32
threads, one process-wide managed heap, per-thread stacks and GC root chains,
cooperative stop-the-world collection, synchronization primitives and
thread-safe collections that preserve shared object identity, one-value thread
arguments, logical thread ids and managed worker pools with backpressure.
It also exhaustively covers every public `is` runtime category, including
case-insensitive `Thread`/`thread` checks and their negated forms.
Compiler-scale coverage crosses repeated phased collections and verifies that
target GC options cannot alter compiler-internal collection or target bytes.

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
| Python-built MiniLang compiler | 55,541,248 | `109D488D583C739FD5E5BB7B1ED365BD165EE48C64329B18451987748ED8FEB7` |
| MiniLang self-build through `build.ps1` / `.mlo` | 56,171,008 | `5B57C261C10853DD6AA77F7E7FE71AEDACF93A1EDC78FCC14EF32A9F35769348` |

The compiler images differ because the supported self-build is linked from
`.mlo` objects while the Python bootstrap emits one monolithic image. Both subsequently compiled
`type_checks.ml` to the same 144,896-byte target with SHA-256
`61B6FED70395A88F4640823E6A55525AF95E83523C2B104D4877937FE7299E87`.
Two consecutive MiniLang object-pipeline self-build stages were byte-identical
at 56,171,008 bytes with the hash shown above, so that supported self-host path
does reach a binary fixed point.

A monolithic self-build was also attempted with the earlier 4 GiB bootstrap
heap and exhausted it before producing an executable. Self-builds
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
contract: both backends use the same inline expansion budget with unconditional
callable fallback bodies, local integer flow, constant-loop lowering,
GC-root/prologue sizing and short-back-edge selection. Stack sizing also
accounts for calls hidden inside eligible inline bodies, so an expanded wide
call cannot overwrite caller locals, debug saves or the root-frame record. The shared
`tests/codegen_optimizations.ml` fixture covers optimized behavior and fallback
semantics, including a narrow caller around a hidden ten-argument call; listing
checks additionally verify that all inline fallback bodies and both the small
and expanded loop/root forms remain.

The self-hosted compiler additionally retains `.mlo` production/linking,
`--object-pipeline`, assembly/PE/data listings and its direct encoder helpers.

## Self-host performance work

The MiniLang implementation was optimized without changing target bytes. The
main changes are native string/bytes hashing for compiler-internal fast maps,
paged byte/array builders, chunked/indexed `.rdata` and `.data` label tables,
chunked section-relocation records, direct 32/64-bit assembler emission,
pre-sized label maps and generational text-fixup resolution. Each bounded phase
scans only newly emitted patches; unresolved forward references are revisited
once after helper emission instead of after every function batch. The parsed AST and active codegen graph are explicit roots across
automatic and manual compiler collections. Compiler GC cadence is independent
of the target's `--gc-limit`. These are implementation details of the
self-hosted compiler, not additions to the language-level compatibility
contract.

## Tests

Latest complete runs for this revision:

```text
Python harness:    PASS 87, FAIL 0, SKIP 0
MiniLang harness:  PASS 85, FAIL 0
ML opcode smoke:   synchronized golden vectors and direct encoder passed
Thread stress:     thread_pool PASS 60/60 processes (30 per compiler output)
                   managed argument publication/GC PASS 30/30 processes
```

The original MiniQuake regression was also rebuilt end to end through the
MiniLang `.mlo` object pipeline: 112 modules / 656 objects linked successfully
in 349.891 seconds. The resulting 64,147,456-byte PE has SHA-256
`8C467FB4904CD62FEACF1052BDBB5433271937749C8E870D7FFD7E602FB38800`;
its `--help` runtime smoke exited with code 0. This specifically exercises the
hidden wide inline-call frame sizing, object-state cloning and large patch/link
paths that triggered the reported compiler failure.

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
