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
| `language_suite.ml` | 1,677,824 | `F9CEA6409801E380CF75910F8787BD9CAC6A992E2EB76D1D12076715A06E9E9C` |
| `stdlib_unit_tests.ml` | 4,015,104 | `0D4ADCCC86B05628A88182436075D65656A25A5CABD4B253A4DF331B334CA902` |
| `gc_periodic_test.ml` | 162,816 | `2B35AC3DF135B27D7EB0254ED53F29697EA6C060E4C2316ABE4284920D854287` |
| `gc_heap_stress.ml` | 83,968 | `5B0D13ABB45078E48960D4F056BA47D91914192CED5C3E82C0F573120F65AE9B` |
| `gc_box_float_safepoint.ml` | 376,832 | `B132A3B930898EA7E3B1AAAD85C47F006AF973E31DBD6761FD108A50AB605D55` |
| `gc_float_call_roots.ml` | 426,496 | `38E460E46EA32FB55971F533944D0AC0056B21808C62F48117DBB934E178DA27` |
| `gc_nested_graph_roots.ml` | 275,456 | `6A0661D8BA259ABC1DD0AAE750E04082F812CBE9FA3CE558DBC66BF495A7A8D9` |
| `gc_reference_write_roots.ml` | 133,120 | `82F922E01CF3BAE597785C12C76F999F369491ADE324438D02C574EF5087DD35` |
| `aes128_ecb_nist_kat.ml` | 338,432 | `C78B946F22B022AB54242F03368D4ECE02D5ED460275B7DAA064F4524B4CD307` |
| `winapi_extern_smoke.ml` | 64,512 | `1583B4C6CF73B38947D2A70CEEC1115793CCD0460DE0C520E97E3E2AE1052BC8` |
| `native_bytes_ptr_smoke.ml` | 84,480 | `E2465D781EB5BC912A68BAB6B165B32A406A1947048A431A3948D6E10568677C` |
| `native_raw_value_smoke.ml` | 82,944 | `8B863F87376AA3A8C78B178569D25A22CDBAA60F4A28C7763807D86B9929E4B6` |
| `native_callback_wndproc_smoke.ml` | 88,064 | `0C78C4815B2F548C54A7AB13A61117BC8B4C40D475AF77ECEAABDE8D760C34E7` |
| `global_function_rebind.ml` | 69,632 | `264042565E63A487B73DAA9AD4AF2794F55EA3B9A2E3CE80B1C25172A852F99B` |
| `thread_features.ml` | 214,528 | `EE9B539BF5FC03BC85717BD10937E97D1318D6AB8F8044132B7456337C46C8DD` |
| `threading_stdlib.ml` | 925,184 | `DDA9E4EA3F12483AF9592DCB3874EA3D5A106632FA70763AED23576E08EBAE5A` |
| `extern_abi_validation_valid.ml` | 71,168 | `7390B62DD0A9642CB8AEF9FE3DF427A1BDADBAF9E26AD56D38F8812604985FC5` |
| `codegen_optimizations.ml` | 274,944 | `A13344BE58B8E58B866E91AF89AEB697BDCF54182F3E408EF80ABB222E8DC217` |
| `thread_pool.ml` | 677,376 | `E5B905022ABC231FB50996380086EFD2275F5324F85FD4D26F09A56583F195CA` |
| `type_checks.ml` | 143,360 | `DF9E884456F25C90D384B18AF46BBB7F00E760683FF8E56D384BDB2E40748633` |
| `member_callable_direct.ml` | 74,240 | `E7BB9F9784CE7A335E28E8F57715A03E8CDD9836E61288A8CB36D40CE212D73E` |
| `codegen_phase_gc.ml` | 466,432 | `3303AEABD5607CF614755764798531D1EDF95715C8DB2600893F07D534E9A98D` |
| `compiler_gc_liveness.ml` (`--gc-limit 1m`) | 165,376 | `D53E124E6105691AEE16FD859AF21EFBBDFB0BCEC113F46C2ED38E2AC4B61FA9` |
| `defer_features.ml` | 83,456 | `5BB15FB39983A1752CA7C33900CB9B85E3E404046F21B0927FC11137DC1F4B56` |
| `extern_out_runtime.ml` | 74,240 | `A6E02746D93EE638E314ADC535EA314EE15BD413C5D52C680B82CCCE3DE86211` |

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
| Python-built MiniLang compiler | 54,276,608 | `E87580A31690233D7BEBF0234A82C844E05207A08302FE845A5B35E80A03C0A6` |
| MiniLang self-build through `build.ps1` / `.mlo` | 54,773,248 | `64283A3A46E43B16BE910B5DD254BF350781E522C8F3B7879086FC0344546119` |

The compiler images differ because the supported self-build is linked from
`.mlo` objects while the Python bootstrap emits one monolithic image. Both
subsequently compiled `language_suite.ml`, `defer_features.ml` and
`extern_out_runtime.ml` to the byte-identical target hashes listed above. Two
consecutive current MiniLang object-pipeline self-build stages were
byte-identical at 54,773,248 bytes with the hash shown above, so the supported
self-host path reaches a binary fixed point.

A monolithic self-build was also attempted with the earlier 4 GiB bootstrap
heap and exhausted it before producing an executable. Self-builds
must therefore use `MiniLangCompilerML/build.ps1`, which deliberately enables
the memory-bounded object pipeline. A byte-identical monolithic bootstrap fixed
point is not currently claimed.

## Parity work included in this revision

No existing feature was removed. The synchronized surface includes:

- aliased explicit-file and relative imports;
- stricter extern ABI validation and positive/negative fixtures;
- native scalar/managed-struct marshaling for omitted trailing `out`
  parameters, including BOOL failure propagation;
- LIFO `defer` cleanup with call-time captures on return, fall-through and
  automatic error propagation;
- TOML project manifests with content-validated incremental artifact caching
  and optional self-hosted `.mlo` builds;
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

The current append/clone optimization pass additionally replaces the growing
function, global, scope and local arrays with geometrically growing internal
vectors, builds the per-module function index once, and uses sparse read-only
support-label indexes for `.mlo` object clones. Support bytes and support label
arrays are no longer copied into every short-lived function object. Forced full
collections are amortized across 64 objects/four modules; the automatic
compiler heap limit remains the safety net. `--profile-compiler` exposes the
phase timings without affecting generated target bytes.

On the same compiler source and heap flags, an instrumented object-pipeline
self-build improved from 336.073 seconds (286.172 seconds object emission) to
218.330 seconds (166.438 seconds object emission), a 35.0% total and 41.8%
object-emission reduction. A consecutive second self-build took 230.850
seconds; both 52,948,992-byte compiler images were byte-identical with SHA-256
`0325E633D03B2BBAACBEB47F503CB0E774580D3F9CB0F5F6E7047FD64387F9B3`.

After the earlier GC-root parity synchronization, that source revision was
validated through two consecutive self-host stages. They completed in
162.501 and 208.573 seconds and produced identical 53,514,752-byte compiler
images with SHA-256
`1C15CC446E1A15C16CE84938B6961A287245750FD4072501313409BEFC5E9F05`.

With `defer`, managed extern-out marshaling and project manifests included, the
final two fully current stages took 326.648 and 278.837 seconds, emitted 293
objects each and were byte-identical at 54,773,248 bytes with SHA-256
`64283A3A46E43B16BE910B5DD254BF350781E522C8F3B7879086FC0344546119`.

## Tests

Latest complete runs for this revision:

```text
Python harness:    PASS 94, FAIL 0, SKIP 0
MiniLang harness:  PASS 93, FAIL 0
ML opcode smoke:   synchronized golden vectors and direct encoder passed
Thread stress:     thread_pool PASS 60/60 processes (30 per compiler output)
                   managed argument publication/GC PASS 30/30 processes
```

The most recent MiniQuake regression (before the three language/tooling
additions documented above) was rebuilt end to end through the
MiniLang `.mlo` object pipeline: 112 modules / 656 objects linked successfully
in 420.095 seconds. Planning took 35.109 seconds, object emission 283.657
seconds and the fresh linker process 99.250 seconds; label resolution and patch
application accounted for 74.829 and 19.515 seconds of the linker phase. The
resulting 59,706,880-byte PE has SHA-256
`2CDD41475932CCC2A2EFBF2FCAAF36844DDD1AE96577E2D55CA57FE5595B9A2F`;
its `--help` runtime smoke exited with code 0. The matching Python monolithic
build took 69.089 seconds, leaving a measured 6.08x self-host gap. Object-pipeline
layout is outside the cross-compiler byte-identity contract, while all 25
current monolithic parity targets above matched exactly.

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
