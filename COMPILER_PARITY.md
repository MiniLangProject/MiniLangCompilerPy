# Compiler parity and self-hosting

Verified on 23 August 2026 against the matching 1.0.0 revisions of:

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
| `language_suite.ml` | 1,611,264 | `EFAB37BAE26C94D37F86251DF06A3C9C2BA8B5EFF783C036D4103F3134FAB39A` |
| `stdlib_unit_tests.ml` | 3,762,688 | `FCD7C73C89A485D248B7CAD91903BFEFDB8036E1A88705646A914DA12058FA3E` |
| `gc_periodic_test.ml` | 161,280 | `4876C18B4E367688A26090E6EC947921E1543EB60052618E063C794DACC78E99` |
| `gc_heap_stress.ml` | 83,456 | `F466A0EE8CE26C2BD71D365C600CECBF8F00152F655323A95FB02119BE51D718` |
| `gc_box_float_safepoint.ml` | 365,056 | `EF8DFCFB90DD57D2E9778DCFE6715DA1E6A0E1CBDE240F0BB8D891C68F062A72` |
| `gc_float_call_roots.ml` | 411,648 | `F505F887117B069766A88A1311C84F516B7005F7A3662E9999BA2288121C996B` |
| `gc_nested_graph_roots.ml` | 271,872 | `F2F7C04AD3E0F907EDBB25D4E0959FA8E314DD6CD0BFD1FA17B3CFED360DF07B` |
| `gc_reference_write_roots.ml` | 132,608 | `4C1AA70AA4501458C576AA6F619BBCDD41542FDC3AE1F2A8AD5F537D4ED25355` |
| `aes128_ecb_nist_kat.ml` | 331,776 | `D257F6F7F75036384DB08F6AA22C9D9CCDCAF9CA1E7146B245A799CA2B0A08F4` |
| `winapi_extern_smoke.ml` | 64,512 | `944BA64C4D8C5A27CCE8E17ADB0E0A7683D128D13D3EEC0F08526B255AA19564` |
| `native_bytes_ptr_smoke.ml` | 84,480 | `2F2D64A74A5258B6A633A9354D8D39AC825A8030E4C350C2471E9351AD60676C` |
| `native_raw_value_smoke.ml` | 82,944 | `1615B1278569E998597F4E2C2317513E9BA9ABE368846D7FB5FAEC7F4D6AE21F` |
| `native_callback_wndproc_smoke.ml` | 86,528 | `82FC4B0ECA563535841D8ED1EA1A2446E30E18A0FB52A11A09552BBC690419E3` |
| `global_function_rebind.ml` | 69,120 | `A3D4661966A7AC7E7E57DC11FD7C1C39E7499DD8C49D1B49489F225DB72B1891` |
| `thread_features.ml` | 239,104 | `AC62897033463B3E33BACC25B77E160A76ED71EFD74B1D9499742AAC16EF93C9` |
| `threading_stdlib.ml` | 908,800 | `89AFECFE6DF68134D54B7F914DB7275A466615F3A9ED0455C1FB025D2DB12D19` |
| `extern_abi_validation_valid.ml` | 70,656 | `05387489F45AEE34BF227E4965281A93137159AB84B7C4BA09565A32920EE6D8` |
| `codegen_optimizations.ml` | 285,696 | `AA54ABD78DF049A976E895E85911354CBAAB7318556469F56C188D61C07EA385` |
| `thread_pool.ml` | 656,896 | `294AF95CD24BDD72DFBF0258F05C9B21A8542BB097531049F4E92571B601EBE2` |
| `type_checks.ml` | 135,680 | `CABA11CACCCC9A15946172085489C50D0452AD15E2EF20F5B4EC7A8C7F8A4BCA` |
| `member_callable_direct.ml` | 72,704 | `99EB4C4FD38EBBCB82A8EA994E9F815C31C59BED2C0B0117246DC032C69BD886` |
| `codegen_phase_gc.ml` | 404,480 | `70D9F9145CFAA29716E72160B760DDA31B992A56750D6A000AB87ED7A4622D03` |
| `compiler_gc_liveness.ml` (`--gc-limit 1m`) | 164,864 | `0A6617023A0EB39691AEAE6BB8CBF2749E2C745550FE431603B1B61578C3B3E4` |
| `defer_features.ml` | 83,456 | `D5ADFC76E2BD6FA08AE1313CBA75D38C77FD48FDA0A0D9A231C5EF23ABB069C7` |
| `extern_out_runtime.ml` | 74,240 | `A3317E95D46637027B7DBD6BCF493D6ED3CE1FBB84C618FD27E693371834168D` |

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
| Python-built MiniLang compiler | 54,161,920 | `92363D1BC22A2B7EA648C189A563B6EC86B9BBCDF1D5861DA29D528593B1FC3C` |
| MiniLang self-build through `build.ps1` / `.mlo` | 54,650,368 | `C6365921E6112AEEEA7F32DFF9E846A1AD358448582C72A6579EFAB6F67E4B00` |

The compiler images differ because the supported self-build is linked from
`.mlo` objects while the Python bootstrap emits one monolithic image. Both
subsequently compiled `language_suite.ml`, `defer_features.ml` and
`extern_out_runtime.ml` to the byte-identical target hashes listed above. Two
consecutive current MiniLang object-pipeline self-build stages were
byte-identical at 54,650,368 bytes with the hash shown above, so the supported
self-host path reaches a binary fixed point.

Both compilers report `MiniLang Compiler 1.0.0` for `-version` and
`--version`. The repositories and GitHub releases are source-only; generated
compiler and test executables are intentionally excluded.

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
callable fallback bodies, local representation flow for integers, floats,
booleans, strings, arrays, bytes and concrete structs, constant-loop lowering,
loop-invariant container-base hoisting, proven bounds-check elimination,
GC-root/prologue sizing and short-back-edge selection. Stack sizing also
accounts for calls hidden inside eligible inline bodies, so an expanded wide
call cannot overwrite caller locals, debug saves or the root-frame record. The shared
`tests/codegen_optimizations.ml` fixture covers optimized behavior and fallback
semantics, including a narrow caller around a hidden ten-argument call. Listing
checks additionally verify float/bool/struct fast paths, specialized array and
bytes indexing, invariant hoists, eliminated in-range loop checks, retained
negative-index normalization, all inline fallback bodies and both the small and
expanded loop/root forms.

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

With the current type-flow, invariant-hoisting and bounds-check pass included,
the latest two stages took 181.644 and 470.513 seconds, emitted 301 objects each
and were byte-identical at 54,650,368 bytes with SHA-256
`C6365921E6112AEEEA7F32DFF9E846A1AD358448582C72A6579EFAB6F67E4B00`.

## Tests

Latest complete runs for this revision:

```text
Python harness:    PASS 96, FAIL 0, SKIP 0
MiniLang harness:  PASS 94, FAIL 0
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
.\build.ps1
.\build\mlc_win64.exe .\tests\language_suite.ml .\build\suite-ml.exe -I .

$pythonHash = (Get-FileHash ..\MiniLangCompilerPy\build\suite-py.exe -Algorithm SHA256).Hash
$miniLangHash = (Get-FileHash .\build\suite-ml.exe -Algorithm SHA256).Hash
$pythonHash -eq $miniLangHash
```

The final expression must be `True`. Equality is guaranteed only when source
contents, imported files, include-root order, compiler options and canonical
source names are equivalent.
