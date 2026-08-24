# Compiler parity and self-hosting

Verified on 24 August 2026 against the matching 1.1.0 revisions of:

- `MiniLangCompilerPy`, the Python bootstrap/reference compiler; and
- `MiniLangCompilerML`, the compiler implemented in MiniLang.

## Compatibility result

There are two compatibility claims:

1. **Target-output parity:** for the same sources, include-root order and
   compiler options, the Python compiler, the normal self-hosted path and the
   self-hosted `.mlo` pipeline emit byte-identical Windows x64 PE files.
2. **Compiler-image layout contract:** compiler sources use the same canonical
   entry/function/support and section layout as every other target. Historical
   full fixed-point measurements are listed separately from current automated
   and MiniQuake target-output measurements.

Python accepts `--object-pipeline` for project/CLI parity and emits its
equivalent monolithic image. The serialized `.mlo` files remain an internal
self-host implementation detail; the final linked PE is part of the same
byte-identity contract.

## 1.1.0 release fixed point

The release compiler was rebuilt through the complete trust chain. All stages
report `MiniLang Compiler 1.1.0`.

| Compiler image | Size | SHA-256 |
| --- | ---: | --- |
| Stage 1, built by Python | 55,712,256 | `3453273F217CBD24BC38777B4AF5255AC1117C6E00DB803DFC0C94654212A8EE` |
| Stage 2, built by Stage 1 | 55,712,256 | `431C7E74BB0A200EA17BB1831D726C8CB5755DB3008A07687916375E717AD71F` |
| Stage 3, built by Stage 2 | 55,712,256 | `431C7E74BB0A200EA17BB1831D726C8CB5755DB3008A07687916375E717AD71F` |

Stage 2 and Stage 3 are byte-identical, establishing the self-hosted fixed
point. The equally sized Python bootstrap image has a different layout; it is
the bootstrap input, not the fixed-point claim.

The representative `language_suite.ml` target was then built by Python, by the
Stage 3 monolithic path and by the Stage 3 `.mlo` path. All three files ran
successfully and were byte-identical: 1,620,480 bytes, SHA-256
`6E7BF4DCA93339C95B6EB4587613918053EE827A178A4055124599978FF94C67`.

## Current TLAB and safepoint fixed-point verification

The post-release TLAB implementation and the back-to-back GC safepoint fix were
bootstrapped and self-compiled again on 24 August 2026. The compiler image
stabilized after the first self-hosted stage:

| Compiler image | Size | SHA-256 |
| --- | ---: | --- |
| Stage 1, built by Python | 56,076,800 | `FF9ABB3004E780C7B0CF0295AB5F4CA02197CA508F2C87E51F76C5B0CE222BEE` |
| Stage 2, built by Stage 1 | 56,076,288 | `4CA9E4030FAC128DCFCDD3AAB6D885C1E29F04DBC9A9DCD006D48EC96682907B` |
| Stage 3, built by Stage 2 | 56,076,288 | `4CA9E4030FAC128DCFCDD3AAB6D885C1E29F04DBC9A9DCD006D48EC96682907B` |

The parallel short-lived-allocation target built by Python and Stage 2 is
byte-identical at 170,496 bytes with SHA-256
`191A6FA983B7F9E83236E9AE970DB1174927D7D98F9AAB061AD73B9BC07DC8FB`.
Its 24-thread, 48-million-allocation workload completed 50 consecutive runs
without a timeout after the fix. The dedicated back-to-back GC regression is
also byte-identical at 112,128 bytes with SHA-256
`F2AE65320F4A92C2EA5232B04F4CE8B83BC335DDF552870FD50DEBDD38468F82`.

## Historical regression binary record

The following exact hashes record the earlier broad parity pass. The programs
remain in the automated suites; the table is retained as a reproducible
historical record rather than relabelled with unmeasured release hashes.

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
| `codegen_optimizations.ml` | 331,776 | `34478CFA76A8B1493B92B99C099F7ED0A5939589FB5CC045C0E667059B38B6AF` |
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
arguments, logical thread ids, 64 KiB thread-local allocation buffers and
managed worker pools with backpressure.
It also exhaustively covers every public `is` runtime category, including
case-insensitive `Thread`/`thread` checks and their negated forms.
Compiler-scale coverage crosses repeated phased collections and verifies that
target GC options cannot alter compiler-internal collection or target bytes.

All 32 files below `std/` also have matching relative paths and byte-for-byte
identical contents in both repositories. This includes `std.threading`, the
concurrent collection modules, CPU feature dispatch, CRC-32/CRC-32C checksum
modules and the CNG-backed cryptography modules.

## Historical pre-canonical bootstrap and self-build stages

The same `MiniLangCompilerML/mlc_win64.ml` source tree was compiled with the
same heap and GC options for this comparison.

| Compiler image | Size | SHA-256 |
| --- | ---: | --- |
| Python-built MiniLang compiler | 54,161,920 | `92363D1BC22A2B7EA648C189A563B6EC86B9BBCDF1D5861DA29D528593B1FC3C` |
| MiniLang self-build through `build.ps1` / `.mlo` | 54,650,368 | `C6365921E6112AEEEA7F32DFF9E846A1AD358448582C72A6579EFAB6F67E4B00` |

The table above records the last release artifact comparison before canonical
object layout was introduced. Current `.mlo` linking concatenates fragments in
the exact monolithic entry/function/support and section order, shares the
global constant pools, and therefore no longer introduces an image-layout
difference. The historical compiler-image rows are retained for comparison;
they are not presented as a fresh fixed-point measurement of this revision.

Both compilers report `MiniLang Compiler 1.1.0` for `-version` and
`--version`. The repositories and GitHub releases are source-only; generated
compiler and test executables are intentionally excluded.

Self-builds should continue to use `MiniLangCompilerML/build.ps1`, which keeps
the large assembler graph bounded by spilling canonical `.mlo` fragments. The
memory-management strategy no longer changes the resulting compiler image.

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
- synchronized assembler coverage with 228 golden opcode vectors.

Generated-code optimization is synchronized as part of the same parity
contract: both backends use the same inline expansion budget with unconditional
callable fallback bodies, local representation flow for integers, floats,
booleans, strings, arrays, bytes and concrete structs, constant-loop lowering,
known-struct method devirtualization and inline expansion, two ABI-preserved
XMM register homes for proven hot primitive locals, constant integer strength
reduction, loop-invariant container-base hoisting, proven bounds-check
elimination, GC-root/prologue sizing and short-back-edge selection. Stack sizing also
accounts for calls hidden inside eligible inline bodies, so an expanded wide
call cannot overwrite caller locals, debug saves or the root-frame record. The shared
`tests/codegen_optimizations.ml` fixture covers optimized behavior and fallback
semantics, including a narrow caller around a hidden ten-argument call. Listing
checks additionally verify float/bool/struct fast paths, specialized array and
bytes indexing, invariant hoists, eliminated in-range loop checks, retained
negative-index normalization, all inline fallback bodies and both the small and
expanded loop/root forms. Structural listing checks also assert direct known
method targets, removal of the polymorphic method cache in those paths,
XMM-backed hot-local loads, ABI save/restore across a promoted user-function
call and the absence of division/multiply/CL setup for the covered constant
integer cases.

Canonical object batches also carry the cumulative inline byte budget and call
accounting from one fragment to the next. Local `fn_ret_*` and `fn_defer_*`
control-flow labels are excluded from runtime-helper discovery. The shared
optimization fixture crosses multiple object batches to guard this state.

The self-hosted compiler additionally retains `.mlo` production/linking,
`--object-pipeline`, assembly/PE/data listings and its direct encoder helpers.

## Self-host performance work

The MiniLang implementation was optimized without changing target bytes. The
main changes are native string/bytes hashing for compiler-internal fast maps,
paged byte/array builders, chunked/indexed `.rdata` and `.data` label tables,
chunked section-relocation records, direct 32/64-bit assembler emission,
pre-sized label maps and generational text-fixup resolution. Each bounded phase
scans only newly emitted patches; unresolved forward references are revisited
once after helper emission instead of after every function batch. The parsed
AST and active codegen graph are explicit roots through function emission and
are released before the support-helper tail. The compiler's internal periodic
GC limit is 3 GiB for large canonical builds and remains independent of the
target's `--gc-limit`. These are implementation details of the
self-hosted compiler, not additions to the language-level compatibility
contract.

The append optimization pass additionally replaces the growing
function, global, scope and local arrays with geometrically growing internal
vectors and builds the per-module function index once. The canonical object
writer isolates short-lived function-analysis batches while advancing shared,
append-only read-only/data/BSS builders and constant pools. Fragment boundaries
therefore cannot alter data order or deduplication, and prior section state is
never copied merely to append the next delta.
`--profile-compiler` exposes phase timings without affecting generated target
bytes.

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

With the type-flow, invariant-hoisting and bounds-check pass included, the last
pre-canonical two stages took 181.644 and 470.513 seconds, emitted 301 objects each
and were byte-identical at 54,650,368 bytes with SHA-256
`C6365921E6112AEEEA7F32DFF9E846A1AD358448582C72A6579EFAB6F67E4B00`.

With method devirtualization, hot primitive register homes and integer strength
reduction included, consecutive self-host stages completed in 160.022 and
128.441 seconds. They produced byte-identical 56,409,600-byte compiler images
with SHA-256
`DB0DB8DB532F340DC4A126D4C64EC8E8D5AF7F1D3412F2DFA5155339F8FA07DB`.

## Tests

Latest complete runs for this revision:

```text
Python harness:    PASS 103, FAIL 0, SKIP 0
MiniLang harness:  PASS 96, FAIL 0
ML opcode smoke:   synchronized golden vectors and direct encoder passed
Outer ML gates:    CRC/SIMD/CNG, ABI, object parity, listings and repros passed
```

The 2026-08-24 MiniQuake check used clean commit
`7e8d0f614f7ad33f423e88873c210b7f846bbced`. Python compiled the 142-source
target in 66.368 seconds and the self-hosted monolithic compiler in 932.680
seconds. Both produced the same 57,156,608-byte PE with SHA-256
`A2E36E0A572B394FCE4A531AED4C3574E4D21A83E0F9761238DA72A0B2200923`.
Both the previous and optimized PE passed a 120-frame retail E1M1 headless
smoke. In an alternating two-run A/B check with 300 warm-up and 10,000 measured
frames per run, average measured frame time fell from 12,665.0 to 12,262.5 ms,
approximately 790 to 815 frames/s (+3.3%). Individual runs varied, so this is a
local performance check rather than a release-grade statistical claim.

The 1.1.0 MiniQuake acceptance input was a frozen 142-file source snapshot from
commit `1036b1c3b551d00de777c67293d262a6cc5c2739` plus 18 dirty worktree
entries. Its source-tree SHA-256 was
`9EE5DD4ACC9DAAC7D6A810DA497D7DA385A80D2934A4EE2EC2DE0D897A44B285`.
Python compiled it in 67.528 seconds, the self-hosted monolithic path in
2,024.375 seconds and the canonical `.mlo` pipeline in 431.789 seconds. The
`.mlo` path is 4.69 times faster than the self-hosted monolith; Python remains
6.39 times faster than `.mlo` on this input.

All three outputs are byte-identical 57,005,568-byte PE files with SHA-256
`3071B78B6F2C72B8C3036E5D62010831758F6EA3E7FFA3F6AF908BB9756003B3`.
The `.mlo` run emitted 494 function fragments in 361.500 seconds, runtime
helpers in 3.781 seconds and completed its fresh-process link in 42.375
seconds. Retail Quake `id1` data passed a 120-frame runtime smoke and a
120-frame deterministic compatibility trace with rolling hash `74dc3dc9`.
The same target completed 1,000 E1M1 headless frames in 712 ms and 1,000
rendered frames in 5,995 ms, approximately 1,404.5 frames/s and 166.8 FPS.

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
.\build\mlc_win64.exe .\tests\language_suite.ml .\build\suite-mlo.exe -I . --object-pipeline
$objectHash = (Get-FileHash .\build\suite-mlo.exe -Algorithm SHA256).Hash
($pythonHash -eq $miniLangHash) -and ($miniLangHash -eq $objectHash)
```

The final expression must be `True`. Equality is guaranteed only when source
contents, imported files, include-root order, compiler options and canonical
source names are equivalent.
