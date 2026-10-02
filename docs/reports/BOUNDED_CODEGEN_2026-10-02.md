# Bounded code-generation improvements — 2 October 2026

Development evaluation after v1.2.14. No language/API/version change and no
release publication is part of this work.

## Implementation and limits

Both backends implement the same conservative subsets of the five proposed areas:

1. **Temporary struct projection:** `Pair(x, y).field` needs no allocation when
   the constructor has 1–8 fields, full positional arity, absent/int contracts,
   and every argument is a total integer expression of bounded depth (three).
   Calls, heap reads, captures, named/default arguments and fallible expressions
   retain the original path. This is not general escape analysis or scalar
   replacement of a local object across multiple statements.
2. **Dynamic loops:** stable unboxed local/parameter array/bytes roots can be
   hoisted for `for i = 0 to len(values) - 1`. Container parameter contracts
   now seed representation analysis even without operator overloads. Later
   writes are still validated. Dynamic bounds checks are deliberately retained:
   MiniLang's inclusive `0 to -1` loop executes descending. This is not loop
   versioning or general bounds-check elimination. Root publication, GC polls,
   cancellation polls, alias-visible element writes and evaluation order remain.
3. **Local register use:** for proven integer operands, the completed left
   value remains in R10 across an unboxed integer RHS variable load instead
   of being spilled/reloaded. Other expressions retain their rooted stack
   homes. This is not a new global register allocator or dead-store pass.
4. **Code size:** constant runtime-error construction is emitted once as
   `fn_make_error_const`, called from its cold sites. The helper preserves
   shadow-space/alignment rules, tagged codes, immortal message pointers and
   source/function/line metadata. Allocation and catchability are unchanged.
   This work does not add forward-branch relaxation.
5. **Bounded specialization:** untyped integer literal parameters of existing
   single-return inline expansions receive integer representation facts.
   Arguments still evaluate in order, guards remain, the generic callable body
   remains, and the existing per-callee 4096-byte inline budget still applies.
   Reassigning a parameter or using a multi-statement body excludes this new
   specialization. There are no additional cloned functions or general PGO.

The initial wider register fast path exposed different existing type proofs in
two assembler functions when the LHS was dynamic. Restricting the new path to
two proven integer operands restored the full compiler fixed point. Regression
coverage also guards against retaining literal-parameter facts across later
parameter writes; the single-return restriction prevents that unsound inference.

## Verification

- Python suite: **156 passed, zero failures/skips**.
- Native ML: **136 core tests passed**, complete outer runner passed (CLI, ABI, GC,
  concurrency, Windows/Linux, FFI, object-pipeline and listing regressions).
- Shared runtime fixture covers allocation-free projection, discarded-field
  side effects and contract failures, empty/descending/singleton loops, array
  and byte stores, container/index mutation exclusions, wrong container types,
  collection inside a hoisted loop, generic inline fallback, parameter type
  changes and error code/source/function/line retention.
- Shared `tests/check_codegen_structure.py` verifies eliminated versus retained
  constructor allocations, hoisted roots, retained dynamic bounds checks,
  mutation exclusions, integer-register instruction patterns, one shared error
  helper, specialized inline arithmetic and the generic callable fallback.
- Windows/Linux regression images agree across Python, Windows-hosted ML and
  Linux-hosted ML; both normal and object pipelines were checked for ML.
- Windows Python bootstrap and full Windows-native selfbuild are byte-identical.
  Python and Windows ML also cross-build the full Linux compiler identically.
  A full Linux-native compiler selfbuild was **not repeated** in this round;
  Linux-native compilation and execution of regression fixtures were checked.
- MiniDoc regenerated: **37 files, 3285 symbols, zero warnings**.
- Standard-library sources are unchanged.

The existing native `cstr` return-codegen parity exception documented in
[COMPILER_PARITY.md](../../COMPILER_PARITY.md) is not changed by this work.

## Measurement method

Use the preserved v1.2.14 compiler to build the same extended benchmark source
as the current compiler. Verify that current Python and ML benchmark images
are byte-identical per target. Run Windows and Linux/WSL measurements
sequentially, after builds/tests finish: one warmup per image, then twenty-one
alternating before/after pairs for each of twenty workloads.

The program's monotonic timer measures the workload; process wall time is
reported separately. Managed heap deltas measure bump-pointer growth, not
cumulative allocation, reserved virtual memory or retained live objects.
Only the bounded struct-projection case disables periodic GC (at most 16 MB
before optimization) to expose allocation volume without collection/reuse;
other cases keep the default collector settings. Peak RSS/working set is
measured separately per process (Windows GetProcessMemoryInfo, Linux GNU time).
Tiny sub-millisecond cases and WSL scheduling are noisy; these microbenchmarks
are not a claim about MiniQuake/MiniSQL/HollowKeep application throughput.

## Results

Machine: AMD Ryzen 9 9900X (12 cores / 24 logical processors).
The final results pin the runner and its children to logical CPU 0 and use
**21 alternating pairs** per case. Initial unpinned runs showed unstable short
control timings and are not used for the table.

Median workload time, milliseconds (negative percentages are improvements):

| Workload | Windows before → after | Change | Linux/WSL before → after | Change |
| --- | ---: | ---: | ---: | ---: |
| 500,000 temporary struct projections | 8.0559 → 0.4641 | −94.2% | 11.3126 → 0.5095 | −95.5% |
| Dynamic array indexing | 22.6135 → 22.0877 | −2.3% | 22.9922 → 22.6576 | −1.5% |
| Integer local-register workload | 12.5649 → 12.1696 | −3.1% | 12.1660 → 11.5759 | −4.8% |
| Literal inline arithmetic | 4.9816 → 3.2421 | −34.9% | 5.6922 → 3.4779 | −38.9% |
| 100,000 caught runtime errors | 2.0859 → 2.3083 | **+10.7%** | 2.2067 → 2.1112 | −4.3% |

The projection case's heap bump growth falls from **16,000,000 to zero bytes**.
Peak working set falls from 23,515,136 to 7,462,912 bytes on Windows (−68.3%);
Linux GNU-time peak RSS falls from 17,301,504 to 1,179,648 bytes.
These are separate OS metrics, not directly comparable cross-OS memory totals.

| Image | Before, bytes | After, bytes | Change |
| --- | ---: | ---: | ---: |
| Windows benchmark PE | 179,712 | 165,888 | −7.7% |
| Linux benchmark ELF | 190,192 | 177,904 | −6.5% |
| Windows self-hosted compiler | 64,587,264 | 54,494,720 | −15.6% |
| Linux self-hosted compiler | 64,589,648 | 54,497,120 | −15.6% |

The Windows benchmark's actual .text shrinks from 122,575 to 108,696 bytes
(−11.3%); the compiler's .text shrinks from 64,080,855 to 53,988,255 bytes
(−15.8%). The compiler-image comparison includes the small amount of new
optimizer implementation code, not just a recompile of unchanged sources.

### Controls and trade-offs

There is **no across-the-board speedup**. All checksums agree, but code layout
and OS scheduling still affect small workloads. Complete control changes:

| Control | Windows time change | Linux/WSL time change |
| --- | ---: | ---: |
| division | −0.2% | −1.2% |
| division-constants | −0.1% | −0.5% |
| division-wide | −5.4% | +0.9% |
| local-cse | **+11.5%** | −18.3% |
| integer-format | −0.7% | −0.9% |
| integer-format-small | −0.9% | −5.2% |
| repeat | −4.3% | +2.7% |
| repeat-one | +2.3% | −60.6% |
| concat-empty | +11.5% | −54.2% |
| join-one | +2.6% | −57.3% |
| concat-control | −1.8% | +0.5% |
| concat-small-control | +6.1% | +2.2% |
| repeat-two-control | +4.0% | +6.5% |
| repeat-two-multi-control | +1.7% | approximately 0% |
| join-control | +1.4% | +2.8% |

The identity controls take less than 0.2 ms: their large relative changes should
not be extrapolated to applications. The Windows local-CSE regression is
material in this microbenchmark. An exploratory 32-byte loop-alignment build
recovered that loss, but worsened other controls and added padding; blanket
alignment was therefore **not enabled**. This supports a layout effect, not a
proof that every observed timing difference is caused by alignment.

Shared error construction trades an extra call/frame for substantially less
code. The Windows error-storm slowdown is retained and disclosed rather than
described as a universal performance gain. Dynamic-loop wins are modest; the
large, robust gains are targeted struct allocation elimination, leaf inline
specialization, and code size. Real application throughput still needs
application-specific A/B evaluation.

Full samples, checksums, peak RSS and image SHA-256 values:
[Windows](BOUNDED_CODEGEN_WINDOWS_2026-10-02.json),
[Linux/WSL](BOUNDED_CODEGEN_LINUX_2026-10-02.json).

### Verified image hashes

| Artifact | SHA-256 |
| --- | --- |
| Windows compiler: Python bootstrap = native selfbuild | `D69006C432B55D1912585F5340F5DAAB3C6F724A648C32BB1E1EA5E467A2CE99` |
| Linux compiler: Python = Windows ML cross-build | `752BE5AD165C835AAE482B30A511ED13FB5832A88E660170DE2FA3FB14FE536B` |
| Windows runtime fixture, across hosts/pipelines | `D571E7C48E72A2B4D80D3D361A7B5B1007B17042A101DFF20D08AB8277F585F7` |
| Linux runtime fixture, across hosts/pipelines | `F3DE7C24A4A66E1A0A435CB72D5DAC89711DB941689D6D3B05697E57C7E10697` |
| Windows benchmark: Python = ML | `9BA8C6DE82FE34222825FDDBEE34905F8B9BAC18517D9CFB8A26B5A461B9AC61` |
| Linux benchmark: Python = ML | `BB41806A3DC0189F8DE5F680A2EACB9A539C1FBB90DF4EB9DA1F30ECFC4E4036` |

These are development artifacts, not replacements for published v1.2.14
release checksums. The existing canonical release executables were not replaced.

## Reproduction

From either repository, build `benchmarks/runtime_codegen.ml` with the
preserved baseline and current compiler, using identical target/options:

```text
python benchmarks/compare_runtime_codegen.py before.exe after.exe --runs 21 --cpu 0 --output windows.json
python3 benchmarks/compare_runtime_codegen.py ./before-linux ./after-linux --runs 21 --cpu 0 --output linux.json
python tests/check_codegen_structure.py path/to/compiler
```

For the Python compiler, pass `mlc_win64.py` to the structural checker; for the
native compiler, pass its executable. Run the Linux benchmark command inside
Linux. No commit, push, version bump or release upload is performed here.
