# Register-name resolution dispatch — 13 November 2026

A call profile of the full self-build (1,040,015,120 calls; the
instrumentation disables inlining, so tiny helpers are over-represented)
placed `mlc.asm._rid_any` at 13,842,672 calls: every register operand of
every emitted instruction resolves its spelling through a linear string
ladder of up to 48 comparisons, and the register predicates
(`_is_r8_name`, `_is_r32_name`, `_is_force_rex_8`, `_is_r64_name`) were
plain functions, adding a call each at roughly 155 emission call sites.
The Python twin already resolves through the `_RID`/`_R32`/`_R8`
dictionaries, making the ladder a self-hosted-compiler-only cost. This
report evaluates the measured replacement.

Implementation notes: `_rid_any` now dispatches on the register-name
length (two, three or four characters) and compares only the candidates
of that length. The accepted spellings and returned register ids are
identical to the old ladder (48 spellings; unknown names and non-strings
still return −1). `_rid_any` and the four register predicates carry the
`inline` marker. The Python twin is unchanged.

## Microbenchmark

`_rid_any` called in a tight loop over name sets, identical harness
before and after, three rounds each (median in parentheses):

| Case | Before | After |
| --- | ---: | ---: |
| Call overhead (`_modrm_byte` baseline) | 20–21 ns | 15–16 ns |
| Early ladder hits (`rax`…) | 52–56 ns | 26–28 ns |
| Late 8-bit hits (`sil`…) | 70–71 ns | 86–89 ns |
| Late 64-bit hits (`r15`…) | 174–233 ns | 52–53 ns |
| Realistic mix (40 spellings) | 111–127 ns (112) | 77–82 ns (78) |

The late 8-bit spellings (`spl`/`bpl`/`sil`/`dil`) sit deeper inside the
length-three block than in the old front-loaded ladder and pay roughly
15 ns more per hit; the extended-register and dword spellings drop from
up to 233 ns to 52–53 ns, which dominates the compiler's register mix.

## Self-build measurements

Both rows compile the unchanged repository source (the current worktree
of this repository) with a baseline compiler built from the repository
HEAD `efb7c59` in a temporary worktree and the current compiler. Three
measured rounds after a warm-up round, alternating compiler order on a
pinned CPU.

| Metric | Before | Current | Delta |
| --- | ---: | ---: | --- |
| Full warm ML self-build, wall median | 51.99 s | 50.76 s | −1.23 s (−2.4%) |
| Codegen phase median | 37,218 ms | 35,881 ms | −1,337 ms |
| Serialization phase median | 8,209 ms | 8,276 ms | Within variation |
| Full warm ML self-build, image | 65,861,120 B | 65,861,120 B | Byte-identical |
| Image hash | `ec4a8ed7…e3` | `ec4a8ed7…e3` | Identical |
| Peak process-tree commitment | 1.36 GiB | 1.36 GiB | Unchanged |

The raw per-round times (before 51.73–52.73 s, after 50.58–50.89 s) do
not overlap between variants.

## Evaluation

- The self-build gains 1.23 s of wall time (2.4%). The microbench
  estimate for the ladder alone (13.84 M calls at roughly 35 ns saved
  per mixed call, about 0.5 s) is exceeded because the `inline` markers
  also remove the call overhead of the register predicates at every
  emission site.
- Both variants emit byte-identical compiler images (same SHA-256),
  proving output parity of the refactor; no behavioral change ships.
- The Python twin needs no change: it already resolves through
  dictionaries, and both compilers agree byte-for-byte on the parity
  fixture (hash `57f0d92c…b01c`).
- Remaining profile hotspots for later rounds: the `_coerce_name`
  family (96.4 M calls) and the fastmap/arena form checks
  (`arr_vec_is`, `_fm_is_valid`, `_chunks_is_paged`).

## Validation already completed with the change

- Python unified suite: 222/222 passed. Native harness
  (`scripts/run_tests.ps1`): all steps green.
- `check_incremental.py` against both repositories: 96 compilation
  checks across three backends, all PASS.
- `check_codegen_structure.py` green in both compilers.
- Python and ML compilers agree byte-for-byte on the parity fixture
  `tests/codegen_optimizations.ml`.

## Reproduction

```text
# baseline image
git worktree add <dir> efb7c59
<dir>/build.ps1 -Compiler <repo>/build/mlc_win64.exe -SkipSmoke
# current image
<repo>/build.ps1 -SkipSmoke
# measurement
python tests/bench_compiler_optimization.py build/bench_rid_config.json build/bench_rid_report.json --repeats 3 --cpu 4
```

Raw samples, phase timings, image hashes, medians and the microbenchmark
readings are in
[`REGISTER_NAME_DISPATCH_2026-11-13.json`](REGISTER_NAME_DISPATCH_2026-11-13.json).