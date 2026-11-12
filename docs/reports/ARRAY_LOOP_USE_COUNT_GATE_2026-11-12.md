# Array loop versioning use-count gate — 12 November 2026

The 30 October experiments report left the dynamic array loop profitability
heuristic as worth improving: the guarded fast/empty split for dynamically
sized arrays duplicated loop bodies whose cost slowed the full compiler
self-build. Both compilers now require at least two indexed reads of the
hoisted collection before versioning a dynamic loop. Single-use loops keep
the ordinary checked loop. The change ships as the commit
"Gate dynamic array loop versioning on the indexed use count" in both
repositories; this report is its measured evaluation.

Implementation notes: the ML compiler counts uses through per-use entries in
the hoist plan targets (the internal dedupe in `_fast_target_add` was
removed; consumers deduplicate themselves), and plans carry a fifth
`use_count` element. The Python twin keeps a parallel `use_counts` dict in
`_for_index_hoist_plans`. `hoist_targets` still consumes elements 0–3 only.

## Generated program measurements

Both rows compile the same repository source with a baseline compiler built
from the release 1.3.3 tree (the 9 November release commit in each
repository) and the current repository compiler. Self-hosting makes the
bootstrap path irrelevant to the result.

| Workload | Baseline | Current | Delta |
| --- | ---: | ---: | --- |
| `tests/codegen_optimizations.ml` `.text` | 301,568 B | 300,032 B | −1,536 B (−0.5%) |
| `benchmarks/runtime_codegen.ml` `.text` | 166,912 B | 165,888 B | −1,024 B |
| Full warm ML self-build, wall median | 50.87 s | 50.71 s | Not distinguishable |
| Full warm ML self-build, image | 65,894,912 B | 65,878,528 B | −16,384 B |
| Full warm ML self-build, peak process-tree commitment | 1.36 GiB | 1.36 GiB | Unchanged |

The self-build medians come from three measured rounds after a warm-up
round, alternating compiler order on a pinned CPU; the raw per-round times
(50.61–51.17 s) overlap between variants. Batch phase medians (codegen
36,320 vs 36,097 ms; serialization 8,165 vs 8,254 ms) stay inside that
run-to-run variation.

Both `codegen_optimizations` fixture outputs are byte-identical between the
two compilers and pass; the current image hash
(`57f0d92c…b01c`) is the established cross-compiler parity hash. The
`runtime_codegen` benchmark returns checksum 24,187,476,000,000 from both
images; only its self-reported millisecond figure differs.

## Evaluation

- The gate removes the duplicated loop bodies of single-use dynamic loops.
  On the compiler image this is worth about 16 KiB (four 4-KiB pages). The
  magnitude matches the earlier rejected bounded loop-cost prototype from
  the 4 November evaluation, which found the same 16 KiB against a broader
  cost walk. Those two gates overlap: the same single-use loops dominate
  both.
- The 30 October self-build slowdown of the full array versioning is
  therefore mostly the price of versioned multi-use loops; the single-use
  share is not visible in self-build wall time.
- Raising the threshold beyond two uses has no headroom: the measurable
  code-size pool left after the gate is smaller than one percent already.
  No further threshold tuning is planned.
- Single-use dynamic loops return to checked loops; the retained multi-use
  fast/empty split and all guarded behavior are unchanged.

## Validation already completed with the change

- Python unified suite: 222/222 passed. Native harness: all steps green,
  including the byte-parity fixture checks.
- `check_codegen_structure.py` green in both compilers: single-use
  fixture keeps the checked loop, the multi-use fixture keeps the
  unchecked fast version and the checked empty-array fallback.
- Python and ML compilers agree byte-for-byte on the parity fixture.

## Reproduction

```text
# baseline image
git worktree add <dir> <release-1.3.3-commit>
<dir>/build.ps1 -Compiler <repo>/build/mlc_win64.exe -Output <dir>/build/mlc_base.exe -SkipSmoke
# current image
<repo>/build.ps1 -SkipSmoke
# measurement
python tests/bench_compiler_optimization.py build/bench_heuristic_config.json build/bench_heuristic_report.json --repeats 3 --cpu 4
```

Raw samples, phase timings, image hashes and medians are in
[`ARRAY_LOOP_USE_COUNT_GATE_2026-11-12.json`](ARRAY_LOOP_USE_COUNT_GATE_2026-11-12.json).
Section sizes above were read from the PE headers of the compiled fixtures.