# Incremental interface reuse potential — 12 November 2026

The 30 October experiments report notes that the `.mif` declaration cache
"does not yet reuse semantic analysis across edited source files". A
per-file interface digest scheme (one small record per source file, combined
into the global fingerprint) was sketched to keep the analysis cache valid
across single-file edits. Following the project's measurement-first rule,
the achievable saving was measured before any implementation. This report
documents the measured rejection.

## Measurement setup

- Compiler: the repository `build/mlc_win64.exe` at the use-count-gate
  commit.
- Source: a temporary copy of the compiler tree (`mlc/`, `std/`,
  `mlc_win64.ml`; 2,166 cached native fragments across 47 modules).
- Object pipeline with the `build.ps1` heap flags and the incremental
  fragment cache, ten builds: one prime run, then three measured runs per
  mode after the prime:
  - `cached` — full `.mif` hit (record read and validated).
  - `recomputed` — `.mif` record deleted before the run; the compiler
    recomputes the global declaration fingerprint and rewrites the record.
    This is exactly the work a per-file scheme would try to avoid.
  - `edited` — one comment line appended to the entry file (the AST-relevant
    content is unchanged, but every cache key covering the entry file
    changes).
- Tool: `benchmarks/measure_interface_self.py` (in the self-hosted
  repository), a variant of `benchmarks/measure_interface_cache.py` with the
  heap flags, the object pipeline and the edited scenario. Byte-identical
  images across all runs are enforced.

## Measurements

| Mode | Median | Range |
| --- | ---: | ---: |
| `cached` | 38.74 s | 38.66–38.83 s |
| `recomputed` | 37.74 s | 37.63–40.10 s |
| `edited` | 38.86 s | 36.43–39.07 s |

- Recomputing the global declaration fingerprint (including rewriting the
  record) is not slower than reading the record: the medians differ by about
  one second in favor of recomputing, inside the 2.5-second spread of the
  recomputed samples. The interface walk costs nothing measurable at
  self-build scale.
- The prime run took 80.07 s (2,166 fragments compiled once into the cache);
  every warm run reuses all 2,166 fragments.
- After the comment edit, the first build recompiled exactly 2 of 2,166
  fragments (the entry-file functions) and reused the rest. The edited
  builds are not slower than the clean cached builds.
- All ten images are byte-identical (SHA-256 `00b6b3c2…e42e`, matching the
  self-build image of the same compiler from the use-count-gate
  evaluation).

## Decision: rejected

The proposed scheme can only save the interface recompute it would replace,
and that recompute is already free at realistic scale:

- A per-file digest scheme would add one record per source file, an ordered
  registration list (the files map is slot-ordered, not visit-ordered), a
  combined-key schema migration invalidating every existing `.mif` record
  once, and a fallback path for incomplete registrations — for a measured
  saving of zero.
- The 30 October measurements already put the full-recompute saving at
  3–5% only for a synthetic 1,000-function single file and "no gain" for
  `mlfmt`; the Python twin showed the same pattern. The self-build is the
  realistic case, and it shows no measurable cost at all.
- The token and fragment caches already absorb single-file edits: a
  comment edit recompiles 2 of 2,166 fragments with wall time inside
  run-to-run noise.

No per-file interface cache is planned; the `.mif` record and its
whole-program key stay as they are. The remaining edit-time cost is
re-parsing and relinking, which the token cache and fragment reuse already
cover.

## Reproduction

```text
<copy mlc/, std/ and mlc_win64.ml to a temporary directory>
python benchmarks/measure_interface_self.py build/mlc_win64.exe <src>/mlc_win64.ml --include <src> --cache <src>/cache --runs 3 --output build/interface_self.json
```

Raw samples, medians, fragment-reuse statistics and image hashes are in
[`INCREMENTAL_INTERFACE_REUSE_2026-11-12.json`](INCREMENTAL_INTERFACE_REUSE_2026-11-12.json).