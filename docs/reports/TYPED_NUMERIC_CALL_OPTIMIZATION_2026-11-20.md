# Typed numeric helper optimization (2026-11-20)

## Change

Both code generators now consider a short, fully typed `int` helper with one
local arithmetic temporary for their existing bounded call-site inliner. The
eligible function has non-optional `int` parameters, an `int` return, one local
assignment, and pure two-leaf `+`, `-` or `*` expressions for the assignment
and return. The existing inliner enforces its size budget. It preserves
parameter and return contracts and leaves the normal callable body available
for indirect calls and fallback. A pure `int` initializer guarded by
`as int` can reuse an already checked parameter fact; a custom `typeof` still
runs. The inline scope carries the proven local fact so return-contract
behavior remains identical to the ordinary function body.

A second bounded shape fuses a private float temporary into its return
expression at an inline call site. The existing float-tree emitter keeps a
runtime tag guard and replays the original Value operations whenever an
intermediate result normalizes to an integer. Only non-optional float
parameters, a float return, two pure `+`, `-` or `*` expressions and a single
use of the temporary qualify. Parameter and return contracts still run.

This does not add a new machine-code calling convention or change MiniLang's
runtime Value representation. A general raw XMM typed-call ABI and typed
containers remain separate work. A statically wrong call still
produces the existing catchable runtime type error (`1308`), preserving the
language's `try(...)` behavior.

## Measurement

Windows x64, `benchmarks/typed_integer_helper.ml` (measured from an identical
copy in the ignored experiment build directory):
30 million direct calls to `step(x as int) returns int`, with one local `x + 3`
and return `local * 2`. Existing compiler versus candidate, ten interleaved
runs per image, wall time including process startup. The images printed the
same result (`900000210000000`).

| Measure | Existing | Candidate |
| --- | ---: | ---: |
| Median wall time | 154.86 ms | 126.41 ms |
| Change | | **18.4% faster** |
| PE file size | 84,992 bytes | 84,992 bytes |
| Sampled peak private bytes | 35,401,728 | 35,401,728 |

A second 30-million-call case uses `intermediate as int = x + 3` in
[`benchmarks/typed_integer_local_guard.ml`](../../benchmarks/typed_integer_local_guard.ml).
The same ten-run interleaved method yielded:

| Measure | Existing | Candidate |
| --- | ---: | ---: |
| Median wall time | 156.15 ms | 93.91 ms |
| Change | | **39.9% faster** |
| PE file size | 84,992 bytes | 84,480 bytes |
| Sampled peak private bytes | 35,397,632 | 35,397,632 |

This is a focused microbenchmark. It does not establish a speedup for MiniSQL,
HollowKeep, or general application workloads. The float trial with ten
million calls showed overlapping times, so no float-specific optimization was
accepted for the earlier plain-inlining candidate. The new guarded
float-tree fusion was then measured with ten million calls to
[`benchmarks/typed_float_temporary.ml`](../../benchmarks/typed_float_temporary.ml):

| Measure | Existing | Candidate |
| --- | ---: | ---: |
| Median wall time | 244.81 ms | 168.11 ms |
| Change | | **31.3% faster** |
| PE file size | 82,432 bytes | 83,968 bytes |
| Sampled peak private bytes | 35,397,632 | 35,397,632 |

A separate 100,000-call allocation probe in
[`benchmarks/typed_float_allocation.ml`](../../benchmarks/typed_float_allocation.ml)
measured `heap_bytes_used()` growth of 7.2 MB versus 4.8 MB (33.3% less).
This measures short-run heap growth, not live retained objects or peak private
process memory.

## Verification

The executable hashes below are from the development builds before the
version bump. See the [release verification matrix](release-1.3.10-version-matrix.json)
for the tagged 1.3.10 binaries.

- Python suite: 253 passed, zero failed or skipped.
- Self-hosted suite: 169 passed, zero failed; the full platform and standard-library runner also completed successfully.
- Focused matrix: eight fixtures, Windows and Linux targets, Python
  monolithic, self-hosted monolithic and `.mlo` pipeline: 48 byte-identical
  images and eight Windows runtime cases passed, including custom `typeof`.
- Windows self-hosting reached an exact SHA-256 fixed point:
  `A2431ECECEC0E0F07A2C76D6869A18C5E27A5D5B5707504C362EFEFAF19FAD82`.
- The Python and self-hosted Linux compiler images are byte-identical:
  `9EF48E1CF79BF8D5A2D435DE654FFD0B94CB287F417BC0A7C6419F1E36A5B7E7`.

The new float fixtures check integer-normalizing intermediates, caught type
errors, indirect calls, custom `typeof` effects, error origin and forced GC.
Both new float fixtures also ran successfully under WSL Linux.
