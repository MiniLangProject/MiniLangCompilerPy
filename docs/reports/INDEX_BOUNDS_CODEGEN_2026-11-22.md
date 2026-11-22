# Dynamic index bounds checks, 2026-11-22

## Code analysis and change

After a negative array, bytes, or string index is adjusted by the nonnegative
container length, both code generators used a signed negative-index branch and
a signed upper-bound branch. A single 64-bit unsigned comparison with the
length rejects both an index below `-len` and an index at or above `len`.
The optimized read and write paths and the general dispatch paths now emit
`cmp rcx, rdx; jae out_of_bounds`. Each affected path removes one `test` or
`cmp` and one conditional branch. The complete 64-bit index is retained.

The [regression fixture](../../tests/language_index_bounds_fast.ml) covers
positive, negative, empty-container and ±2^32 indices; array, bytes, and
string reads; array and bytes writes; and the optimized loop paths. The parity
runner also checks the emitted branch shape.

## Runtime measurement

The [benchmark source](../../benchmarks/index_bounds_fast.ml) performs
30,000,000 dynamic indexes per process. `STORE` selects reads or writes;
`GENERIC` removes the array parameter annotation to exercise general dispatch.
The [measurement script](../../benchmarks/measure_index_bounds.py) checks
output, warms each image twice, alternates A/B order, and reports process-time
medians. Runs used Windows x64 on an AMD Ryzen 9 9900X. Both compiler versions
were the self-hosted compiler, before and after this change, with
`--no-gc-periodic`; the new images were byte-identical to Python compiler
images. The baseline compiler SHA-256 was
`545CF5480B7BFB4818BF3062EC4B3E0BBE67CC64B1528F7F11BCF6494EDBDED2`.

| Index path | A/B rounds | Before | After | Change |
| --- | ---: | ---: | ---: | ---: |
| Specialized array read | 30 | 76.94 ms | 75.43 ms | -1.97% |
| Specialized array write | 30 | 82.66 ms | 81.39 ms | -1.53% |
| General read | 60 | 83.33 ms | 82.87 ms | -0.56% |
| General write | 60 | 78.36 ms | 77.31 ms | -1.33% |

The general read result varied across shorter repetitions from -0.46% to
+0.87%, so it does not establish a measurable runtime gain. The shorter branch
sequence remains useful for code size. The general write benchmark image fell
from 88,576 to 88,064 bytes; the other three images retained their aligned
file sizes. No game-frame FPS result is inferred from these loop timings.

## Correctness and compiler parity

- Python test suite: 264 passed, 0 failed, 0 skipped.
- Self-hosted regression runner with `-SkipRepros`: passed on Windows and its
  configured Linux/WSL checks, including the new index fixture.
- Python, self-hosted monolithic, and self-hosted `.mlo` output: 30 of 30
  byte-identical images across five relevant fixtures and both x64 targets.
- The Linux index fixture also executed successfully under WSL.
- Self-hosted compiler stages 1 and 2: identical SHA-256
  `59C52D918E1CF7FD050617E0F49013E16E1FB5434F70A5BEB54A73D10EB04972`.

MiniQuake FPS was not measured in this run. The measured improvement applies
to workloads with frequent dynamic indexing; the effect on a particular game
depends on how much frame time it spends in those paths.
