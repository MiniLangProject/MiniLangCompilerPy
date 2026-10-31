# Standard library performance pass (31 October 2026)

The Python and self-hosted compiler repositories contain identical changes to
their standard libraries. Measurements used paired executables compiled from
the old and new sources on the same Windows host; Linux runs used WSL Ubuntu.
Times are representative milliseconds, not whole-application estimates.
Windows `time.ticks()` has roughly 15 ms resolution, so small differences
were not treated as wins.

| Workload | Old | New | Decision |
| --- | ---: | ---: | --- |
| Base64 decode, 20 MiB, Windows | 500–547 | 265–282 | Keep lookup/ASM path from 256 encoded bytes |
| RLE encode, 100 MiB repeated bytes, Windows | 766–828 | 47–62 | Keep hybrid run scanner |
| RLE encode, 100 MiB random bytes, Windows | 1797–1812 | 1718–1922 | No consistent regression |
| LZ4 encode, 200,000 × 1 KiB repeated, Windows | 297–375 | 187–250 | Keep fused hash/table ASM |
| LZ4 encode, 20,000 × 4 KiB random, Windows | 344–406 | 313–360 | No regression |
| Stack bulk copies, 20,000 × 4,096 cells, Windows | 437–469 | 46–78 | Keep native `copyArray` |
| List front insert/remove, 5,000 × 4,096 cells, Windows | 203–250 | 15–32 | Keep temporary bulk copy from 64 shifted cells |
| Stable sort, 100 × 4,096 integers, Windows | 94–110 | 47–63 | Keep direct default comparator |
| Fast sort, same workload, Windows | 94–110 | 31–47 | Keep direct default comparator |
| Quote 20 × 1.2 MB with many escapes, Windows | 531–578 | 46–63 | Keep exact-size ASM path |
| Constant-time compare, 50 × 1 MiB unequal lengths, Windows | 218–266 | 62–63 | Keep length-safe ASM scanner |
| Compact 50 × 1 MiB repeated bytes, Windows | 31–47 | 15–31 | Keep RLE lower-bound skip |
| TLS pin equality, 2 million 32-byte comparisons, Windows | 250–282 | 46–47 | Keep native scanner |
| Linux time fields, 1 million write/read pairs | 60–67 | 33–38 | Keep two-dword operations |
| Linux timespec writes, 1 million calls | 26–29 | 18–20 | Keep two-dword operations |
| Linux `sqrt`, 100,000 values | 32–40 | 4–8 | Keep native libm/CRT path |
| Linux `exp`, 100,000 values | 21–25 | 4–7 | Keep native libm/CRT path |
| Linux `ln`, 100,000 values | 17–18 | 5–8 | Keep native libm/CRT path |

`string.split` uses one search pass and a growable result list. In the tested
Windows workloads it reduced the no-separator case from about 31 to 15 ms
and sparse separators from about 110 to 94 ms; dense separators remained
about 94 ms. The self-hosted compiler showed the same pattern.

## Candidates not retained

- A pure ASM RLE run scanner made random input much slower. The retained
  hybrid checks the first bytes in MiniLang before scanning a real run in ASM.
- A separate ASM LZ4 table probe slowed random input. Fusing hash calculation
  with the byte-backed table probe removed that regression.
- Bounded RLE and LZ4 encoders did not improve container workloads measurably.
  A sound lower bound for the *entire* RLE output did improve `compact`.
- ASM integer hash mixing, byte states in the ordinary hash map, and an ASM
  uppercase hex encoder showed no reliable gain. Byte states in the
  synchronized map showed only a small, noisy lookup gain, no churn gain, and
  changed the exposed state field type, so that variant was removed.
- `StringBuilder.toString` cannot decode only its initialized prefix with the
  current primitives. Its existing full-buffer fast path remains; removing
  the partial-buffer copy requires a new runtime primitive.

## Verification

- `tests/stdlib_unit_tests.ml` on Windows and Linux with both compilers;
  expanded cases cover long Base64 input, long quoted UTF-8/escapes, large
  list shifts with references, split boundaries, and native math contracts.
- `tests/compression_codecs.ml` on Windows and Linux with both compilers.
- `tests/linux_target_smoke.ml` on Linux with both compilers, including signed
  64-bit field packing.
- Old/new encoded RLE and LZ4 byte hashes matched for boundary sizes and
  repeated, patterned, and random blocks. Old/new Base64 and quote outputs
  matched on the same differential fixture.

The native math functions return more accurate approximations than the old
software series. They require `msvcrt.dll` on Windows and `libm.so.6` on
Linux, both already available on the tested targets. The existing rules for
nonpositive `sqrt` (returns `0.0`) and `ln` (returns `void`) remain.
