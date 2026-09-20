# Standard-library audit optimizations (20 September 2026)

This update is source-identical in the Python and self-hosted compiler
repositories. It changes standard-library code and tests, not the compiler
code generator or the MiniLang language.

## Changes

- `std.sort.sortFastBy` now uses an integer midpoint pivot and a bounded
  quicksort work stack. Stable `sortBy` uses bottom-up merging for larger
  arrays instead of quadratic insertion sorting; small arrays retain the
  insertion-sort path.
- Timed channels and `whenAnyFor` use `std.time.ticks()` deadlines instead
  of counting requested one-millisecond sleeps. Linux timed lock, semaphore,
  and event waits use the same monotonic basis. OS scheduling can still
  overshoot a deadline.
- Ordinary and synchronized hash maps update existing keys without a growth
  rehash. Deletion tombstones are counted and compacted at the current
  capacity when they occupy at least half the buckets.
- Schannel receives fragmented TLS records into geometrically grown buffers
  and encrypts outgoing records in one contiguous allocation. Its plaintext
  queue avoids a copy when entirely drained. OpenSSL avoids an exact-size
  receive slice.
- Linux `std.fs.copyFile` first tries `copy_file_range`, except on WSL
  DrvFS where that path measured slower. A failed/unsupported kernel copy
  resumes with one 1-MiB user-space buffer. The destination is not truncated
  until an open-descriptor inode check excludes copying a file over itself;
  non-overwrite mode uses `O_EXCL`.
- Windows `writeAllText` now checks the actual byte count and finishes a
  short native write rather than silently accepting a truncated file.
- `StringBuilder.toString` decodes an exactly filled buffer directly,
  avoiding one temporary byte slice; partially filled buffers retain the
  existing semantics.

## Measurements

Five independent runs per compiler and target on the same Windows host
(WSL2 Ubuntu for Linux). The permanent fixture is
`benchmarks/stdlib_collections_copy.ml`. Times below are median milliseconds.
The old sort number is a local reproduction of the previous insertion loop
on 8,192 reversed integers; the old Linux copy number is the previous
`readAllBytes` + `writeAllBytes` algorithm run on the same 32-MiB input.
They are diagnostic comparisons, not whole-application performance claims.

| Workload | Python Windows | Self-hosted Windows | Python Linux/ext4 | Self-hosted Linux/ext4 |
| --- | ---: | ---: | ---: | ---: |
| Previous stable sort, 8,192 reversed ints | 265 | 266 | 279 | 275 |
| Current stable sort, same input | below timer tick | below timer tick | 3 | 2 |
| Current stable sort, 10 × 16,384 ints | 32 | 31 | 30 | 29 |
| Hash-map 100,000 insert/delete pairs | 15 | 16 | 20 | 20 |
| Channel `ReceiveFor(50)`, actual wait | 63 | 63 | 50 | 50 |
| Previous Linux copy, 32 MiB on ext4 | — | — | 28 | 12 |
| Current Linux copy, 32 MiB on ext4 | — | — | 9 | 9 |

The earlier audit measured a 50-ms channel wait at roughly 765–782 ms on
Windows and 56–57 ms on Linux. Windows' coarser sleep/tick behavior explains
why the new wait is about 63 ms rather than precisely 50 ms. The native
Windows copy measurement varies between 0 and 16 ms at this resolution, so
no meaningful Windows-copy speed claim is made.

On WSL DrvFS (`/mnt/c`), the Python compiler's paired old/current Linux
copy medians were 260/257 ms. Native `copy_file_range` was slower there,
which is why the implementation selects bounded buffered I/O on DrvFS.
ext4's old-copy numbers are bimodal (about 12 or 28 ms), so the ext4 table
should not be read as a stable percentage improvement. The new Linux copy
uses no whole-file managed buffer: the fallback uses 1 MiB, and the kernel
path uses no managed transfer buffer. Peak RSS was not separately measured.
TLS throughput and the exact-fill StringBuilder path were not independently
benchmarked; their copy reductions were checked functionally.

## Verification

- Standard-library unit tests: Windows and Linux, Python and self-hosted
  compilers; Linux additionally run on both DrvFS and ext4. Includes the
  formerly failing fast-sort input, stable large-array sort, map updates and
  tombstone churn, large copy, overwrite refusal, and same-inode refusal.
- Task/channel and threading tests: Windows and Linux with both compilers;
  timed waits assert broad elapsed-time bounds.
- Native TLS integration: Schannel and OpenSSL with both compilers, positive
  client/server handshakes, hostname-rejection cases, and a 128-KiB transfer
  over multiple records.
- Representative Windows PE and Linux ELF outputs compiled from identical
  fixtures by the Python and self-hosted compilers had equal SHA-256 hashes.
  The tests establish byte parity for those fixtures, not every possible
  MiniLang program.

For example, the final standard-library test PE hash was
`5e10e6f97440a6fa12b655a04da75344120b9b30ba5a8637f21c0b70e1b88dc1`
and the ELF hash was
`6167d53925bd5c554351a3d3863f9695d32c59118d4f2ed831aaf605405ab4d3`
from both compilers.

The complete self-hosted compiler was also rebuilt from the current sources
once with each compiler. Both 65,331,200-byte Windows images had SHA-256
`e242c678b3a969a9858777b3206dc2a13cd5ca2e6f4812383e71e04ac75cea13`
and passed the build script's smoke test. These were separate diagnostic
artifacts; the existing `build/mlc_win64.exe` was not replaced.
