# MiniLang 1.3.13 — scalable array equality

This source update fixes a correctness defect in both native code generators:
distinct equal arrays could compare unequal once the old work stack contained
more than 256 pending element pairs. A flat array of length 257 reproduced the
failure; nesting could reach the same limit with fewer elements per array.

## Behavior

Array equality now streams elements through explicit continuation frames. Flat
arrays use constant stack space regardless of their length and allocate no
comparison workspace. Nested comparisons memoize ordered array pairs in a hash
table with exact pointer checks on collisions and a maximum 50% load factor.
The first 32 distinct pairs fit inline; larger traversals grow a managed array
geometrically. There is no replacement arbitrary element/depth limit.

Separate cyclic arrays previously could run indefinitely. They now compare by
their unfolded structural values: revisiting a pair does not compare it again,
but all siblings of its first visit must still match. Thus a one-node cycle and
a two-node cycle may be equal if their values and branching are equal. A later
different leaf still makes the comparison false. Shared subgraphs need only
one traversal per ordered pair, without requiring identical alias structure.

Existing leaf behavior is retained, including numeric/string comparison and
identity handling for other objects. A 484-comparison bounded truth table,
including NaNs, produces the same result as 1.3.12. This change does not redefine
NaN identity cases or introduce nested operator-overload dispatch.

## Memory and threading

The continuation and memo banks contain traced array pointers and tagged
integer indices. On the first spill, precise root records publish the initialized
inline bank, original operands, pending child pair and workspace. Each visited
array remains independently reachable from the traced workspace. Subsequent
growth publishes the new buffer after initialization and rehashing. Success and
inequality both unlink the records, allowing every temporary buffer to be
reclaimed by the normal collector.

The workspace copy uses a non-allocating 64-bit `REP MOVSQ`; initialization,
hashing and rehashing contain no allocation or GC safepoint. The allocator
preserves the nonvolatile registers used for traversal. An allocation failure
takes the existing fatal out-of-memory path, rather than returning a false
inequality. Arithmetic/array-length representation guards also terminate rather
than wrapping the allocation or truncating the collector's root span.

Read-only shared graph comparisons are supported across threads and have their
own root records. Concurrent unsynchronized mutation remains a data race under
the language's existing threading contract. No shared comparison cache or
platform-specific raw allocation/release contract is introduced.

Metadata requires **O(distinct visited array pairs)** space. Hash lookup is
expected constant time with full collision resolution; adversarial collisions
can still degrade an open-addressed table. The implementation avoids both the
old width failure and an intermediate quadratic ancestor search, which was
rejected during measurement.

## Performance scope

The flat key cases used by Wusel remain allocation-free. The isolated probe
compares widths 5, 13, 81 and 256 against 1.3.12; wider old results are incorrect
and are not valid speed baselines. The exact alternating-run timings, allocation
totals, GC work and Linux minor-page-fault counts are retained in
[the performance record](docs/reports/release-1.3.13-array-equality-performance.json).

Five alternating before/after process pairs produced these median native times.
They are isolated comparison costs, not game-frame or compiler-throughput results.

| Flat array length | 1.3.12 | 1.3.13 | Comparison allocations |
| --- | ---: | ---: | ---: |
| 5 | 19.68 ns | 18.56 ns | 0 |
| 13 | 31.50 ns | 25.57 ns | 0 |
| 81 | 112.43 ns | 85.59 ns | 0 |
| 256 | 356.26 ns | 240.05 ns | 0 |
| 1,024 | incorrect result | 0.916 microseconds | 0 |
| 65,536 | incorrect result | 56.62 microseconds | 0 |

Cycle detection and retained comparison metadata have a cost on deep acyclic
chains that the old traversal happened to handle cheaply. The depth-4096 probe
actually contains 4,097 distinct pairs: crossing the capacity boundary needs
eight geometric allocations totaling about 1.045 MB per comparison. The final paired
medians were 498.17 microseconds versus 17.44 microseconds for the old valid
chain case. It performed no GC, but touched approximately 255 new pages per
comparison. This is an explicit tradeoff for complete graph comparison, not a
claim that every equality operation or compiled application becomes faster.

## Validation

- 82 focused assertions cover widths through 65,536; depth through 4,096; first,
  last and deep mismatches; typed arrays; aliases; large nested graphs; shared
  diamond DAGs; cycles; memo growth; forced GC and workspace reclamation.
- Four workers repeatedly compare read-only shared graphs while allocations and
  explicit collections exercise thread-local root ownership.
- A fixed 1 MiB heap enters equality and produces the expected allocator OOM
  exit, without returning a Boolean result.
- [The compiler matrix](docs/reports/release-1.3.13-array-equality-matrix.json)
  records 42 byte-identical images across Python, native monolithic and native
  MLO, with 15 native executions (including three expected OOM exits). Linux executes
  natively; Windows and MinUX images are cross-build checks on this host.
  Concurrent-GC configurations are Windows-only and were not executed here.

Reproduction on Linux, with the sibling compiler checkout already bootstrapped:

```sh
python tests/check_array_equality.py \
  --reference mlc_win64.py \
  --compiler ../MiniLangCompilerML/build/mlc_linux_x64 \
  --report build/array-equality-matrix.json
```

Rebuild the native compiler from this source revision. Previously published
binary release archives retain their original contents and version numbers.
