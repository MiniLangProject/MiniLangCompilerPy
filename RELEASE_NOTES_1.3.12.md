# MiniLang 1.3.12 source update

## NaN normalization

Native floating-point NaN now remains a float after arithmetic. x86 `UCOMISD`
sets both the parity and zero flags for unordered operands; the old normalizer
mistook that zero flag for exact integer equality and converted NaN to zero.
Both code generators now check unordered status before integer normalization.
Constant-folded arithmetic follows the same rule; boxed NaN constants use the
self-hosted compiler's canonical quiet-NaN encoding in both constant pools.
The same rule applies to scalar helpers, unboxed numeric consumers, fused trees
and counted loops. Exact integer results, signed-61 wrapping and zero
normalization retain their previous behavior. Existing division-by-zero and
unordered-divisor contracts are unchanged.

The new `numeric_nan_normalization.ml` fixture covers native `sqrt(-1)`, an
immediate NaN, arithmetic-generated NaN, scalar and optimized paths, infinities,
zero and integer wrapping. Existing numeric regression oracles now explicitly
accept matching unordered floats.

## Allocation and collector diagnostics

`gc_stat(5)` and `gc_stat(12)` continue to report central allocator requests and
bytes. They do not include every small-object allocation. New stable indices expose the complete allocation path and collector work:

| Index | Meaning | Unit |
| --- | --- | --- |
| 22 | All public allocation requests, including small bump/TLAB requests | requests |
| 23 | Aligned requested object blocks, including headers; excluding TLAB refill capacity and free-block slack | bytes |
| 24 | Cumulative full-stop collector work | nanoseconds |
| 25 | Longest full-stop collector work interval | nanoseconds |
| 26 | Most recent full-stop collector work interval | nanoseconds |

The timers start after heap-lock acquisition and the stop-the-world rendezvous,
and end before threads resume. They measure collector work, not the complete
application stall. Linux uses a monotonic clock; Windows uses its performance
counter and frequency. Duration indices are unavailable for concurrent
collection and unsupported timer targets; unavailable diagnostics return `void`.
Indices 16–21 retain their existing concurrent-only availability. Allocation
instrumentation is emitted only when source code references `gc_stat`, and
diagnostic reads allocate nothing. A conservative AST scan preserves indirect
and default-argument references. This also fixes the old reachability gate:
builtin hoisting previously made it look as though every program used statistics,
so unused diagnostic writes were emitted. Per-thread allocation totals use atomic
increments. The gate regression checks allocation writes and collector clocks
in both monolithic and object-pipeline builds; read-only builtin helpers can
still be emitted by existing hoisting.


## Validation

The [runtime matrix](docs/reports/release-1.3.12-runtime-matrix.json) records
60 byte-identical images: ten fixtures, Linux/Windows targets, and Python,
self-hosted monolithic, and self-hosted object-pipeline compilation. All ten
Linux runtime cases passed. Windows images were cross-built, not executed.
The final Linux bootstrap passed version, direct/MLO image identity, execution
and project-build smoke checks.

`python3 tests/gc_stats_gate_check.py --compiler PATH_TO_NATIVE_COMPILER
--reference-compiler PATH_TO_PYTHON_COMPILER` passed six gate cases. Native
images must match the Python reference exactly before its symbolic allocator
and clock listing is inspected; the native assembler itself writes raw bytes.
The three inputs cover no reference (including misleading comments/strings),
a direct reference, and a first-class reference used only as a default argument.
Each is checked with and without the object pipeline.

This is a source revision. It does not replace the hashes or verification
claims of previously published 1.3.11 binary packages. See repository-local
regression reports for the exact compilers and targets exercised by this update.
