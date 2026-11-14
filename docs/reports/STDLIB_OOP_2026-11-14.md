# Stateful standard-library methods (2026-11-14)

Both compiler repositories use the same 53 standard-library sources. This
change adds methods to the existing `FileHandle` and `tls.Stream` structs and
optional owning `TcpConnection`, `TcpListener` and `UdpSocket` wrappers. The
functional APIs and their return values remain available. File and TLS
methods reuse their existing structs; each network wrapper adds one small
struct allocation per socket. All methods call the established native helpers.

## Correctness

`tests/stdlib_oop_services.ml` covers positional file reads and writes,
append, truncation, locks, explicit and repeated close, a user callback named
`_close`, fake TLS provider lifecycle and borrowed-socket ownership, TCP
connect/accept/peer/receive-into, UDP datagrams, and closed-state errors.
It runs on Windows and Linux. The Python and Windows self-hosted compilers
produced byte-identical PE and ELF files; the Linux self-hosted compiler
produced the same ELF bytes. The shared std sources and all 357 generated
std MiniDoc files are byte-identical across repositories. MiniDoc reports
53 files, 2,006 symbols and zero warnings.
The full Python suite passed 230/230 cases; the native harness passed
146/146 cases and its remaining platform checks completed successfully.
The final fixture was rerun on both targets after the last factory additions.

On Linux, the new test initially exposed an unrelated name collision:
the test callback `_close` could be selected in place of the file module's
native `close` import. `std.io.file` now calls that import with its full
package name at both call sites. The regression test keeps the colliding
callback to protect the file API against recurrence.

## Positional I/O measurement

`tests/bench_stdlib_oop.ml` compares `file.readAt(handle, ...)` with
`handle.readAt(...)` in the same executable. Each timed phase performs
50,000 cached reads of 4 KiB into a reused buffer. Four A/B/B/A phases
follow one warmup; four complete runs were taken per target. Linux uses
`/tmp` rather than WSL DrvFS so the result measures the file API rather
than the mounted Windows filesystem. Times are in-process monotonic
milliseconds and include the native read calls.

| Target | Functional median per phase | Method median per phase |
| --- | ---: | ---: |
| Windows x64 | 62.5 ms | 63 ms |
| Linux x64 (WSL, `/tmp`) | 10 ms | 10 ms |

Raw phase times (ms) were Windows functional
`63,62,62,62,62,78,78,78`, method `46,63,47,63,63,78,78,78`;
Linux functional `10,10,10,10,10,11,11,10`, method
`10,9,10,10,11,10,10,12`.

The sample has timer granularity and system-load noise; it shows no
repeatable material regression in this cached-read workload. It does not
measure socket setup, GC pressure or cold storage. Python and self-hosted
compilers emitted byte-identical benchmark images for both targets.

## API scope

`std.crypto` and `std.compress` currently expose one-shot backends. A
wrapper that buffers every chunk before one final call would increase peak
memory and copying, so this change does not present such a wrapper as a
streaming API. True incremental backends can be added separately when a
concrete use case requires them.
