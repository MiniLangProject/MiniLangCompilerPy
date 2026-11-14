# MiniLang 1.3.8

The shared standard library adds object-oriented methods to the existing
`std.io.file.FileHandle` and `std.tls.Stream` structs. Optional
`std.net.TcpConnection`, `TcpListener` and `UdpSocket` structs own their native
socket handles and provide explicit, idempotent `close()` methods. Existing
module functions remain available and unchanged. The Linux file module now
qualifies its native `close` import to avoid a user-function name collision.

`--version`, `-version` and `MINILANG_VERSION` report **1.3.8**.

The [platform services guide](docs/PLATFORM_SERVICES.md) documents resource
ownership. The [evaluation](docs/reports/STDLIB_OOP_2026-11-14.md) records
Windows/Linux correctness, byte parity, MiniDoc generation and a cached-file
read benchmark. The [release matrix](docs/reports/release-1.3.8-version-matrix.json)
records final compiler hashes and validation. The one-shot crypto and
compression backends remain functional APIs; no input-buffering pseudo-stream
was added.

The Python reference compiler is distributed as source and requires Python
3.11 or newer. Ready-to-run Windows and Linux compiler packages are in the
matching self-hosted release.
