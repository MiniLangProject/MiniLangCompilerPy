# MiniLang 1.3.9

MiniLang adds `--target minux-x64` to the Python and native compilers, with
native ELF output, shared SysV FFI marshalling, managed memory and threading,
built-in packing and complete compiler selfhosting under MinUX.

The shared standard library selects native MinUX math, memory, filesystem,
process, time, terminal, network, TLS and crypto services. Advanced files include
positional/durable writes, directory synchronization and advisory locks. Native
media supports PCM WAV and raw AVI. MiniGui 0.1.1 provides the native desktop
bridge. Protected-page C-string reads are corrected on every compiler target.

Both compiler CLIs and `MINILANG_VERSION` report **1.3.9**. Native packages are
provided for Windows x64, Linux x64 and MinUX x64, with matching standard-library
sources, runtime libraries, documentation, manifests and SHA-256 sidecars.
The MinUX compiler is packed to satisfy the native 16 MiB loader limit.

MinUX requires the [kernel prerequisites](https://github.com/n1k0m0/MinUX/commit/3675df7)
for large managed workloads, file locks and directory durability. Install the
included MinUX runtime libraries in `/lib`. Preserve the bundled Mbed TLS license.
See [the MinUX guide](docs/MINUX.md) for deployment and capability limits,
including native IPv4 networking without a localhost loopback interface,
unsupported socket options and restricted GUI/media formats.

Validation of the implementation includes 230 Python regression tests, 146
native harness tests, 321 portable stdlib assertions inside MinUX, and eleven
packed fixture comparisons across Python/direct/MLO output. Full MLO stage2
and stage3 compiler builds inside MinUX reached a byte-identical fixed point
before the version-only release bump; stage3 compiled and ran a program. The
release matrix records the new binaries and their separate release validation.

[Release verification](docs/reports/release-1.3.9-version-matrix.json)
