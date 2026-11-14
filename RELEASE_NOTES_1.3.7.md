# MiniLang 1.3.7

Both compilers now include an optional, dependency-free executable packer for
Windows x64 PE and Linux x64 ELF. `--pack` compresses generated code with LZ4;
the embedded startup loader decompresses it directly in memory. No UPX or
other external tool is needed to build or run packed programs. `--unpack-exe`
restores the original file byte-for-byte. The previous UPX method remains
available explicitly with `--pack=upx --upx PATH`.

`--version`, `-version` and `MINILANG_VERSION` report **1.3.7**.

The [packing guide](docs/EXECUTABLE_PACKING.md) documents usage and limits.
The [evaluation](docs/reports/NATIVE_PACKING_2026-11-14.md) records 12
byte-identical Windows/Linux images across Python, Windows self-hosted and
Linux self-hosted compilers in both build pipelines. Full regression suites
passed: 229 Python tests and the native suite. Large compiler images shrink
by approximately 77.6%; a packed compiler has higher startup latency, so
packing remains optional. The [release matrix](docs/reports/release-1.3.7-version-matrix.json)
records final compiler hashes and smoke checks.

The Python reference compiler is distributed as source and requires Python
3.11 or newer. Matching ready-to-run Windows and Linux compilers are in the
self-hosted release.
