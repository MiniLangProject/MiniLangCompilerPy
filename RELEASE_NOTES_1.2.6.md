# MiniLang Compiler 1.2.6

This patch release supports MiniGui's new Windows/Linux backend and fixes native
C-string return conversion in the Python reference compiler. The byte-copy
helper can overwrite a volatile register holding the returned string length;
the emitter now reloads that length before terminating the MiniLang string.
This prevents crashes when GTK returns widget text.

Both compiler repositories cover Unicode, empty and null C-string returns.
The self-hosted emitter already preserves the length correctly; its version is
advanced alongside the reference compiler to retain the matching release pair.
Both CLI version switches and MINILANG_VERSION now report 1.2.6.

The release is verified with native Windows/Linux compiler builds, the Linux
FFI regression emitted by both compilers, CLI/predefined-version checks and
MiniGui's Windows/Linux control, generator and startup tests. Earlier full-suite
and fixed-point results remain identified as 1.2.5 results in COMPILER_PARITY.md.

## Binary downloads

- [Windows x64 ZIP](https://github.com/MiniLangProject/MiniLangCompilerPy/releases/download/v1.2.6/MiniLangCompilerPy-1.2.6-windows-x64.zip)
- [Linux x64 tar.gz](https://github.com/MiniLangProject/MiniLangCompilerPy/releases/download/v1.2.6/MiniLangCompilerPy-1.2.6-linux-x64.tar.gz)

Extract the complete package, including `std/`. Run `mlc.exe` on Windows or
`./mlc` on Linux. Compile with `-I .` from the package directory; select
`--target linux-x64` explicitly for Linux output. Each archive has a SHA-256
sidecar and includes a quick-start guide. No installed Python is required.
Linux binaries were built and tested on Ubuntu 24.04 x86-64 (glibc 2.39).

The reference compiler is distributed as a PyInstaller executable with its
Python runtime embedded. The runtime extracts to a temporary directory
when launched. It does not launch a system Python interpreter.
