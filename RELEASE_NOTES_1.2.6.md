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

Following existing compiler releases, GitHub publishes source archives only.
Build the self-hosted compiler with build.ps1 on Windows or build.sh on Linux,
using the matching MiniLangCompilerPy checkout for bootstrap.
