# MiniLang Compiler 1.2.11

This release completes portable native audio playback in MiniLang's standard
library without changing the language syntax, executable format or native
bridge ABI.

- `std.audio` provides typed player ownership, WAV/MP3/MIDI format detection,
  playback control, seeking, volume, rate, looping, duration/position queries,
  state inspection and a safe polled event queue.
- Windows plays WAV and MP3 through Media Foundation and local Standard MIDI
  Files through a dedicated WinMM sequencer. Linux uses the dynamically loaded
  GStreamer 1.x runtime for all supported audio formats.
- Local-file and network-source policy is explicit, cleanup is idempotent, and
  bridge errors are converted into managed MiniLang errors.
- Deterministic WAV, MP3 and MIDI fixtures exercise both compilers, Windows and
  Linux, alongside the existing video coverage.

Both compiler repositories contain the same 53-module standard library and the
same version-1 native media bridge sources. The Python suite passes 151/151;
the complete self-hosted suite passes with 136/136 embedded MiniLang tests.
Strict MiniDoc generation covers 53 files and 1,928 symbols with zero warnings.

Python bootstrap and self-hosting produce byte-identical release compiler
images. The Windows image is 65,331,200 bytes with SHA-256
`493965554B865B9666927551165D321D9338359CD4BFCF03AF01A344CA6B3F20`;
the Linux image is 65,335,104 bytes with SHA-256
`3986392C43989A67C30DC70E2A3A8502E49F2BA66DB5C284C39372D24397F300`.

Both CLI version switches and `MINILANG_VERSION` report 1.2.11. This Python
compiler release provides GitHub source archives. Ready-to-run Windows x64 and
Linux x64 compiler packages, including `std/`, native-media runtimes and
SHA-256 sidecars, are in the
[matching self-hosted release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.11).
