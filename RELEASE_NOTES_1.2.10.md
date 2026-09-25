# MiniLang Compiler 1.2.10

This release adds portable native audio/video playback to MiniLang's standard
library without changing the language syntax or executable format.

- `std.video` provides explicit player ownership, playback control, seeking,
  volume, stream metadata, state inspection and a safe polled event queue.
- Windows playback uses Media Foundation; Linux playback uses a dynamically
  loaded GStreamer 1.x runtime and therefore needs no GStreamer development
  headers to build the bridge.
- Local files are enabled by default while network sources require an explicit
  opt-in. Native window attachment enables embedding video in GUI applications.
- Matching native bridge sources, strict bounds/conversion checks, build
  scripts and cross-compiler Windows/Linux regression coverage are included.

Both compiler repositories contain the same 52-module standard library and the
same version-1 native video bridge sources. The focused playback regression and
full compiler suites pass, and strict MiniDoc generation reports zero warnings.

Python bootstrap and self-hosting produce byte-identical release compiler
images. The Windows image is 65,331,200 bytes with SHA-256
`D1E4312E9ADEA6EB190B68F0210999B06A22D744C43070874CF9BBA018FA05D8`;
the Linux image is 65,335,104 bytes with SHA-256
`83640A9437C16785647E21EEE254DD5AA4896B54126F28B426FD35FA5930AF28`.

Both CLI version switches and `MINILANG_VERSION` report 1.2.10. This Python
compiler release provides GitHub source archives. Ready-to-run Windows x64 and
Linux x64 compiler packages, including `std/`, native-video runtimes and SHA-256
sidecars, are in the
[matching self-hosted release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.10).
