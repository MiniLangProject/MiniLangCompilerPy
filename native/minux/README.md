# MinUX native adapters

Build from the compiler repository on Linux/WSL:

```sh
python3 tools/build_minux_native.py --minux-root ../../MinUX
```

The build uses the existing MinUX SDK, GCC 12.5 and verified Mbed TLS 3.6.5
source. Mbed TLS is rebuilt privately with PIC and pthread locking; its license
accompanies the output. No dependency downloads or toolchain modifications occur.
The native import/relocation audit is recorded in `runtime-manifest.json`.

Install the resulting `.so` libraries in MinUX `/lib`. TLS needs a trusted CA
bundle, or an explicit per-client CA file/pin. The shared crypto library uses
native `/dev/urandom`; no fallback RNG is provided.

`platform.c` implements positional I/O, native advisory-lock calls and echo-safe
secret input. `crypto.c` and `tls.c` delegate cryptography to Mbed TLS. `media.cpp`
implements bounded integer-PCM WAV and raw BGR AVI decoding/playback, with actual
audio completion tracking and native desktop BMP attachment. Compressed codecs
and network media report unsupported-format errors.

See [the target guide](../../docs/MINUX.md) for kernel prerequisites, complete
capability limits and real-guest verification commands. MiniGui's desktop bridge
lives in the sibling repository at `native/minux/minigui_minux.cpp`.
