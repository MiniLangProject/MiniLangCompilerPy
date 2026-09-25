# Native std.video bridge

std.video keeps the MiniLang API identical on both supported targets while
delegating decoding, clocks, audio output and optional video presentation to
the operating system's media stack:

- Windows x64 uses Media Foundation's IMFMediaEngine.
- Linux x64 uses GStreamer 1.x playbin and GstVideoOverlay.

The bridge has a small versioned C ABI declared in
include/minilang_video.h. Backend threads never call into MiniLang. They write
into a bounded native event queue which the application drains with
Player.pollEvent(). This avoids managed callbacks during GC and makes event
delivery deterministic from the application's control thread.

## Build

Windows requires Visual Studio C++ x64 build tools and a Windows SDK:

    .\native\video\windows\build.ps1

Linux requires only a C compiler to build the bridge. GStreamer is resolved
dynamically, so development headers are not required:

    sh native/video/linux/build.sh

The resulting bridge must be deployed beside the MiniLang executable:

- minilang_video.dll on Windows;
- libminilang_video.so on Linux.

Windows 10/11 supplies Media Foundation. Linux needs the GStreamer 1.x runtime
and the plugin packages for the formats an application accepts. On Ubuntu, a
useful non-patent-encumbered baseline is:

    sudo apt install libgstreamer1.0-0 gstreamer1.0-plugins-base gstreamer1.0-plugins-good

Additional codecs are deliberately an application/deployment choice.

## Ownership and UI integration

Each successful Player.open() owns one native backend instance. Always call
close(); repeated calls are harmless. Open, control and close calls for one
player must stay serialized on the same application thread. Decoder work stays
on backend threads and does not use MiniLang's managed heap. Player fields
documented as internal are runtime implementation details and must not be
modified by application code.

Without attach(), playback is headless but still clocked, which is useful for
audio, metadata probing and tests. For visible video, pass a valid native child
window/surface handle to attach() before the first play(). On Windows this is
an HWND; on Linux it is the platform handle expected by GstVideoOverlay. A GUI
toolkit should expose that handle without transferring ownership.

Network URIs are rejected by default. Set PlayerOptions.allowNetwork only when
the application intends to accept remote media. Supported containers and
codecs follow the installed OS media stack rather than a private codec bundle.

## Integration test

tests/video_stdlib.ml covers option validation, local/network policy, metadata,
audio/video stream discovery, playback, pause, seek, end-of-stream, state and
deterministic cleanup. The opt-in runner builds both bridges, generates silent
and audio/video fixtures with FFmpeg, executes Windows and Linux tests with
both compiler implementations, and verifies byte-identical target output:

    .\native\video\test.ps1

Use -SkipLinux on a host without WSL/Ubuntu. The normal compiler test suite
does not require media runtimes or FFmpeg.
