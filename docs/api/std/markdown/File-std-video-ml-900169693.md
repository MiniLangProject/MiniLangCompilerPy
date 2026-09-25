# `std/video.ml`

[Home](README.md) · [Files](Files.md)

Provides native audio/video playback on Windows and Linux.

Package: [`std.video`](Package-std-video-1470394703.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-video-backend-function-backend-std-video-ml-1365649424"></a>
### backend

```ml
function backend()
```

Return the native backend name.


Source: `std/video.ml:489`

- [std.video.Event](Type-std-video-event-1402863457.md) — struct
- [std.video.EventKind](Type-std-video-eventkind-276077919.md) — enum
<a id="function-function-std-video-isavailable-function-isavailable-std-video-ml-1080881046"></a>
### isAvailable

```ml
function isAvailable()
```

Report whether the installed bridge ABI matches this standard library.


Source: `std/video.ml:498`

<a id="constant-constant-std-video-max-video-milliseconds-const-max-video-milliseconds-9223372036854-std-video-ml-2017745157"></a>
### MAX_VIDEO_MILLISECONDS

```ml
const MAX_VIDEO_MILLISECONDS = 9223372036854
```

Largest seek value that remains representable as GStreamer nanoseconds.


Source: `std/video.ml:19`

- [std.video.Player](Type-std-video-player-1368988610.md) — struct
- [std.video.PlayerOptions](Type-std-video-playeroptions-261096172.md) — struct
- [std.video.State](Type-std-video-state-64793316.md) — enum
<a id="constant-constant-std-video-video-abi-version-const-video-abi-version-1-std-video-ml-322457182"></a>
### VIDEO_ABI_VERSION

```ml
const VIDEO_ABI_VERSION = 1
```

Native bridge ABI expected by this version of the standard library.


Source: `std/video.ml:17`

<a id="constant-constant-std-video-video-error-const-video-error-1781-std-video-ml-356035852"></a>
### VIDEO_ERROR

```ml
const VIDEO_ERROR = 1781
```

Stable std.video error number.


Source: `std/video.ml:15`
