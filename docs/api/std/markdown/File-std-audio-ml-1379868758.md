# `std/audio.ml`

[Home](README.md) · [Files](Files.md)

Provides WAV, MP3 and MIDI playback on Windows and Linux.

Package: [`std.audio`](Package-std-audio-501224270.md)

Reachable from entry: **no**

## Imports

- `std/path.ml` as `path` → [std/path.ml](File-std-path-ml-701536411.md)
- `std/string.ml` as `strings` → [std/string.ml](File-std-string-ml-1276545685.md)
- `std/video.ml` as `media` → [std/video.ml](File-std-video-ml-900169693.md)

## Declarations

<a id="constant-constant-std-audio-audio-error-const-audio-error-1782-std-audio-ml-2034036877"></a>
### AUDIO_ERROR

```ml
const AUDIO_ERROR = 1782
```

Stable std.audio error number.


Source: `std/audio.ml:18`

<a id="function-function-std-audio-backend-function-backend-std-audio-ml-1381422234"></a>
### backend

```ml
function backend()
```

Return the native audio backend name.


Source: `std/audio.ml:363`

- [std.audio.Event](Type-std-audio-event-1751276296.md) — struct
- [std.audio.EventKind](Type-std-audio-eventkind-1850962106.md) — enum
- [std.audio.Format](Type-std-audio-format-787557795.md) — enum
<a id="function-function-std-audio-formatfromsource-function-formatfromsource-source-std-audio-ml-1827824367"></a>
### formatFromSource

```ml
function formatFromSource(source)
```

Detect a supported audio format from a local path or URI suffix. Unknown extensions remain playable when the native backend supports them.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `source` | `dynamic` | — | Source path or URI. |


Source: `std/audio.ml:146`

<a id="function-function-std-audio-formatname-function-formatname-value-std-audio-ml-941796055"></a>
### formatName

```ml
function formatName(value)
```

Return a stable lowercase name for an audio format.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Format enum value. |


Source: `std/audio.ml:164`

<a id="function-function-std-audio-isavailable-function-isavailable-std-audio-ml-629756284"></a>
### isAvailable

```ml
function isAvailable()
```

Report whether the installed shared-media bridge is available.


Source: `std/audio.ml:368`

<a id="function-function-std-audio-issupportedformat-function-issupportedformat-value-std-audio-ml-2003268917"></a>
### isSupportedFormat

```ml
function isSupportedFormat(value)
```

Report whether a format is part of std.audio's portable format contract.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Format enum value. |


Source: `std/audio.ml:173`

<a id="constant-constant-std-audio-max-audio-milliseconds-const-max-audio-milliseconds-media-max-video-milliseconds-std-audio-ml-290400000"></a>
### MAX_AUDIO_MILLISECONDS

```ml
const MAX_AUDIO_MILLISECONDS = media.MAX_VIDEO_MILLISECONDS
```

Largest supported seek position in milliseconds.


Source: `std/audio.ml:20`

- [std.audio.Player](Type-std-audio-player-1417198005.md) — struct
- [std.audio.PlayerOptions](Type-std-audio-playeroptions-1251061429.md) — struct
- [std.audio.State](Type-std-audio-state-765656853.md) — enum
