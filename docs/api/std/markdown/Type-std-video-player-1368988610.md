# `std.video.Player`

[Home](README.md) · [Source file](File-std-video-ml-900169693.md)

<a id="struct-struct-std-video-player-struct-player-std-video-ml-1399171301"></a>
## Player

```ml
struct Player
```

A native player handle with deterministic explicit ownership.


Source: `std/video.ml:361`

## Members

<a id="method-method-std-video-player-attach-function-attach-windowhandle-std-video-ml-1608197656"></a>
### attach

```ml
function attach(windowHandle)
```

Attach video output to a native child-window handle before playback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `windowHandle` | `dynamic` | — | Non-zero platform handle owned by the GUI. |


Source: `std/video.ml:418`

<a id="method-method-std-video-player-backend-function-backend-std-video-ml-1693740782"></a>
### backend

```ml
function backend()
```

Return the backend selected for this target.


Source: `std/video.ml:411`

<a id="method-method-std-video-player-close-function-close-std-video-ml-1703187686"></a>
### close

```ml
function close()
```

Release playback threads, decoder state and native handles. Multiple close calls are harmless.


Source: `std/video.ml:560`

<a id="method-method-std-video-player-duration-function-duration-std-video-ml-2040872134"></a>
### duration

```ml
function duration()
```

Return duration in milliseconds, or -1 while unknown.


Source: `std/video.ml:464`

<a id="method-method-std-video-player-hasaudio-function-hasaudio-std-video-ml-1292757598"></a>
### hasAudio

```ml
function hasAudio()
```

Report whether the loaded source has an audio stream.


Source: `std/video.ml:524`

<a id="method-method-std-video-player-hasvideo-function-hasvideo-std-video-ml-583470366"></a>
### hasVideo

```ml
function hasVideo()
```

Report whether the loaded source has a video stream.


Source: `std/video.ml:530`

<a id="static_method-static-method-std-video-player-open-static-function-open-source-options-void-std-video-ml-1315792215"></a>
### open

```ml
static function open(source, options = void)
```

Open a local path or URI without beginning playback. Attach a native child-window handle before play() when video is visible.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `source` | `dynamic` | — | Local filename, file URI, or explicitly enabled network URI. |
| `options` | `dynamic` | <code>void</code> | PlayerOptions, or void for defaults. |


Source: `std/video.ml:378`

<a id="field-field-std-video-player-options-options-std-video-ml-1898541966"></a>
### options

```ml
options
```

Options retained for introspection.


Source: `std/video.ml:366`

<a id="method-method-std-video-player-pause-function-pause-std-video-ml-893559170"></a>
### pause

```ml
function pause()
```

Pause playback while retaining the current position.


Source: `std/video.ml:433`

<a id="method-method-std-video-player-play-function-play-std-video-ml-899937614"></a>
### play

```ml
function play()
```

Start or resume playback.


Source: `std/video.ml:426`

<a id="method-method-std-video-player-pollevent-function-pollevent-std-video-ml-100661544"></a>
### pollEvent

```ml
function pollEvent()
```

Return the next queued event, or void when no event is available.


Source: `std/video.ml:548`

<a id="method-method-std-video-player-position-function-position-std-video-ml-1200193178"></a>
### position

```ml
function position()
```

Return the current playback position in milliseconds.


Source: `std/video.ml:458`

<a id="method-method-std-video-player-seek-function-seek-milliseconds-std-video-ml-2146787904"></a>
### seek

```ml
function seek(milliseconds)
```

Seek to a non-negative millisecond position.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Target position from the beginning of the stream. |


Source: `std/video.ml:448`

<a id="method-method-std-video-player-setloop-function-setloop-enabled-std-video-ml-184318821"></a>
### setLoop

```ml
function setLoop(enabled)
```

Enable or disable automatic restart after end of stream.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `dynamic` | — | Whether end-of-stream restarts playback. |


Source: `std/video.ml:513`

<a id="method-method-std-video-player-setmuted-function-setmuted-muted-std-video-ml-588095491"></a>
### setMuted

```ml
function setMuted(muted)
```

Mute or unmute audio.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `muted` | `dynamic` | — | Whether audio output is muted. |


Source: `std/video.ml:489`

<a id="method-method-std-video-player-setplaybackrate-function-setplaybackrate-rate-std-video-ml-2075537326"></a>
### setPlaybackRate

```ml
function setPlaybackRate(rate)
```

Set playback speed from 0.25 through 4.0.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `rate` | `dynamic` | — | Requested playback-rate multiplier. |


Source: `std/video.ml:501`

<a id="method-method-std-video-player-setvolume-function-setvolume-volume-std-video-ml-531169772"></a>
### setVolume

```ml
function setVolume(volume)
```

Set linear volume from 0.0 through 1.0.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `volume` | `dynamic` | — | Linear volume in the inclusive range 0.0 through 1.0. |


Source: `std/video.ml:477`

<a id="method-method-std-video-player-state-function-state-std-video-ml-1095459556"></a>
### state

```ml
function state()
```

Return the current lifecycle state.


Source: `std/video.ml:470`

<a id="method-method-std-video-player-stop-function-stop-std-video-ml-2144431098"></a>
### stop

```ml
function stop()
```

Stop playback and seek to the beginning.


Source: `std/video.ml:440`

<a id="method-method-std-video-player-videoheight-function-videoheight-std-video-ml-1033994046"></a>
### videoHeight

```ml
function videoHeight()
```

Return the decoded video height, or zero before metadata is available.


Source: `std/video.ml:542`

<a id="method-method-std-video-player-videowidth-function-videowidth-std-video-ml-2002722782"></a>
### videoWidth

```ml
function videoWidth()
```

Return the decoded video width, or zero before metadata is available.


Source: `std/video.ml:536`
