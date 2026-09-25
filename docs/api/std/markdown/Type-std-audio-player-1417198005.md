# `std.audio.Player`

[Home](README.md) · [Source file](File-std-audio-ml-1379868758.md)

<a id="struct-struct-std-audio-player-struct-player-std-audio-ml-1564612999"></a>
## Player

```ml
struct Player
```

A native audio player with deterministic explicit ownership.


Source: `std/audio.ml:178`

## Members

<a id="method-method-std-audio-player-backend-function-backend-std-audio-ml-1800188746"></a>
### backend

```ml
function backend()
```

Return the native backend selected for this target.


Source: `std/audio.ml:225`

<a id="method-method-std-audio-player-close-function-close-std-audio-ml-1700319502"></a>
### close

```ml
function close()
```

Release decoder state, playback threads and native handles. Multiple close calls are harmless.


Source: `std/audio.ml:353`

<a id="method-method-std-audio-player-duration-function-duration-std-audio-ml-452982834"></a>
### duration

```ml
function duration()
```

Return duration in milliseconds, or -1 while unknown.


Source: `std/audio.ml:279`

<a id="method-method-std-audio-player-format-function-format-std-audio-ml-554587574"></a>
### format

```ml
function format()
```

Return the format inferred from the source filename.


Source: `std/audio.ml:231`

<a id="method-method-std-audio-player-hasaudio-function-hasaudio-std-audio-ml-1580341818"></a>
### hasAudio

```ml
function hasAudio()
```

Report whether the backend detected an audio stream.


Source: `std/audio.ml:291`

<a id="static_method-static-method-std-audio-player-open-static-function-open-source-options-void-std-audio-ml-11174309"></a>
### open

```ml
static function open(source, options = void)
```

Open a local audio path or URI without beginning playback. WAV, MP3 and MIDI are the portable named formats.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `source` | `dynamic` | — | Local filename, file URI, or explicitly enabled network URI. |
| `options` | `dynamic` | `void` | PlayerOptions, or void for defaults. |


Source: `std/audio.ml:195`

<a id="field-field-std-audio-player-options-options-std-audio-ml-620952056"></a>
### options

```ml
options
```

Options retained for introspection.


Source: `std/audio.ml:183`

<a id="method-method-std-audio-player-pause-function-pause-std-audio-ml-217486234"></a>
### pause

```ml
function pause()
```

Pause playback while retaining the current position.


Source: `std/audio.ml:244`

<a id="method-method-std-audio-player-play-function-play-std-audio-ml-1904415466"></a>
### play

```ml
function play()
```

Start or resume playback.


Source: `std/audio.ml:236`

<a id="method-method-std-audio-player-pollevent-function-pollevent-std-audio-ml-1721749456"></a>
### pollEvent

```ml
function pollEvent()
```

Return the next queued event, or void when no event is available.


Source: `std/audio.ml:340`

<a id="method-method-std-audio-player-position-function-position-std-audio-ml-90934830"></a>
### position

```ml
function position()
```

Return the current playback position in milliseconds.


Source: `std/audio.ml:273`

<a id="method-method-std-audio-player-seek-function-seek-milliseconds-std-audio-ml-148056452"></a>
### seek

```ml
function seek(milliseconds)
```

Seek to a non-negative millisecond position. Backend support for MIDI seeking depends on the installed synthesizer.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Target position from the beginning of the stream. |


Source: `std/audio.ml:262`

<a id="method-method-std-audio-player-setloop-function-setloop-enabled-std-audio-ml-294019719"></a>
### setLoop

```ml
function setLoop(enabled)
```

Enable or disable automatic restart after end of stream.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `dynamic` | — | Whether end-of-stream restarts playback. |


Source: `std/audio.ml:331`

<a id="method-method-std-audio-player-setmuted-function-setmuted-muted-std-audio-ml-798585953"></a>
### setMuted

```ml
function setMuted(muted)
```

Mute or unmute audio.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `muted` | `dynamic` | — | Whether audio output is muted. |


Source: `std/audio.ml:310`

<a id="method-method-std-audio-player-setplaybackrate-function-setplaybackrate-rate-std-audio-ml-692689886"></a>
### setPlaybackRate

```ml
function setPlaybackRate(rate)
```

Set playback speed from 0.25 through 4.0. MIDI rate support depends on the installed backend synthesizer.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `rate` | `dynamic` | — | Requested playback-rate multiplier. |


Source: `std/audio.ml:321`

<a id="method-method-std-audio-player-setvolume-function-setvolume-volume-std-audio-ml-637762712"></a>
### setVolume

```ml
function setVolume(volume)
```

Set linear volume from 0.0 through 1.0. Windows MIDI sequencers may expose only mute rather than per-player volume; the runtime never changes the process-wide MIDI mapper volume.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `volume` | `dynamic` | — | Linear volume in the inclusive range 0.0 through 1.0. |


Source: `std/audio.ml:300`

<a id="method-method-std-audio-player-state-function-state-std-audio-ml-287810628"></a>
### state

```ml
function state()
```

Return the current lifecycle state.


Source: `std/audio.ml:285`

<a id="method-method-std-audio-player-stop-function-stop-std-audio-ml-1105092494"></a>
### stop

```ml
function stop()
```

Stop playback and seek to the beginning.


Source: `std/audio.ml:252`
