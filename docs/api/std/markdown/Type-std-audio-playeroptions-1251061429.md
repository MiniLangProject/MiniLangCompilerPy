# `std.audio.PlayerOptions`

[Home](README.md) · [Source file](File-std-audio-ml-1379868758.md)

<a id="struct-struct-std-audio-playeroptions-struct-playeroptions-std-audio-ml-924590435"></a>
## PlayerOptions

```ml
struct PlayerOptions
```

Options applied when an audio player is opened.


Source: `std/audio.ml:57`

## Members

<a id="field-field-std-audio-playeroptions-allownetwork-allownetwork-std-audio-ml-769428434"></a>
### allowNetwork

```ml
allowNetwork
```

Permit non-file audio URIs.


Source: `std/audio.ml:59`

<a id="static_method-static-method-std-audio-playeroptions-defaults-static-function-defaults-std-audio-ml-294074605"></a>
### defaults

```ml
static function defaults()
```

Return conservative defaults: local input, no loop and full volume.


Source: `std/audio.ml:70`

<a id="field-field-std-audio-playeroptions-loopenabled-loopenabled-std-audio-ml-1950580844"></a>
### loopEnabled

```ml
loopEnabled
```

Restart automatically after end of stream.


Source: `std/audio.ml:61`

<a id="field-field-std-audio-playeroptions-muted-muted-std-audio-ml-330986456"></a>
### muted

```ml
muted
```

Start with audio muted.


Source: `std/audio.ml:65`

<a id="field-field-std-audio-playeroptions-playbackrate-playbackrate-std-audio-ml-725023934"></a>
### playbackRate

```ml
playbackRate
```

Initial playback-rate multiplier.


Source: `std/audio.ml:67`

<a id="field-field-std-audio-playeroptions-volume-volume-std-audio-ml-1176627696"></a>
### volume

```ml
volume
```

Linear volume in the inclusive range 0.0 through 1.0.


Source: `std/audio.ml:63`
