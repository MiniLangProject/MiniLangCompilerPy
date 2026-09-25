# `std.video.PlayerOptions`

[Home](README.md) · [Source file](File-std-video-ml-900169693.md)

<a id="struct-struct-std-video-playeroptions-struct-playeroptions-std-video-ml-943772821"></a>
## PlayerOptions

```ml
struct PlayerOptions
```

Options applied when a player is opened.


Source: `std/video.ml:48`

## Members

<a id="field-field-std-video-playeroptions-allownetwork-allownetwork-std-video-ml-1795373070"></a>
### allowNetwork

```ml
allowNetwork
```

Permit non-file media URIs.


Source: `std/video.ml:50`

<a id="static_method-static-method-std-video-playeroptions-defaults-static-function-defaults-std-video-ml-1265987065"></a>
### defaults

```ml
static function defaults()
```

Return conservative defaults: local input, no loop, full volume.


Source: `std/video.ml:61`

<a id="field-field-std-video-playeroptions-loopenabled-loopenabled-std-video-ml-1313048056"></a>
### loopEnabled

```ml
loopEnabled
```

Restart automatically after end of stream.


Source: `std/video.ml:52`

<a id="field-field-std-video-playeroptions-muted-muted-std-video-ml-977345220"></a>
### muted

```ml
muted
```

Start with audio muted.


Source: `std/video.ml:56`

<a id="field-field-std-video-playeroptions-playbackrate-playbackrate-std-video-ml-1512701646"></a>
### playbackRate

```ml
playbackRate
```

Initial playback rate.


Source: `std/video.ml:58`

<a id="field-field-std-video-playeroptions-volume-volume-std-video-ml-1450984488"></a>
### volume

```ml
volume
```

Linear volume in the inclusive range 0.0 through 1.0.


Source: `std/video.ml:54`
