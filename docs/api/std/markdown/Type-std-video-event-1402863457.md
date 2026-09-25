# `std.video.Event`

[Home](README.md) · [Source file](File-std-video-ml-900169693.md)

<a id="struct-struct-std-video-event-struct-event-std-video-ml-63509799"></a>
## Event

```ml
struct Event
```

One asynchronous player notification.


Source: `std/video.ml:67`

## Members

<a id="field-field-std-video-event-code-code-std-video-ml-1693865033"></a>
### code

```ml
code
```

Backend-specific numeric diagnostic, or zero.


Source: `std/video.ml:73`

<a id="field-field-std-video-event-kind-kind-std-video-ml-130534463"></a>
### kind

```ml
kind
```

Event category.


Source: `std/video.ml:69`

<a id="field-field-std-video-event-message-message-std-video-ml-1753117663"></a>
### message

```ml
message
```

Human-readable detail, empty for ordinary state changes.


Source: `std/video.ml:75`

<a id="field-field-std-video-event-state-state-std-video-ml-1602272439"></a>
### state

```ml
state
```

Player state observed after the event.


Source: `std/video.ml:71`
