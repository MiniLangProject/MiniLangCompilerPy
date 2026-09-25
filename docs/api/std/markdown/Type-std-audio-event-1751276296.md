# `std.audio.Event`

[Home](README.md) · [Source file](File-std-audio-ml-1379868758.md)

<a id="struct-struct-std-audio-event-struct-event-std-audio-ml-25341793"></a>
## Event

```ml
struct Event
```

One asynchronous audio-player notification.


Source: `std/audio.ml:76`

## Members

<a id="field-field-std-audio-event-code-code-std-audio-ml-2006442385"></a>
### code

```ml
code
```

Backend-specific numeric diagnostic, or zero.


Source: `std/audio.ml:82`

<a id="field-field-std-audio-event-kind-kind-std-audio-ml-138493303"></a>
### kind

```ml
kind
```

Event category.


Source: `std/audio.ml:78`

<a id="field-field-std-audio-event-message-message-std-audio-ml-1505772211"></a>
### message

```ml
message
```

Human-readable detail, empty for ordinary state changes.


Source: `std/audio.ml:84`

<a id="field-field-std-audio-event-state-state-std-audio-ml-1219631291"></a>
### state

```ml
state
```

Player state observed after the event.


Source: `std/audio.ml:80`
