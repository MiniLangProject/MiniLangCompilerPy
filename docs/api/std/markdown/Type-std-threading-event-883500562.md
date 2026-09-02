# `std.threading.Event`

[Home](README.md) · [Source file](File-std-threading-ml-508437988.md)

<a id="struct-struct-std-threading-event-struct-event-std-threading-ml-2035158861"></a>
## Event

```ml
struct Event
```

Win32 manual- or auto-reset event for one-to-many notifications.


Source: `std/threading.ml:229`

## Members

<a id="method-method-std-threading-event-close-function-close-std-threading-ml-458936001"></a>
### close

```ml
function close()
```

Close the event after no thread can wait on it again.


Source: `std/threading.ml:289`

<a id="field-field-std-threading-event-closed-closed-std-threading-ml-1682840367"></a>
### closed

```ml
closed
```

Stores the closed member of `Event`.


Source: `std/threading.ml:235`

<a id="field-field-std-threading-event-handle-handle-std-threading-ml-349719439"></a>
### handle

```ml
handle
```

Stores the handle member of `Event`.


Source: `std/threading.ml:231`

<a id="method-method-std-threading-event-isclosed-function-isclosed-std-threading-ml-2083169725"></a>
### IsClosed

```ml
function IsClosed()
```

Exposes the Windows event closed state through a PascalCase alias.


Source: `std/threading.ml:311`

<a id="method-method-std-threading-event-isclosed-function-isclosed-std-threading-ml-424965693"></a>
### isClosed

```ml
function isClosed()
```

Reports whether this Windows event handle has been closed.


Source: `std/threading.ml:284`

<a id="field-field-std-threading-event-manualreset-manualreset-std-threading-ml-236428395"></a>
### manualReset

```ml
manualReset
```

Stores the manual reset member of `Event`.


Source: `std/threading.ml:233`

<a id="static_method-static-method-std-threading-event-new-static-function-new-manualreset-initialstate-std-threading-ml-955984394"></a>
### new

```ml
static function new(manualReset, initialState)
```

Create an event with explicit reset mode and initial signal state.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `manualReset` | `dynamic` | — | Value supplied for `manualReset`. |
| `initialState` | `dynamic` | — | Value supplied for `initialState`. |


Source: `std/threading.ml:240`

<a id="method-method-std-threading-event-reset-function-reset-std-threading-ml-851676123"></a>
### Reset

```ml
function Reset()
```

Releases or resets reset.


Source: `std/threading.ml:309`

<a id="method-method-std-threading-event-reset-function-reset-std-threading-ml-899439323"></a>
### reset

```ml
function reset()
```

Return a manual-reset event to the nonsignaled state.


Source: `std/threading.ml:278`

<a id="method-method-std-threading-event-set-function-set-std-threading-ml-1006217145"></a>
### Set

```ml
function Set()
```

Updates set.


Source: `std/threading.ml:307`

<a id="method-method-std-threading-event-set-function-set-std-threading-ml-175502265"></a>
### set

```ml
function set()
```

Signal the event and release the applicable waiters.


Source: `std/threading.ml:272`

<a id="method-method-std-threading-event-trywait-function-trywait-std-threading-ml-1736278617"></a>
### TryWait

```ml
function TryWait()
```

Implements try wait.


Source: `std/threading.ml:305`

<a id="method-method-std-threading-event-trywait-function-trywait-std-threading-ml-1669113241"></a>
### tryWait

```ml
function tryWait()
```

Test the signal state without blocking.


Source: `std/threading.ml:267`

<a id="method-method-std-threading-event-wait-function-wait-std-threading-ml-2053849165"></a>
### Wait

```ml
function Wait()
```

PascalCase aliases mirror the native Thread API.


Source: `std/threading.ml:300`

<a id="method-method-std-threading-event-wait-function-wait-std-threading-ml-2104680781"></a>
### wait

```ml
function wait()
```

Wait indefinitely until the event is signaled.


Source: `std/threading.ml:252`

<a id="method-method-std-threading-event-waitfor-function-waitfor-milliseconds-std-threading-ml-1651884527"></a>
### WaitFor

```ml
function WaitFor(milliseconds)
```

Exposes the Windows event timed wait through a PascalCase alias.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/threading.ml:303`

<a id="method-method-std-threading-event-waitfor-function-waitfor-milliseconds-std-threading-ml-1897816367"></a>
### waitFor

```ml
function waitFor(milliseconds)
```

Wait until signaled or until the timeout expires.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/threading.ml:259`
