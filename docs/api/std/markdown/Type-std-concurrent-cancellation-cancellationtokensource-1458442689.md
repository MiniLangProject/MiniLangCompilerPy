# `std.concurrent.cancellation.CancellationTokenSource`

[Home](README.md) · [Source file](File-std-concurrent-cancellation-ml-1392694543.md)

<a id="struct-struct-std-concurrent-cancellation-cancellationtokensource-struct-cancellationtokensource-std-concurrent-cancellation-ml-208979298"></a>
## CancellationTokenSource

```ml
struct CancellationTokenSource
```

Owns the native event used to publish one idempotent cancellation request.


Source: `std/concurrent/cancellation.ml:59`

## Members

<a id="method-method-std-concurrent-cancellation-cancellationtokensource-cancel-function-cancel-std-concurrent-cancellation-ml-462585941"></a>
### Cancel

```ml
function Cancel()
```

Exposes source cancellation through a PascalCase alias.


Source: `std/concurrent/cancellation.ml:137`

<a id="method-method-std-concurrent-cancellation-cancellationtokensource-cancel-function-cancel-std-concurrent-cancellation-ml-1744828821"></a>
### cancel

```ml
function cancel()
```

Requests cancellation from this source.


Source: `std/concurrent/cancellation.ml:85`

<a id="field-field-std-concurrent-cancellation-cancellationtokensource-cancelled-cancelled-std-concurrent-cancellation-ml-1107796773"></a>
### cancelled

```ml
cancelled
```

Stores the cancelled member of `CancellationTokenSource`.


Source: `std/concurrent/cancellation.ml:65`

<a id="method-method-std-concurrent-cancellation-cancellationtokensource-close-function-close-std-concurrent-cancellation-ml-2069306449"></a>
### close

```ml
function close()
```

Dispose only after all operations using tokens from this source finished.


Source: `std/concurrent/cancellation.ml:121`

<a id="field-field-std-concurrent-cancellation-cancellationtokensource-closed-closed-std-concurrent-cancellation-ml-1594733725"></a>
### closed

```ml
closed
```

Stores the closed member of `CancellationTokenSource`.


Source: `std/concurrent/cancellation.ml:67`

<a id="method-method-std-concurrent-cancellation-cancellationtokensource-dispose-function-dispose-std-concurrent-cancellation-ml-1933081907"></a>
### Dispose

```ml
function Dispose()
```

Closes this cancellation source through its PascalCase alias.


Source: `std/concurrent/cancellation.ml:141`

<a id="field-field-std-concurrent-cancellation-cancellationtokensource-event-event-std-concurrent-cancellation-ml-1198528429"></a>
### event

```ml
event
```

Stores the event member of `CancellationTokenSource`.


Source: `std/concurrent/cancellation.ml:63`

<a id="field-field-std-concurrent-cancellation-cancellationtokensource-guard-guard-std-concurrent-cancellation-ml-427892449"></a>
### guard

```ml
guard
```

Stores the guard member of `CancellationTokenSource`.


Source: `std/concurrent/cancellation.ml:61`

<a id="method-method-std-concurrent-cancellation-cancellationtokensource-iscancellationrequested-function-iscancellationrequested-std-concurrent-cancellation-ml-1851143927"></a>
### IsCancellationRequested

```ml
function IsCancellationRequested()
```

Exposes the source cancellation state through a PascalCase alias.


Source: `std/concurrent/cancellation.ml:139`

<a id="method-method-std-concurrent-cancellation-cancellationtokensource-iscancellationrequested-function-iscancellationrequested-std-concurrent-cancellation-ml-1684155959"></a>
### isCancellationRequested

```ml
function isCancellationRequested()
```

Reports whether this source has requested cancellation.


Source: `std/concurrent/cancellation.ml:100`

<a id="static_method-static-method-std-concurrent-cancellation-cancellationtokensource-new-static-function-new-std-concurrent-cancellation-ml-177292884"></a>
### new

```ml
static function new()
```

Creates a cancellation token source.


Source: `std/concurrent/cancellation.ml:70`

<a id="method-method-std-concurrent-cancellation-cancellationtokensource-token-function-token-std-concurrent-cancellation-ml-1903566395"></a>
### Token

```ml
function Token()
```

Converts token.


Source: `std/concurrent/cancellation.ml:135`

<a id="method-method-std-concurrent-cancellation-cancellationtokensource-token-function-token-std-concurrent-cancellation-ml-198279739"></a>
### token

```ml
function token()
```

Converts token.


Source: `std/concurrent/cancellation.ml:80`

<a id="method-method-std-concurrent-cancellation-cancellationtokensource-wait-function-wait-std-concurrent-cancellation-ml-1133919633"></a>
### wait

```ml
function wait()
```

Blocks until this source requests cancellation.


Source: `std/concurrent/cancellation.ml:108`

<a id="method-method-std-concurrent-cancellation-cancellationtokensource-waitfor-function-waitfor-milliseconds-std-concurrent-cancellation-ml-427995255"></a>
### waitFor

```ml
function waitFor(milliseconds)
```

Waits up to a bounded duration for this source to request cancellation.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/cancellation.ml:115`
