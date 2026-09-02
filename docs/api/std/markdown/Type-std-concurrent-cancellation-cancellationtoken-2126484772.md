# `std.concurrent.cancellation.CancellationToken`

[Home](README.md) · [Source file](File-std-concurrent-cancellation-ml-1392694543.md)

<a id="struct-struct-std-concurrent-cancellation-cancellationtoken-struct-cancellationtoken-std-concurrent-cancellation-ml-2017752400"></a>
## CancellationToken

```ml
struct CancellationToken
```

Read-only cancellation view passed to cooperative operations. Cancellation never terminates an OS thread; code observes the shared request explicitly.


Source: `std/concurrent/cancellation.ml:16`

## Members

<a id="method-method-std-concurrent-cancellation-cancellationtoken-check-function-check-std-concurrent-cancellation-ml-459292792"></a>
### Check

```ml
function Check()
```

Provide check behavior for this standard-library module.


Source: `std/concurrent/cancellation.ml:55`

<a id="method-method-std-concurrent-cancellation-cancellationtoken-check-function-check-std-concurrent-cancellation-ml-163271096"></a>
### check

```ml
function check()
```

Return a regular error value when cancellation has been requested.


Source: `std/concurrent/cancellation.ml:40`

<a id="method-method-std-concurrent-cancellation-cancellationtoken-iscancellationrequested-function-iscancellationrequested-std-concurrent-cancellation-ml-427321518"></a>
### IsCancellationRequested

```ml
function IsCancellationRequested()
```

Exposes the token cancellation state through a PascalCase alias.


Source: `std/concurrent/cancellation.ml:48`

<a id="method-method-std-concurrent-cancellation-cancellationtoken-iscancellationrequested-function-iscancellationrequested-std-concurrent-cancellation-ml-1369244462"></a>
### isCancellationRequested

```ml
function isCancellationRequested()
```

Reports whether cancellation was requested for this token.


Source: `std/concurrent/cancellation.ml:21`

<a id="field-field-std-concurrent-cancellation-cancellationtoken-source-source-std-concurrent-cancellation-ml-1773031056"></a>
### source

```ml
source
```

Source associated with `CancellationToken`.


Source: `std/concurrent/cancellation.ml:18`

<a id="method-method-std-concurrent-cancellation-cancellationtoken-wait-function-wait-std-concurrent-cancellation-ml-1185604580"></a>
### Wait

```ml
function Wait()
```

Exposes the token wait operation through a PascalCase alias.


Source: `std/concurrent/cancellation.ml:50`

<a id="method-method-std-concurrent-cancellation-cancellationtoken-wait-function-wait-std-concurrent-cancellation-ml-173979236"></a>
### wait

```ml
function wait()
```

Blocks until cancellation is requested for this token.


Source: `std/concurrent/cancellation.ml:27`

<a id="method-method-std-concurrent-cancellation-cancellationtoken-waitfor-function-waitfor-milliseconds-std-concurrent-cancellation-ml-944284170"></a>
### WaitFor

```ml
function WaitFor(milliseconds)
```

Exposes the timed token wait through a PascalCase alias.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/cancellation.ml:53`

<a id="method-method-std-concurrent-cancellation-cancellationtoken-waitfor-function-waitfor-milliseconds-std-concurrent-cancellation-ml-192213066"></a>
### waitFor

```ml
function waitFor(milliseconds)
```

Waits up to a bounded duration for this token to be cancelled.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/cancellation.ml:34`
