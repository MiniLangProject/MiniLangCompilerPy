# `std.threading.Lock`

[Home](README.md) · [Source file](File-std-threading-ml-508437988.md)

<a id="struct-struct-std-threading-lock-struct-lock-std-threading-ml-1930547675"></a>
## Lock

```ml
struct Lock
```

Re-entrant native mutex. Every successful acquire must be released.


Source: `std/threading.ml:66`

## Members

<a id="method-method-std-threading-lock-acquire-function-acquire-std-threading-ml-730248196"></a>
### Acquire

```ml
function Acquire()
```

PascalCase aliases match the native Thread API.


Source: `std/threading.ml:124`

<a id="method-method-std-threading-lock-acquire-function-acquire-std-threading-ml-1409763972"></a>
### acquire

```ml
function acquire()
```

Block until the current thread owns the mutex.


Source: `std/threading.ml:82`

<a id="method-method-std-threading-lock-acquirefor-function-acquirefor-milliseconds-std-threading-ml-706820674"></a>
### AcquireFor

```ml
function AcquireFor(milliseconds)
```

Provide acquire for behavior for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/threading.ml:127`

<a id="method-method-std-threading-lock-acquirefor-function-acquirefor-milliseconds-std-threading-ml-1593851138"></a>
### acquireFor

```ml
function acquireFor(milliseconds)
```

Wait at most the requested number of milliseconds for ownership.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/threading.ml:89`

<a id="method-method-std-threading-lock-close-function-close-std-threading-ml-259621520"></a>
### close

```ml
function close()
```

Close the mutex handle after all users have stopped accessing it.


Source: `std/threading.ml:113`

<a id="field-field-std-threading-lock-closed-closed-std-threading-ml-457087762"></a>
### closed

```ml
closed
```

Closed associated with `Lock`.


Source: `std/threading.ml:70`

<a id="field-field-std-threading-lock-handle-handle-std-threading-ml-2071608898"></a>
### handle

```ml
handle
```

Handle associated with `Lock`.


Source: `std/threading.ml:68`

<a id="method-method-std-threading-lock-isclosed-function-isclosed-std-threading-ml-758314184"></a>
### IsClosed

```ml
function IsClosed()
```

Exposes the Windows lock closed state through a PascalCase alias.


Source: `std/threading.ml:133`

<a id="method-method-std-threading-lock-isclosed-function-isclosed-std-threading-ml-1648794824"></a>
### isClosed

```ml
function isClosed()
```

Reports whether this Windows lock handle has been closed.


Source: `std/threading.ml:108`

<a id="static_method-static-method-std-threading-lock-new-static-function-new-std-threading-ml-2018063371"></a>
### new

```ml
static function new()
```

Create an initially unowned native mutex.


Source: `std/threading.ml:73`

<a id="method-method-std-threading-lock-release-function-release-std-threading-ml-521757954"></a>
### Release

```ml
function Release()
```

Releases or resets release.


Source: `std/threading.ml:131`

<a id="method-method-std-threading-lock-release-function-release-std-threading-ml-1801433858"></a>
### release

```ml
function release()
```

Release one acquisition held by the current thread.


Source: `std/threading.ml:102`

<a id="method-method-std-threading-lock-tryacquire-function-tryacquire-std-threading-ml-103662424"></a>
### TryAcquire

```ml
function TryAcquire()
```

Provide try acquire behavior for this standard-library module.


Source: `std/threading.ml:129`

<a id="method-method-std-threading-lock-tryacquire-function-tryacquire-std-threading-ml-1996881112"></a>
### tryAcquire

```ml
function tryAcquire()
```

Attempt immediate acquisition without blocking.


Source: `std/threading.ml:97`
