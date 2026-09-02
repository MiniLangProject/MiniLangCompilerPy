# `std.threading.Semaphore`

[Home](README.md) · [Source file](File-std-threading-ml-508437988.md)

<a id="struct-struct-std-threading-semaphore-struct-semaphore-std-threading-ml-1959521521"></a>
## Semaphore

```ml
struct Semaphore
```

Counting semaphore with a fixed maximum permit count.


Source: `std/threading.ml:137`

## Members

<a id="method-method-std-threading-semaphore-acquire-function-acquire-std-threading-ml-704951551"></a>
### Acquire

```ml
function Acquire()
```

PascalCase aliases mirror the native Thread API.


Source: `std/threading.ml:213`

<a id="method-method-std-threading-semaphore-acquire-function-acquire-std-threading-ml-1510023359"></a>
### acquire

```ml
function acquire()
```

Block until one permit can be consumed.


Source: `std/threading.ml:163`

<a id="method-method-std-threading-semaphore-acquirefor-function-acquirefor-milliseconds-std-threading-ml-92650353"></a>
### AcquireFor

```ml
function AcquireFor(milliseconds)
```

Implements acquire for.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/threading.ml:216`

<a id="method-method-std-threading-semaphore-acquirefor-function-acquirefor-milliseconds-std-threading-ml-1568461297"></a>
### acquireFor

```ml
function acquireFor(milliseconds)
```

Consume one permit within the requested timeout.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/threading.ml:170`

<a id="method-method-std-threading-semaphore-close-function-close-std-threading-ml-2091815591"></a>
### close

```ml
function close()
```

Close the handle after no thread can wait on it again.


Source: `std/threading.ml:202`

<a id="field-field-std-threading-semaphore-closed-closed-std-threading-ml-781506857"></a>
### closed

```ml
closed
```

Stores the closed member of `Semaphore`.


Source: `std/threading.ml:143`

<a id="field-field-std-threading-semaphore-handle-handle-std-threading-ml-1657773001"></a>
### handle

```ml
handle
```

Stores the handle member of `Semaphore`.


Source: `std/threading.ml:139`

<a id="method-method-std-threading-semaphore-isclosed-function-isclosed-std-threading-ml-1130993587"></a>
### IsClosed

```ml
function IsClosed()
```

Exposes the Windows semaphore closed state through a PascalCase alias.


Source: `std/threading.ml:225`

<a id="method-method-std-threading-semaphore-isclosed-function-isclosed-std-threading-ml-331623347"></a>
### isClosed

```ml
function isClosed()
```

Reports whether this Windows semaphore handle has been closed.


Source: `std/threading.ml:197`

<a id="field-field-std-threading-semaphore-maximumcount-maximumcount-std-threading-ml-1417661039"></a>
### maximumCount

```ml
maximumCount
```

Stores the maximum count member of `Semaphore`.


Source: `std/threading.ml:141`

<a id="static_method-static-method-std-threading-semaphore-new-static-function-new-initialcount-maximumcount-std-threading-ml-1769797430"></a>
### new

```ml
static function new(initialCount, maximumCount)
```

Create a semaphore with validated initial and maximum permit counts.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `initialCount` | `dynamic` | — | Value supplied for `initialCount`. |
| `maximumCount` | `dynamic` | — | Value supplied for `maximumCount`. |


Source: `std/threading.ml:148`

<a id="method-method-std-threading-semaphore-release-function-release-std-threading-ml-291476961"></a>
### Release

```ml
function Release()
```

Releases or resets release.


Source: `std/threading.ml:220`

<a id="method-method-std-threading-semaphore-release-function-release-std-threading-ml-302421665"></a>
### release

```ml
function release()
```

Return one permit to the semaphore.


Source: `std/threading.ml:183`

<a id="method-method-std-threading-semaphore-releasemany-function-releasemany-count-std-threading-ml-1835952538"></a>
### ReleaseMany

```ml
function ReleaseMany(count)
```

Releases or resets release many.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `count` | `dynamic` | — | Number of items to process. |


Source: `std/threading.ml:223`

<a id="method-method-std-threading-semaphore-releasemany-function-releasemany-count-std-threading-ml-1703356314"></a>
### releaseMany

```ml
function releaseMany(count)
```

Return multiple permits in one native operation.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `count` | `dynamic` | — | Number of items to process. |


Source: `std/threading.ml:189`

<a id="method-method-std-threading-semaphore-tryacquire-function-tryacquire-std-threading-ml-599040883"></a>
### TryAcquire

```ml
function TryAcquire()
```

Implements try acquire.


Source: `std/threading.ml:218`

<a id="method-method-std-threading-semaphore-tryacquire-function-tryacquire-std-threading-ml-2104513587"></a>
### tryAcquire

```ml
function tryAcquire()
```

Attempt to consume one permit without blocking.


Source: `std/threading.ml:178`
