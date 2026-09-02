# `std.concurrent.channel.BoundedQueue`

[Home](README.md) · [Source file](File-std-concurrent-channel-ml-2137315633.md)

<a id="struct-struct-std-concurrent-channel-boundedqueue-struct-boundedqueue-std-concurrent-channel-ml-1627059426"></a>
## BoundedQueue

```ml
struct BoundedQueue
```

Private bounded FIFO. All state is protected by one native lock, so the capacity check and ring mutation form one atomic operation.


Source: `std/concurrent/channel.ml:26`

## Members

<a id="field-field-std-concurrent-channel-boundedqueue-buffer-buffer-std-concurrent-channel-ml-1427944736"></a>
### buffer

```ml
buffer
```

Stores the buffer member of `BoundedQueue`.


Source: `std/concurrent/channel.ml:36`

<a id="field-field-std-concurrent-channel-boundedqueue-capacity-capacity-std-concurrent-channel-ml-1644283556"></a>
### capacity

```ml
capacity
```

Stores the capacity member of `BoundedQueue`.


Source: `std/concurrent/channel.ml:40`

<a id="field-field-std-concurrent-channel-boundedqueue-closed-closed-std-concurrent-channel-ml-329022928"></a>
### closed

```ml
closed
```

Stores the closed member of `BoundedQueue`.


Source: `std/concurrent/channel.ml:48`

<a id="field-field-std-concurrent-channel-boundedqueue-closedevent-closedevent-std-concurrent-channel-ml-2022018772"></a>
### closedEvent

```ml
closedEvent
```

Stores the closed event member of `BoundedQueue`.


Source: `std/concurrent/channel.ml:30`

<a id="method-method-std-concurrent-channel-boundedqueue-countvalue-function-countvalue-std-concurrent-channel-ml-503180078"></a>
### countValue

```ml
function countValue()
```

Implements count value.


Source: `std/concurrent/channel.ml:111`

<a id="method-method-std-concurrent-channel-boundedqueue-dispose-function-dispose-std-concurrent-channel-ml-1470048932"></a>
### dispose

```ml
function dispose()
```

Disposes the sealed and drained bounded queue.


Source: `std/concurrent/channel.ml:133`

<a id="field-field-std-concurrent-channel-boundedqueue-guard-guard-std-concurrent-channel-ml-1300472300"></a>
### guard

```ml
guard
```

Stores the guard member of `BoundedQueue`.


Source: `std/concurrent/channel.ml:28`

<a id="field-field-std-concurrent-channel-boundedqueue-head-head-std-concurrent-channel-ml-374385680"></a>
### head

```ml
head
```

Stores the head member of `BoundedQueue`.


Source: `std/concurrent/channel.ml:42`

<a id="method-method-std-concurrent-channel-boundedqueue-issealed-function-issealed-std-concurrent-channel-ml-1579367774"></a>
### isSealed

```ml
function isSealed()
```

Reports whether is sealed.


Source: `std/concurrent/channel.ml:119`

<a id="field-field-std-concurrent-channel-boundedqueue-items-items-std-concurrent-channel-ml-681011404"></a>
### items

```ml
items
```

Stores the items member of `BoundedQueue`.


Source: `std/concurrent/channel.ml:34`

<a id="static_method-static-method-std-concurrent-channel-boundedqueue-new-static-function-new-capacity-std-concurrent-channel-ml-1067955915"></a>
### new

```ml
static function new(capacity)
```

Creates the bounded queue backing a channel.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `capacity` | `dynamic` | — | Value supplied for `capacity`. |


Source: `std/concurrent/channel.ml:52`

<a id="method-method-std-concurrent-channel-boundedqueue-seal-function-seal-std-concurrent-channel-ml-1060330214"></a>
### seal

```ml
function seal()
```

Implements seal.


Source: `std/concurrent/channel.ml:124`

<a id="field-field-std-concurrent-channel-boundedqueue-size-size-std-concurrent-channel-ml-1958834322"></a>
### size

```ml
size
```

Stores the size member of `BoundedQueue`.


Source: `std/concurrent/channel.ml:46`

<a id="field-field-std-concurrent-channel-boundedqueue-slots-slots-std-concurrent-channel-ml-360951548"></a>
### slots

```ml
slots
```

Stores the slots member of `BoundedQueue`.


Source: `std/concurrent/channel.ml:32`

<a id="field-field-std-concurrent-channel-boundedqueue-tail-tail-std-concurrent-channel-ml-353718224"></a>
### tail

```ml
tail
```

Stores the tail member of `BoundedQueue`.


Source: `std/concurrent/channel.ml:44`

<a id="method-method-std-concurrent-channel-boundedqueue-tryput-function-tryput-value-std-concurrent-channel-ml-1780235547"></a>
### tryPut

```ml
function tryPut(value)
```

Implements try put.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/concurrent/channel.ml:70`

<a id="method-method-std-concurrent-channel-boundedqueue-trytake-function-trytake-std-concurrent-channel-ml-1966288618"></a>
### tryTake

```ml
function tryTake()
```

Implements try take.


Source: `std/concurrent/channel.ml:93`

<a id="field-field-std-concurrent-channel-boundedqueue-voidflags-voidflags-std-concurrent-channel-ml-681407924"></a>
### voidFlags

```ml
voidFlags
```

Stores the void flags member of `BoundedQueue`.


Source: `std/concurrent/channel.ml:38`
