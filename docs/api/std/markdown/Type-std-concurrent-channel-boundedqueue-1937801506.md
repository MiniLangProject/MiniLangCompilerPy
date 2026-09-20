# `std.concurrent.channel.BoundedQueue`

[Home](README.md) · [Source file](File-std-concurrent-channel-ml-2137315633.md)

<a id="struct-struct-std-concurrent-channel-boundedqueue-struct-boundedqueue-std-concurrent-channel-ml-1627059426"></a>
## BoundedQueue

```ml
struct BoundedQueue
```

Private bounded FIFO. All state is protected by one native lock, so the capacity check and ring mutation form one atomic operation.


Source: `std/concurrent/channel.ml:27`

## Members

<a id="field-field-std-concurrent-channel-boundedqueue-buffer-buffer-std-concurrent-channel-ml-1427944736"></a>
### buffer

```ml
buffer
```

Buffer associated with `BoundedQueue`.


Source: `std/concurrent/channel.ml:37`

<a id="field-field-std-concurrent-channel-boundedqueue-capacity-capacity-std-concurrent-channel-ml-1644283556"></a>
### capacity

```ml
capacity
```

Allocated capacity of `BoundedQueue`.


Source: `std/concurrent/channel.ml:41`

<a id="field-field-std-concurrent-channel-boundedqueue-closed-closed-std-concurrent-channel-ml-329022928"></a>
### closed

```ml
closed
```

Closed associated with `BoundedQueue`.


Source: `std/concurrent/channel.ml:49`

<a id="field-field-std-concurrent-channel-boundedqueue-closedevent-closedevent-std-concurrent-channel-ml-2022018772"></a>
### closedEvent

```ml
closedEvent
```

Closed event associated with `BoundedQueue`.


Source: `std/concurrent/channel.ml:31`

<a id="method-method-std-concurrent-channel-boundedqueue-countvalue-function-countvalue-std-concurrent-channel-ml-503180078"></a>
### countValue

```ml
function countValue()
```

Provide count value behavior for this standard-library module.


Source: `std/concurrent/channel.ml:112`

<a id="method-method-std-concurrent-channel-boundedqueue-dispose-function-dispose-std-concurrent-channel-ml-1470048932"></a>
### dispose

```ml
function dispose()
```

Disposes the sealed and drained bounded queue.


Source: `std/concurrent/channel.ml:134`

<a id="field-field-std-concurrent-channel-boundedqueue-guard-guard-std-concurrent-channel-ml-1300472300"></a>
### guard

```ml
guard
```

Guard associated with `BoundedQueue`.


Source: `std/concurrent/channel.ml:29`

<a id="field-field-std-concurrent-channel-boundedqueue-head-head-std-concurrent-channel-ml-374385680"></a>
### head

```ml
head
```

Head associated with `BoundedQueue`.


Source: `std/concurrent/channel.ml:43`

<a id="method-method-std-concurrent-channel-boundedqueue-issealed-function-issealed-std-concurrent-channel-ml-1579367774"></a>
### isSealed

```ml
function isSealed()
```

Reports whether is sealed.


Source: `std/concurrent/channel.ml:120`

<a id="field-field-std-concurrent-channel-boundedqueue-items-items-std-concurrent-channel-ml-681011404"></a>
### items

```ml
items
```

Items associated with `BoundedQueue`.


Source: `std/concurrent/channel.ml:35`

<a id="static_method-static-method-std-concurrent-channel-boundedqueue-new-static-function-new-capacity-std-concurrent-channel-ml-1067955915"></a>
### new

```ml
static function new(capacity)
```

Creates the bounded queue backing a channel.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `capacity` | `dynamic` | — | Value supplied for `capacity`. |


Source: `std/concurrent/channel.ml:53`

<a id="method-method-std-concurrent-channel-boundedqueue-seal-function-seal-std-concurrent-channel-ml-1060330214"></a>
### seal

```ml
function seal()
```

Provide seal behavior for this standard-library module.


Source: `std/concurrent/channel.ml:125`

<a id="field-field-std-concurrent-channel-boundedqueue-size-size-std-concurrent-channel-ml-1958834322"></a>
### size

```ml
size
```

Current logical size of `BoundedQueue`.


Source: `std/concurrent/channel.ml:47`

<a id="field-field-std-concurrent-channel-boundedqueue-slots-slots-std-concurrent-channel-ml-360951548"></a>
### slots

```ml
slots
```

Slots associated with `BoundedQueue`.


Source: `std/concurrent/channel.ml:33`

<a id="field-field-std-concurrent-channel-boundedqueue-tail-tail-std-concurrent-channel-ml-353718224"></a>
### tail

```ml
tail
```

Tail associated with `BoundedQueue`.


Source: `std/concurrent/channel.ml:45`

<a id="method-method-std-concurrent-channel-boundedqueue-tryput-function-tryput-value-std-concurrent-channel-ml-1780235547"></a>
### tryPut

```ml
function tryPut(value)
```

Provide try put behavior for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/concurrent/channel.ml:71`

<a id="method-method-std-concurrent-channel-boundedqueue-trytake-function-trytake-std-concurrent-channel-ml-1966288618"></a>
### tryTake

```ml
function tryTake()
```

Provide try take behavior for this standard-library module.


Source: `std/concurrent/channel.ml:94`

<a id="field-field-std-concurrent-channel-boundedqueue-voidflags-voidflags-std-concurrent-channel-ml-681407924"></a>
### voidFlags

```ml
voidFlags
```

Void flags associated with `BoundedQueue`.


Source: `std/concurrent/channel.ml:39`
