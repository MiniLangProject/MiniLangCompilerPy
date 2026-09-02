# `std.ds.queue.Queue`

[Home](README.md) · [Source file](File-std-ds-queue-ml-1555253413.md)

<a id="struct-struct-std-ds-queue-queue-struct-queue-std-ds-queue-ml-500280002"></a>
## Queue

```ml
struct Queue
```

FIFO queue backed by a compacting growable array.


Source: `std/ds/queue.ml:58`

## Members

<a id="field-field-std-ds-queue-queue-buf-buf-std-ds-queue-ml-448813111"></a>
### buf

```ml
buf
```

Stores the buf member of `Queue`.


Source: `std/ds/queue.ml:60`

<a id="field-field-std-ds-queue-queue-cap-cap-std-ds-queue-ml-1429216467"></a>
### cap

```ml
cap
```

Stores the cap member of `Queue`.


Source: `std/ds/queue.ml:68`

<a id="method-method-std-ds-queue-queue-clear-function-clear-std-ds-queue-ml-519280311"></a>
### clear

```ml
function clear()
```

Removes all items (keeps capacity).


Source: `std/ds/queue.ml:94`

<a id="method-method-std-ds-queue-queue-dequeue-function-dequeue-std-ds-queue-ml-517233613"></a>
### dequeue

```ml
function dequeue()
```

Removes and returns the front element.


Source: `std/ds/queue.ml:140`

<a id="method-method-std-ds-queue-queue-enqueue-function-enqueue-v-std-ds-queue-ml-1746933747"></a>
### enqueue

```ml
function enqueue(v)
```

Adds an element to the back of the queue.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `v` | `dynamic` | — | Value supplied for `v`. |


Source: `std/ds/queue.ml:121`

<a id="field-field-std-ds-queue-queue-head-head-std-ds-queue-ml-1879688931"></a>
### head

```ml
head
```

Stores the head member of `Queue`.


Source: `std/ds/queue.ml:62`

<a id="method-method-std-ds-queue-queue-isempty-function-isempty-std-ds-queue-ml-350459979"></a>
### isEmpty

```ml
function isEmpty()
```

Checks whether the queue is empty.


Source: `std/ds/queue.ml:89`

<a id="method-method-std-ds-queue-queue-len-function-len-std-ds-queue-ml-62408447"></a>
### len

```ml
function len()
```

Returns the number of elements.


Source: `std/ds/queue.ml:84`

<a id="static_method-static-method-std-ds-queue-queue-new-static-function-new-std-ds-queue-ml-2141908760"></a>
### new

```ml
static function new()
```

Creates a new queue with default capacity.


Source: `std/ds/queue.ml:71`

<a id="method-method-std-ds-queue-queue-peek-function-peek-std-ds-queue-ml-1238278161"></a>
### peek

```ml
function peek()
```

Returns the front element without removing it.


Source: `std/ds/queue.ml:132`

<a id="field-field-std-ds-queue-queue-size-size-std-ds-queue-ml-2115094365"></a>
### size

```ml
size
```

Stores the size member of `Queue`.


Source: `std/ds/queue.ml:66`

<a id="field-field-std-ds-queue-queue-tail-tail-std-ds-queue-ml-189478275"></a>
### tail

```ml
tail
```

Stores the tail member of `Queue`.


Source: `std/ds/queue.ml:64`

<a id="method-method-std-ds-queue-queue-toarray-function-toarray-std-ds-queue-ml-260125405"></a>
### toArray

```ml
function toArray()
```

Returns a snapshot of the queue contents (front -> back).


Source: `std/ds/queue.ml:155`

<a id="static_method-static-method-std-ds-queue-queue-withcapacity-static-function-withcapacity-mincap-std-ds-queue-ml-438691928"></a>
### withCapacity

```ml
static function withCapacity(minCap)
```

Creates a new queue with at least `minCap` capacity.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `minCap` | `dynamic` | — | Value supplied for `minCap`. |


Source: `std/ds/queue.ml:77`
