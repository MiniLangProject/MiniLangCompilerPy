# `std.ds.concurrent_list.ThreadSafeList`

[Home](README.md) · [Source file](File-std-ds-concurrent-list-ml-291130726.md)

<a id="struct-struct-std-ds-concurrent-list-threadsafelist-struct-threadsafelist-std-ds-concurrent-list-ml-226851698"></a>
## ThreadSafeList

```ml
struct ThreadSafeList
```

Lock-protected growable list whose values remain shared-heap objects.


Source: `std/ds/concurrent_list.ml:33`

## Members

<a id="method-method-std-ds-concurrent-list-threadsafelist-add-function-add-value-std-ds-concurrent-list-ml-1193809212"></a>
### add

```ml
function add(value)
```

Append one managed value under the list lock.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/ds/concurrent_list.ml:129`

<a id="method-method-std-ds-concurrent-list-threadsafelist-addall-function-addall-values-std-ds-concurrent-list-ml-1924274557"></a>
### addAll

```ml
function addAll(values)
```

Append all values atomically with respect to other list operations.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `values` | `dynamic` | — | Values to process. |


Source: `std/ds/concurrent_list.ml:150`

<a id="field-field-std-ds-concurrent-list-threadsafelist-buf-buf-std-ds-concurrent-list-ml-183394141"></a>
### buf

```ml
buf
```

Buf associated with `ThreadSafeList`.


Source: `std/ds/concurrent_list.ml:37`

<a id="field-field-std-ds-concurrent-list-threadsafelist-capacity-capacity-std-ds-concurrent-list-ml-3024729"></a>
### capacity

```ml
capacity
```

Allocated capacity of `ThreadSafeList`.


Source: `std/ds/concurrent_list.ml:41`

<a id="method-method-std-ds-concurrent-list-threadsafelist-clear-function-clear-std-ds-concurrent-list-ml-2030947113"></a>
### clear

```ml
function clear()
```

Drop references to all values while retaining the backing capacity.


Source: `std/ds/concurrent_list.ml:281`

<a id="method-method-std-ds-concurrent-list-threadsafelist-close-function-close-std-ds-concurrent-list-ml-1917022135"></a>
### close

```ml
function close()
```

Clear storage and release the native lock after all users have stopped.


Source: `std/ds/concurrent_list.ml:315`

<a id="field-field-std-ds-concurrent-list-threadsafelist-closed-closed-std-ds-concurrent-list-ml-1048168757"></a>
### closed

```ml
closed
```

Closed associated with `ThreadSafeList`.


Source: `std/ds/concurrent_list.ml:43`

<a id="method-method-std-ds-concurrent-list-threadsafelist-count-function-count-std-ds-concurrent-list-ml-174601541"></a>
### count

```ml
function count()
```

Alias for len().


Source: `std/ds/concurrent_list.ml:102`

<a id="method-method-std-ds-concurrent-list-threadsafelist-first-function-first-std-ds-concurrent-list-ml-1203419835"></a>
### first

```ml
function first()
```

Return the first value, or void when empty.


Source: `std/ds/concurrent_list.ml:198`

<a id="static_method-static-method-std-ds-concurrent-list-threadsafelist-fromarray-static-function-fromarray-values-std-ds-concurrent-list-ml-1166086536"></a>
### fromArray

```ml
static function fromArray(values)
```

Copy an ordinary array into a new synchronized list.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `values` | `dynamic` | — | Values to process. |


Source: `std/ds/concurrent_list.ml:63`

<a id="method-method-std-ds-concurrent-list-threadsafelist-get-function-get-index-std-ds-concurrent-list-ml-1342810797"></a>
### get

```ml
function get(index)
```

Return the value at index, or void for invalid/closed access.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `index` | `dynamic` | — | Zero-based item index. |


Source: `std/ds/concurrent_list.ml:170`

<a id="field-field-std-ds-concurrent-list-threadsafelist-guard-guard-std-ds-concurrent-list-ml-1295046217"></a>
### guard

```ml
guard
```

Guard associated with `ThreadSafeList`.


Source: `std/ds/concurrent_list.ml:35`

<a id="method-method-std-ds-concurrent-list-threadsafelist-insert-function-insert-index-value-std-ds-concurrent-list-ml-1673287280"></a>
### insert

```ml
function insert(index, value)
```

Insert before index while preserving the order of following values.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `index` | `dynamic` | — | Zero-based item index. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/ds/concurrent_list.ml:217`

<a id="method-method-std-ds-concurrent-list-threadsafelist-isclosed-function-isclosed-std-ds-concurrent-list-ml-1449244539"></a>
### isClosed

```ml
function isClosed()
```

Report whether the collection has released its native lock.


Source: `std/ds/concurrent_list.ml:112`

<a id="method-method-std-ds-concurrent-list-threadsafelist-isempty-function-isempty-std-ds-concurrent-list-ml-964418993"></a>
### isEmpty

```ml
function isEmpty()
```

Report whether the synchronized item count is zero.


Source: `std/ds/concurrent_list.ml:107`

<a id="method-method-std-ds-concurrent-list-threadsafelist-last-function-last-std-ds-concurrent-list-ml-1508902143"></a>
### last

```ml
function last()
```

Return the last value, or void when empty.


Source: `std/ds/concurrent_list.ml:203`

<a id="method-method-std-ds-concurrent-list-threadsafelist-len-function-len-std-ds-concurrent-list-ml-2066822621"></a>
### len

```ml
function len()
```

Return a synchronized snapshot of the current item count.


Source: `std/ds/concurrent_list.ml:93`

<a id="static_method-static-method-std-ds-concurrent-list-threadsafelist-new-static-function-new-std-ds-concurrent-list-ml-1011596306"></a>
### new

```ml
static function new()
```

Create an empty list with the default initial capacity.


Source: `std/ds/concurrent_list.ml:46`

<a id="method-method-std-ds-concurrent-list-threadsafelist-pop-function-pop-std-ds-concurrent-list-ml-632107569"></a>
### pop

```ml
function pop()
```

Remove and return the last value, or void when empty.


Source: `std/ds/concurrent_list.ml:258`

<a id="method-method-std-ds-concurrent-list-threadsafelist-popor-function-popor-fallback-std-ds-concurrent-list-ml-960393249"></a>
### popOr

```ml
function popOr(fallback)
```

Pop the last value or return fallback when no value is available.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `fallback` | `dynamic` | — | Value supplied for `fallback`. |


Source: `std/ds/concurrent_list.ml:274`

<a id="method-method-std-ds-concurrent-list-threadsafelist-push-function-push-value-std-ds-concurrent-list-ml-57487206"></a>
### push

```ml
function push(value)
```

Stack-style alias for add().

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/ds/concurrent_list.ml:144`

<a id="method-method-std-ds-concurrent-list-threadsafelist-removeat-function-removeat-index-std-ds-concurrent-list-ml-149304045"></a>
### removeAt

```ml
function removeAt(index)
```

Remove and return one indexed value, shifting the tail left.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `index` | `dynamic` | — | Zero-based item index. |


Source: `std/ds/concurrent_list.ml:238`

<a id="method-method-std-ds-concurrent-list-threadsafelist-reserve-function-reserve-minimumcapacity-std-ds-concurrent-list-ml-1098250973"></a>
### reserve

```ml
function reserve(minimumCapacity)
```

Preallocate space without changing the logical length.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `minimumCapacity` | `dynamic` | — | Value supplied for `minimumCapacity`. |


Source: `std/ds/concurrent_list.ml:118`

<a id="method-method-std-ds-concurrent-list-threadsafelist-set-function-set-index-value-std-ds-concurrent-list-ml-564599672"></a>
### set

```ml
function set(index, value)
```

Replace an existing slot and report whether the write succeeded.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `index` | `dynamic` | — | Zero-based item index. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/ds/concurrent_list.ml:185`

<a id="field-field-std-ds-concurrent-list-threadsafelist-size-size-std-ds-concurrent-list-ml-915365791"></a>
### size

```ml
size
```

Current logical size of `ThreadSafeList`.


Source: `std/ds/concurrent_list.ml:39`

<a id="method-method-std-ds-concurrent-list-threadsafelist-toarray-function-toarray-std-ds-concurrent-list-ml-1032101379"></a>
### toArray

```ml
function toArray()
```

Copy a consistent snapshot into an ordinary managed array.


Source: `std/ds/concurrent_list.ml:298`

<a id="static_method-static-method-std-ds-concurrent-list-threadsafelist-withcapacity-static-function-withcapacity-minimumcapacity-std-ds-concurrent-list-ml-2053089166"></a>
### withCapacity

```ml
static function withCapacity(minimumCapacity)
```

Create an empty list preallocated for at least minimumCapacity items.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `minimumCapacity` | `dynamic` | — | Value supplied for `minimumCapacity`. |


Source: `std/ds/concurrent_list.ml:52`
