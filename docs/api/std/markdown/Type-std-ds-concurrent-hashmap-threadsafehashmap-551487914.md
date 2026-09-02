# `std.ds.concurrent_hashmap.ThreadSafeHashMap`

[Home](README.md) · [Source file](File-std-ds-concurrent-hashmap-ml-1798836270.md)

<a id="struct-struct-std-ds-concurrent-hashmap-threadsafehashmap-struct-threadsafehashmap-std-ds-concurrent-hashmap-ml-1151729612"></a>
## ThreadSafeHashMap

```ml
struct ThreadSafeHashMap
```

Lock-protected open-addressing map for shared managed values.


Source: `std/ds/concurrent_hashmap.ml:91`

## Members

<a id="field-field-std-ds-concurrent-hashmap-threadsafehashmap-bucketcount-bucketcount-std-ds-concurrent-hashmap-ml-149082357"></a>
### bucketCount

```ml
bucketCount
```

Bucket count associated with `ThreadSafeHashMap`.


Source: `std/ds/concurrent_hashmap.ml:95`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-clear-function-clear-std-ds-concurrent-hashmap-ml-1301294917"></a>
### clear

```ml
function clear()
```

Replace all bucket arrays while retaining the current capacity.


Source: `std/ds/concurrent_hashmap.ml:308`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-close-function-close-std-ds-concurrent-hashmap-ml-869858615"></a>
### close

```ml
function close()
```

Drop all managed references and release the native lock.


Source: `std/ds/concurrent_hashmap.ml:386`

<a id="field-field-std-ds-concurrent-hashmap-threadsafehashmap-closed-closed-std-ds-concurrent-hashmap-ml-1144171657"></a>
### closed

```ml
closed
```

Closed associated with `ThreadSafeHashMap`.


Source: `std/ds/concurrent_hashmap.ml:105`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-count-function-count-std-ds-concurrent-hashmap-ml-2095071105"></a>
### count

```ml
function count()
```

Return a synchronized snapshot of the live entry count.


Source: `std/ds/concurrent_hashmap.ml:147`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-delete-function-delete-key-std-ds-concurrent-hashmap-ml-886823762"></a>
### delete

```ml
function delete(key)
```

Alias for remove().

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/concurrent_hashmap.ml:303`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-entriesarray-function-entriesarray-std-ds-concurrent-hashmap-ml-1527597983"></a>
### entriesArray

```ml
function entriesArray()
```

Copy live pairs into detached Entry snapshots.


Source: `std/ds/concurrent_hashmap.ml:365`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-get-function-get-key-std-ds-concurrent-hashmap-ml-113965598"></a>
### get

```ml
function get(key)
```

Return a key's value, or void when absent or unavailable.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/concurrent_hashmap.ml:211`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-getor-function-getor-key-fallback-std-ds-concurrent-hashmap-ml-1939592210"></a>
### getOr

```ml
function getOr(key, fallback)
```

Return a key's value or the caller-supplied fallback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |
| `fallback` | `dynamic` | — | Value supplied for `fallback`. |


Source: `std/ds/concurrent_hashmap.ml:230`

<a id="field-field-std-ds-concurrent-hashmap-threadsafehashmap-guard-guard-std-ds-concurrent-hashmap-ml-1695504469"></a>
### guard

```ml
guard
```

Guard associated with `ThreadSafeHashMap`.


Source: `std/ds/concurrent_hashmap.ml:93`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-has-function-has-key-std-ds-concurrent-hashmap-ml-169138350"></a>
### has

```ml
function has(key)
```

Test whether a supported key is present.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/concurrent_hashmap.ml:199`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-increment-function-increment-key-delta-std-ds-concurrent-hashmap-ml-1786891598"></a>
### increment

```ml
function increment(key, delta)
```

Atomically add delta to an integer value, inserting delta when absent.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |
| `delta` | `dynamic` | — | Value supplied for `delta`. |


Source: `std/ds/concurrent_hashmap.ml:249`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-isclosed-function-isclosed-std-ds-concurrent-hashmap-ml-1082109163"></a>
### isClosed

```ml
function isClosed()
```

Report whether storage and its native lock have been released.


Source: `std/ds/concurrent_hashmap.ml:166`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-isempty-function-isempty-std-ds-concurrent-hashmap-ml-1917850989"></a>
### isEmpty

```ml
function isEmpty()
```

Report whether the map contains no live entries.


Source: `std/ds/concurrent_hashmap.ml:161`

<a id="field-field-std-ds-concurrent-hashmap-threadsafehashmap-keys-keys-std-ds-concurrent-hashmap-ml-1696116269"></a>
### keys

```ml
keys
```

Keys associated with `ThreadSafeHashMap`.


Source: `std/ds/concurrent_hashmap.ml:99`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-keysarray-function-keysarray-std-ds-concurrent-hashmap-ml-664401893"></a>
### keysArray

```ml
function keysArray()
```

Copy a consistent snapshot of all live keys.


Source: `std/ds/concurrent_hashmap.ml:323`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-len-function-len-std-ds-concurrent-hashmap-ml-1950357417"></a>
### len

```ml
function len()
```

Alias for count().


Source: `std/ds/concurrent_hashmap.ml:156`

<a id="static_method-static-method-std-ds-concurrent-hashmap-threadsafehashmap-new-static-function-new-std-ds-concurrent-hashmap-ml-2047700696"></a>
### new

```ml
static function new()
```

Create a map with the default bucket count.


Source: `std/ds/concurrent_hashmap.ml:108`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-remove-function-remove-key-std-ds-concurrent-hashmap-ml-1236541502"></a>
### remove

```ml
function remove(key)
```

Remove a live key and leave a tombstone for the probe chain.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/concurrent_hashmap.ml:282`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-set-function-set-key-value-std-ds-concurrent-hashmap-ml-2134634419"></a>
### set

```ml
function set(key, value)
```

Insert or replace one key/value pair atomically.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/ds/concurrent_hashmap.ml:173`

<a id="field-field-std-ds-concurrent-hashmap-threadsafehashmap-size-size-std-ds-concurrent-hashmap-ml-1543510903"></a>
### size

```ml
size
```

Current logical size of `ThreadSafeHashMap`.


Source: `std/ds/concurrent_hashmap.ml:97`

<a id="field-field-std-ds-concurrent-hashmap-threadsafehashmap-states-states-std-ds-concurrent-hashmap-ml-1044331081"></a>
### states

```ml
states
```

States associated with `ThreadSafeHashMap`.


Source: `std/ds/concurrent_hashmap.ml:103`

<a id="field-field-std-ds-concurrent-hashmap-threadsafehashmap-values-values-std-ds-concurrent-hashmap-ml-59180809"></a>
### values

```ml
values
```

Values associated with `ThreadSafeHashMap`.


Source: `std/ds/concurrent_hashmap.ml:101`

<a id="method-method-std-ds-concurrent-hashmap-threadsafehashmap-valuesarray-function-valuesarray-std-ds-concurrent-hashmap-ml-1895275761"></a>
### valuesArray

```ml
function valuesArray()
```

Copy a consistent snapshot of all live values.


Source: `std/ds/concurrent_hashmap.ml:344`

<a id="static_method-static-method-std-ds-concurrent-hashmap-threadsafehashmap-withcapacity-static-function-withcapacity-minimumbuckets-std-ds-concurrent-hashmap-ml-1092752747"></a>
### withCapacity

```ml
static function withCapacity(minimumBuckets)
```

Create a map with at least the requested power-of-two capacity.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `minimumBuckets` | `dynamic` | — | Value supplied for `minimumBuckets`. |


Source: `std/ds/concurrent_hashmap.ml:114`
