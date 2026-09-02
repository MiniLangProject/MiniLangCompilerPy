# `std.ds.hashmap.HashMap`

[Home](README.md) · [Source file](File-std-ds-hashmap-ml-1269372918.md)

<a id="struct-struct-std-ds-hashmap-hashmap-struct-hashmap-std-ds-hashmap-ml-577405800"></a>
## HashMap

```ml
struct HashMap
```

Open-addressing map with deterministic hashing for supported key types.


Source: `std/ds/hashmap.ml:148`

## Members

<a id="field-field-std-ds-hashmap-hashmap-cap-cap-std-ds-hashmap-ml-1648380604"></a>
### cap

```ml
cap
```

Allocated capacity of `HashMap`.


Source: `std/ds/hashmap.ml:150`

<a id="method-method-std-ds-hashmap-hashmap-clear-function-clear-std-ds-hashmap-ml-1700032960"></a>
### clear

```ml
function clear()
```

Removes all entries (keeps capacity).


Source: `std/ds/hashmap.ml:186`

<a id="method-method-std-ds-hashmap-hashmap-count-function-count-std-ds-hashmap-ml-806853896"></a>
### count

```ml
function count()
```

Returns number of entries.


Source: `std/ds/hashmap.ml:176`

<a id="method-method-std-ds-hashmap-hashmap-delete-function-delete-key-std-ds-hashmap-ml-1951284107"></a>
### delete

```ml
function delete(key)
```

Alias for remove(key) to match common naming in the stdlib/tests.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/hashmap.ml:310`

<a id="method-method-std-ds-hashmap-hashmap-entriesarray-function-entriesarray-std-ds-hashmap-ml-1475560178"></a>
### entriesArray

```ml
function entriesArray()
```

Returns all entries (order unspecified).


Source: `std/ds/hashmap.ml:341`

<a id="method-method-std-ds-hashmap-hashmap-get-function-get-key-std-ds-hashmap-ml-1962985435"></a>
### get

```ml
function get(key)
```

Gets value by key.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/hashmap.ml:266`

<a id="method-method-std-ds-hashmap-hashmap-getor-function-getor-key-fallback-std-ds-hashmap-ml-923925195"></a>
### getOr

```ml
function getOr(key, fallback)
```

Gets value by key or returns fallback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |
| `fallback` | `dynamic` | — | Value supplied for `fallback`. |


Source: `std/ds/hashmap.ml:281`

<a id="method-method-std-ds-hashmap-hashmap-has-function-has-key-std-ds-hashmap-ml-1870741851"></a>
### has

```ml
function has(key)
```

Checks if a key exists.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/hashmap.ml:255`

<a id="method-method-std-ds-hashmap-hashmap-isempty-function-isempty-std-ds-hashmap-ml-364699036"></a>
### isEmpty

```ml
function isEmpty()
```

Checks whether map is empty.


Source: `std/ds/hashmap.ml:181`

<a id="field-field-std-ds-hashmap-hashmap-keys-keys-std-ds-hashmap-ml-1682839336"></a>
### keys

```ml
keys
```

Keys associated with `HashMap`.


Source: `std/ds/hashmap.ml:154`

<a id="method-method-std-ds-hashmap-hashmap-keysarray-function-keysarray-std-ds-hashmap-ml-1663031904"></a>
### keysArray

```ml
function keysArray()
```

Returns all keys (order unspecified).


Source: `std/ds/hashmap.ml:315`

<a id="static_method-static-method-std-ds-hashmap-hashmap-new-static-function-new-std-ds-hashmap-ml-111281271"></a>
### new

```ml
static function new()
```

Creates a new empty hash map.


Source: `std/ds/hashmap.ml:161`

<a id="method-method-std-ds-hashmap-hashmap-remove-function-remove-key-std-ds-hashmap-ml-1942441951"></a>
### remove

```ml
function remove(key)
```

Removes a key from the map.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/hashmap.ml:291`

<a id="method-method-std-ds-hashmap-hashmap-set-function-set-key-value-std-ds-hashmap-ml-1174901958"></a>
### set

```ml
function set(key, value)
```

Inserts or updates a key/value pair.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/ds/hashmap.ml:229`

<a id="field-field-std-ds-hashmap-hashmap-size-size-std-ds-hashmap-ml-858599162"></a>
### size

```ml
size
```

Current logical size of `HashMap`.


Source: `std/ds/hashmap.ml:152`

<a id="field-field-std-ds-hashmap-hashmap-states-states-std-ds-hashmap-ml-1342157484"></a>
### states

```ml
states
```

States associated with `HashMap`.


Source: `std/ds/hashmap.ml:158`

<a id="field-field-std-ds-hashmap-hashmap-values-values-std-ds-hashmap-ml-1537395444"></a>
### values

```ml
values
```

Values associated with `HashMap`.


Source: `std/ds/hashmap.ml:156`

<a id="method-method-std-ds-hashmap-hashmap-valuesarray-function-valuesarray-std-ds-hashmap-ml-1708150460"></a>
### valuesArray

```ml
function valuesArray()
```

Returns all values (order unspecified).


Source: `std/ds/hashmap.ml:328`

<a id="static_method-static-method-std-ds-hashmap-hashmap-withcapacity-static-function-withcapacity-mincap-std-ds-hashmap-ml-1784250823"></a>
### withCapacity

```ml
static function withCapacity(minCap)
```

Creates a hash map with at least `minCap` capacity.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `minCap` | `dynamic` | — | Value supplied for `minCap`. |


Source: `std/ds/hashmap.ml:167`
