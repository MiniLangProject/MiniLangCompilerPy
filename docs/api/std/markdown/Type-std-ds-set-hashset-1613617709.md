# `std.ds.set.HashSet`

[Home](README.md) · [Source file](File-std-ds-set-ml-1393232564.md)

<a id="struct-struct-std-ds-set-hashset-struct-hashset-std-ds-set-ml-1639590232"></a>
## HashSet

```ml
struct HashSet
```

Std.ds.set Simple set built on top of std.ds.hashmap.HashMap. Supported key types are the same as the underlying HashMap: - int - bytes - string.


Source: `std/ds/set.ml:24`

## Members

<a id="method-method-std-ds-set-hashset-add-function-add-key-std-ds-set-ml-1838512067"></a>
### add

```ml
function add(key)
```

Adds a key to the set.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/set.ml:50`

<a id="method-method-std-ds-set-hashset-clear-function-clear-std-ds-set-ml-1453333662"></a>
### clear

```ml
function clear()
```

Removes all elements.


Source: `std/ds/set.ml:44`

<a id="method-method-std-ds-set-hashset-delete-function-delete-key-std-ds-set-ml-1333440797"></a>
### delete

```ml
function delete(key)
```

Alias for remove(key) to match common naming in the stdlib/tests.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/set.ml:68`

<a id="method-method-std-ds-set-hashset-has-function-has-key-std-ds-set-ml-902445005"></a>
### has

```ml
function has(key)
```

Checks whether the set contains a key.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/set.ml:56`

<a id="method-method-std-ds-set-hashset-isempty-function-isempty-std-ds-set-ml-840145106"></a>
### isEmpty

```ml
function isEmpty()
```

Checks whether the set is empty.


Source: `std/ds/set.ml:39`

<a id="method-method-std-ds-set-hashset-keysarray-function-keysarray-std-ds-set-ml-1999664542"></a>
### keysArray

```ml
function keysArray()
```

Returns an array of all keys (order is unspecified).


Source: `std/ds/set.ml:73`

<a id="method-method-std-ds-set-hashset-len-function-len-std-ds-set-ml-1244644214"></a>
### len

```ml
function len()
```

Returns the number of elements.


Source: `std/ds/set.ml:34`

<a id="field-field-std-ds-set-hashset-map-map-std-ds-set-ml-1772067654"></a>
### map

```ml
map
```

Map associated with `HashSet`.


Source: `std/ds/set.ml:26`

<a id="static_method-static-method-std-ds-set-hashset-new-static-function-new-std-ds-set-ml-1006408109"></a>
### new

```ml
static function new()
```

Creates a new empty hash set.


Source: `std/ds/set.ml:29`

<a id="method-method-std-ds-set-hashset-remove-function-remove-key-std-ds-set-ml-1015320057"></a>
### remove

```ml
function remove(key)
```

Removes a key from the set.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |


Source: `std/ds/set.ml:62`
