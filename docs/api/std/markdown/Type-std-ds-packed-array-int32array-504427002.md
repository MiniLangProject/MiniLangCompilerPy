# `std.ds.packed_array.Int32Array`

[Home](README.md) · [Source file](File-std-ds-packed-array-ml-1828875008.md)

<a id="class-class-std-ds-packed-array-int32array-class-int32array-std-ds-packed-array-ml-586860522"></a>
## Int32Array

```ml
class Int32Array
```

A fixed-size sequence of signed 32-bit integers with four bytes per cell. Use external synchronization when several threads write to a shared instance.


Source: `std/ds/packed_array.ml:8`

## Members

<a id="field-field-std-ds-packed-array-int32array-data-private-data-as-bytes-bytes-0-std-ds-packed-array-ml-1551396478"></a>
### data

```ml
private data as bytes = bytes(0)
```


Source: `std/ds/packed_array.ml:9`

<a id="method-method-std-ds-packed-array-int32array-get-inline-function-get-index-as-int-returns-int-std-ds-packed-array-ml-921663975"></a>
### get

```ml
inline function get(index as int) returns int
```

Read a signed integer from a checked index.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `index` | `int` | — | Zero-based index, or an index relative to the end when negative. |


**Returns:** The signed integer stored at the checked index.

Source: `std/ds/packed_array.ml:30`

<a id="method-method-std-ds-packed-array-int32array-init-function-init-size-as-int-std-ds-packed-array-ml-1912951731"></a>
### init

```ml
function init(size as int)
```

Allocate a zero-filled sequence.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `size` | `int` | — | Number of elements in the sequence. |


Source: `std/ds/packed_array.ml:13`

<a id="method-method-std-ds-packed-array-int32array-len-function-len-returns-int-std-ds-packed-array-ml-1594219535"></a>
### len

```ml
function len() returns int
```

Return the number of elements.


**Returns:** Number of cells in the sequence.

Source: `std/ds/packed_array.ml:23`

<a id="method-method-std-ds-packed-array-int32array-set-inline-function-set-index-as-int-value-as-int-std-ds-packed-array-ml-1023025283"></a>
### set

```ml
inline function set(index as int, value as int)
```

Replace a cell with a signed 32-bit integer.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `index` | `int` | — | Zero-based index, or an index relative to the end when negative. |
| `value` | `int` | — | Value in the signed 32-bit range. |


Source: `std/ds/packed_array.ml:37`
