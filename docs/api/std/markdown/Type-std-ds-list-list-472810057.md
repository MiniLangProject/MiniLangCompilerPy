# `std.ds.list.List`

[Home](README.md) · [Source file](File-std-ds-list-ml-2070188142.md)

<a id="struct-struct-std-ds-list-list-struct-list-std-ds-list-ml-1145208724"></a>
## List

```ml
struct List
```

Mutable growable sequence with indexed insertion and removal.


Source: `std/ds/list.ml:59`

## Members

<a id="method-method-std-ds-list-list-add-function-add-value-std-ds-list-ml-436826465"></a>
### add

```ml
function add(value)
```

Adds an element at the end of the list.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/ds/list.ml:141`

<a id="method-method-std-ds-list-list-addall-function-addall-values-std-ds-list-ml-274680188"></a>
### addAll

```ml
function addAll(values)
```

Appends all values from an array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `values` | `dynamic` | — | Values to process. |


Source: `std/ds/list.ml:157`

<a id="field-field-std-ds-list-list-buf-buf-std-ds-list-ml-396886348"></a>
### buf

```ml
buf
```

Stores the buf member of `List`.


Source: `std/ds/list.ml:61`

<a id="field-field-std-ds-list-list-cap-cap-std-ds-list-ml-1998558576"></a>
### cap

```ml
cap
```

Stores the cap member of `List`.


Source: `std/ds/list.ml:65`

<a id="method-method-std-ds-list-list-clear-function-clear-std-ds-list-ml-956239204"></a>
### clear

```ml
function clear()
```

Removes all elements while keeping capacity.


Source: `std/ds/list.ml:106`

<a id="method-method-std-ds-list-list-first-function-first-std-ds-list-ml-2140847354"></a>
### first

```ml
function first()
```

Returns the first element.


Source: `std/ds/list.ml:201`

<a id="static_method-static-method-std-ds-list-list-fromarray-static-function-fromarray-values-std-ds-list-ml-902518015"></a>
### fromArray

```ml
static function fromArray(values)
```

Creates a new list from an array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `values` | `dynamic` | — | Values to process. |


Source: `std/ds/list.ml:82`

<a id="method-method-std-ds-list-list-get-function-get-index-std-ds-list-ml-1268966370"></a>
### get

```ml
function get(index)
```

Returns the element at `index`

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `index` | `dynamic` | — | Zero-based item index. |


Source: `std/ds/list.ml:176`

<a id="method-method-std-ds-list-list-insert-function-insert-index-value-std-ds-list-ml-1400622307"></a>
### insert

```ml
function insert(index, value)
```

Inserts a value at `index`

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `index` | `dynamic` | — | Zero-based item index. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/ds/list.ml:241`

<a id="method-method-std-ds-list-list-isempty-function-isempty-std-ds-list-ml-958491744"></a>
### isEmpty

```ml
function isEmpty()
```

Checks whether the list is empty.


Source: `std/ds/list.ml:101`

<a id="method-method-std-ds-list-list-last-function-last-std-ds-list-ml-614101394"></a>
### last

```ml
function last()
```

Returns the last element.


Source: `std/ds/list.ml:209`

<a id="method-method-std-ds-list-list-len-function-len-std-ds-list-ml-1370223244"></a>
### len

```ml
function len()
```

Returns number of elements.


Source: `std/ds/list.ml:96`

<a id="static_method-static-method-std-ds-list-list-new-static-function-new-std-ds-list-ml-1698003813"></a>
### new

```ml
static function new()
```

Creates a new empty list.


Source: `std/ds/list.ml:68`

<a id="method-method-std-ds-list-list-pop-function-pop-std-ds-list-ml-183093544"></a>
### pop

```ml
function pop()
```

Removes and returns the last element.


Source: `std/ds/list.ml:217`

<a id="method-method-std-ds-list-list-popor-function-popor-fallbackvalue-std-ds-list-ml-1510696565"></a>
### popOr

```ml
function popOr(fallbackValue)
```

Removes and returns the last element or a fallback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `fallbackValue` | `dynamic` | — | Value supplied for `fallbackValue`. |


Source: `std/ds/list.ml:230`

<a id="method-method-std-ds-list-list-push-function-push-value-std-ds-list-ml-1846460339"></a>
### push

```ml
function push(value)
```

Alias for add(value).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/ds/list.ml:151`

<a id="method-method-std-ds-list-list-removeat-function-removeat-index-std-ds-list-ml-140564318"></a>
### removeAt

```ml
function removeAt(index)
```

Removes and returns the value at `index`

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `index` | `dynamic` | — | Zero-based item index. |


Source: `std/ds/list.ml:267`

<a id="method-method-std-ds-list-list-reserve-function-reserve-mincap-std-ds-list-ml-1425645590"></a>
### reserve

```ml
function reserve(minCap)
```

Ensures that the capacity is at least `minCap`

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `minCap` | `dynamic` | — | Value supplied for `minCap`. |


Source: `std/ds/list.ml:117`

<a id="method-method-std-ds-list-list-set-function-set-index-value-std-ds-list-ml-1817091431"></a>
### set

```ml
function set(index, value)
```

Replaces the element at `index`

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `index` | `dynamic` | — | Zero-based item index. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/ds/list.ml:189`

<a id="field-field-std-ds-list-list-size-size-std-ds-list-ml-188290370"></a>
### size

```ml
size
```

Stores the size member of `List`.


Source: `std/ds/list.ml:63`

<a id="method-method-std-ds-list-list-toarray-function-toarray-std-ds-list-ml-679354234"></a>
### toArray

```ml
function toArray()
```

Returns a snapshot array of all elements.


Source: `std/ds/list.ml:286`

<a id="static_method-static-method-std-ds-list-list-withcapacity-static-function-withcapacity-mincap-std-ds-list-ml-1912842597"></a>
### withCapacity

```ml
static function withCapacity(minCap)
```

Creates a new list with at least `minCap` capacity.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `minCap` | `dynamic` | — | Value supplied for `minCap`. |


Source: `std/ds/list.ml:74`
