# `std/array.ml`

[Home](README.md) · [Files](Files.md)

Provides the std array package.

Package: [`std.array`](Package-std-array-1432837065.md)

Reachable from entry: **no**

## Imports

- `std/result.ml` as `result` → [std/result.ml](File-std-result-ml-986518417.md)
- `std/string.ml` as `s` → [std/string.ml](File-std-string-ml-1276545685.md)

## Declarations

<a id="function-function-std-array-all-function-all-a-pred-std-array-ml-1158565640"></a>
### all

```ml
function all(a, pred)
```

Returns true if all elements satisfy the predicate.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `pred` | `dynamic` | — | Predicate applied to each candidate value. |


Source: `std/array.ml:339`

<a id="function-function-std-array-any-function-any-a-pred-std-array-ml-130273110"></a>
### any

```ml
function any(a, pred)
```

Returns true if any element satisfies the predicate.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `pred` | `dynamic` | — | Predicate applied to each candidate value. |


Source: `std/array.ml:319`

<a id="function-function-std-array-append-function-append-a-value-std-array-ml-1844937612"></a>
### append

```ml
function append(a, value)
```

Appends a value to an array and returns a new array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/array.ml:416`

<a id="function-function-std-array-concat-function-concat-a-b-std-array-ml-2041570823"></a>
### concat

```ml
function concat(a, b)
```

Concatenates two arrays and returns a new array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/array.ml:435`

<a id="function-function-std-array-contains-function-contains-a-value-std-array-ml-1539166352"></a>
### contains

```ml
function contains(a, value)
```

Checks whether an array contains a value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/array.ml:230`

<a id="function-function-std-array-copy-function-copy-a-std-array-ml-1680176529"></a>
### copy

```ml
function copy(a)
```

Creates a shallow copy of an array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |


Source: `std/array.ml:112`

<a id="function-function-std-array-filter-function-filter-a-pred-std-array-ml-27472074"></a>
### filter

```ml
function filter(a, pred)
```

Filters elements by predicate and returns a new array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `pred` | `dynamic` | — | Predicate applied to each candidate value. |


Source: `std/array.ml:265`

<a id="function-function-std-array-first-function-first-a-std-array-ml-2054141141"></a>
### first

```ml
function first(a)
```

Returns the first element of an array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |


Source: `std/array.ml:390`

<a id="function-function-std-array-getoption-function-getoption-a-index-std-array-ml-1404034711"></a>
### getOption

```ml
function getOption(a, index)
```

Returns an Option containing the indexed value, including a stored void. An empty Option denotes an invalid target/index or an out-of-bounds index.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | Array to read. |
| `index` | `dynamic` | — | Integer index to read. |


Source: `std/array.ml:71`

<a id="function-function-std-array-getor-function-getor-a-index-fallback-std-array-ml-109661577"></a>
### getOr

```ml
function getOr(a, index, fallback)
```

Returns an element, or fallback when the index is invalid or out of bounds. Negative indices address elements relative to the end of the array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | Array to read. |
| `index` | `dynamic` | — | Integer index to read. |
| `fallback` | `dynamic` | — | Value returned when no element exists at index. |


Source: `std/array.ml:59`

<a id="function-function-std-array-getorerror-function-getorerror-a-index-std-array-ml-608041017"></a>
### getOrError

```ml
function getOrError(a, index)
```

Returns an element or a detailed catchable bounds/type error.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | Array to read. |
| `index` | `dynamic` | — | Integer index to read. |


Source: `std/array.ml:96`

<a id="function-function-std-array-indexof-function-indexof-a-value-start-std-array-ml-148871920"></a>
### indexOf

```ml
function indexOf(a, value, start)
```

Finds the first index of a value in an array starting at 'start'.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `value` | `dynamic` | — | Value to process. |
| `start` | `dynamic` | — | Value supplied for `start`. |


Source: `std/array.ml:179`

<a id="function-function-std-array-isarray-function-isarray-x-std-array-ml-605013932"></a>
### isArray

```ml
function isArray(x)
```

Checks whether a value is an array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/array.ml:32`

<a id="function-function-std-array-isempty-function-isempty-a-std-array-ml-946252559"></a>
### isEmpty

```ml
function isEmpty(a)
```

Returns true if an array is empty.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |


Source: `std/array.ml:381`

<a id="function-function-std-array-joinstrings-function-joinstrings-a-sep-std-array-ml-426039153"></a>
### joinStrings

```ml
function joinStrings(a, sep)
```

Joins an array of strings using a separator.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `sep` | `dynamic` | — | Value supplied for `sep`. |


Source: `std/array.ml:359`

<a id="function-function-std-array-last-function-last-a-std-array-ml-1230645617"></a>
### last

```ml
function last(a)
```

Returns the last element of an array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |


Source: `std/array.ml:402`

<a id="function-function-std-array-lastindexof-function-lastindexof-a-value-std-array-ml-787503178"></a>
### lastIndexOf

```ml
function lastIndexOf(a, value)
```

Finds the last index of a value in an array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/array.ml:207`

<a id="function-function-std-array-length-function-length-a-std-array-ml-1052681365"></a>
### length

```ml
function length(a)
```

Returns the number of elements in the array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |


Source: `std/array.ml:372`

<a id="function-function-std-array-map-function-map-a-fn-std-array-ml-1628791657"></a>
### map

```ml
function map(a, fn)
```

Applies a function to every element and returns a new array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `fn` | `dynamic` | — | Function invoked by the operation. |


Source: `std/array.ml:242`

<a id="function-function-std-array-reduce-function-reduce-arr-f-init-std-array-ml-1955820997"></a>
### reduce

```ml
function reduce(arr, f, init)
```

Reduces an array to a single value using an accumulator function.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `arr` | `dynamic` | — | Value supplied for `arr`. |
| `f` | `dynamic` | — | Function invoked by the operation. |
| `init` | `dynamic` | — | Value supplied for `init`. |


Source: `std/array.ml:301`

<a id="function-function-std-array-setifpresent-function-setifpresent-a-index-value-std-array-ml-566540004"></a>
### setIfPresent

```ml
function setIfPresent(a, index, value)
```

Writes an element only when the target and index are valid. Returns true after a write and false otherwise.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | Array to update. |
| `index` | `dynamic` | — | Integer index to update. |
| `value` | `dynamic` | — | Value to store; void is a valid array element. |


Source: `std/array.ml:84`

<a id="function-function-std-array-slice-function-slice-a-offset-length-std-array-ml-1271445914"></a>
### slice

```ml
function slice(a, offset, length)
```

Returns a slice of an array with strict bounds - supports negative offsets (like Python): offset < 0 means "from end".

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `offset` | `dynamic` | — | Zero-based starting offset. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/array.ml:133`
