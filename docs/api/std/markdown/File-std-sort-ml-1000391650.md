# `std/sort.ml`

[Home](README.md) · [Files](Files.md)

Provides the std sort package.

Package: [`std.sort`](Package-std-sort-698049104.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-sort-issorted-function-issorted-arr-lessfn-std-sort-ml-1072433950"></a>
### isSorted

```ml
function isSorted(arr, lessFn)
```

Checks whether an array is sorted according to the given comparator.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `arr` | `dynamic` | — | Value supplied for `arr`. |
| `lessFn` | `dynamic` | — | Value supplied for `lessFn`. |


Source: `std/sort.ml:168`

<a id="function-function-std-sort-sort-function-sort-arr-std-sort-ml-333187585"></a>
### sort

```ml
function sort(arr)
```

Stable in-place sort using the default comparator (ascending).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `arr` | `dynamic` | — | Value supplied for `arr`. |


Source: `std/sort.ml:39`

<a id="function-function-std-sort-sortby-function-sortby-arr-lessfn-std-sort-ml-529537194"></a>
### sortBy

```ml
function sortBy(arr, lessFn)
```

Stable in-place sort with a custom comparator (insertion sort).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `arr` | `dynamic` | — | Value supplied for `arr`. |
| `lessFn` | `dynamic` | — | Value supplied for `lessFn`. |


Source: `std/sort.ml:46`

<a id="function-function-std-sort-sortfast-function-sortfast-arr-std-sort-ml-1925522137"></a>
### sortFast

```ml
function sortFast(arr)
```

Faster in-place sort using the default comparator (ascending) - uses an iterative quicksort with insertion-sort fallback for small ranges - not guaranteed stable.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `arr` | `dynamic` | — | Value supplied for `arr`. |


Source: `std/sort.ml:81`

<a id="function-function-std-sort-sortfastby-function-sortfastby-arr-lessfn-std-sort-ml-1761662250"></a>
### sortFastBy

```ml
function sortFastBy(arr, lessFn)
```

Faster in-place sort with a custom comparator - uses an iterative quicksort with insertion-sort fallback for small ranges - not guaranteed stable.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `arr` | `dynamic` | — | Value supplied for `arr`. |
| `lessFn` | `dynamic` | — | Value supplied for `lessFn`. |


Source: `std/sort.ml:88`
