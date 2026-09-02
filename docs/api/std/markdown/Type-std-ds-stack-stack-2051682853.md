# `std.ds.stack.Stack`

[Home](README.md) · [Source file](File-std-ds-stack-ml-117945432.md)

<a id="struct-struct-std-ds-stack-stack-struct-stack-std-ds-stack-ml-1934879004"></a>
## Stack

```ml
struct Stack
```

LIFO stack with geometric backing-array growth.


Source: `std/ds/stack.ml:119`

## Members

<a id="method-method-std-ds-stack-stack-clear-function-clear-std-ds-stack-ml-244409422"></a>
### clear

```ml
function clear()
```

Removes all elements.


Source: `std/ds/stack.ml:179`

<a id="field-field-std-ds-stack-stack-data-data-std-ds-stack-ml-1702932382"></a>
### data

```ml
data
```

Stores the data member of `Stack`.


Source: `std/ds/stack.ml:121`

<a id="static_method-static-method-std-ds-stack-stack-fromarray-static-function-fromarray-values-std-ds-stack-ml-1532778091"></a>
### fromArray

```ml
static function fromArray(values)
```

Creates a stack from an array (copies the array).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `values` | `dynamic` | — | Values to process. |


Source: `std/ds/stack.ml:130`

<a id="method-method-std-ds-stack-stack-isempty-function-isempty-std-ds-stack-ml-879125514"></a>
### isEmpty

```ml
function isEmpty()
```

Checks whether the stack is empty.


Source: `std/ds/stack.ml:173`

<a id="method-method-std-ds-stack-stack-len-function-len-std-ds-stack-ml-1431646790"></a>
### len

```ml
function len()
```

Gets the number of elements.


Source: `std/ds/stack.ml:167`

<a id="static_method-static-method-std-ds-stack-stack-new-static-function-new-std-ds-stack-ml-1244206485"></a>
### new

```ml
static function new()
```

Creates a new empty stack.


Source: `std/ds/stack.ml:124`

<a id="method-method-std-ds-stack-stack-peek-function-peek-std-ds-stack-ml-520126940"></a>
### peek

```ml
function peek()
```

Peeks the top element without removing it.


Source: `std/ds/stack.ml:236`

<a id="method-method-std-ds-stack-stack-peekor-function-peekor-fallbackvalue-std-ds-stack-ml-938237637"></a>
### peekOr

```ml
function peekOr(fallbackValue)
```

Peeks the top element or returns a fallback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `fallbackValue` | `dynamic` | — | Value supplied for `fallbackValue`. |


Source: `std/ds/stack.ml:248`

<a id="method-method-std-ds-stack-stack-pop-function-pop-std-ds-stack-ml-337641410"></a>
### pop

```ml
function pop()
```

Pops the top element and returns it.


Source: `std/ds/stack.ml:257`

<a id="method-method-std-ds-stack-stack-popor-function-popor-fallbackvalue-std-ds-stack-ml-1004619701"></a>
### popOr

```ml
function popOr(fallbackValue)
```

Pops the top element or returns a fallback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `fallbackValue` | `dynamic` | — | Value supplied for `fallbackValue`. |


Source: `std/ds/stack.ml:276`

<a id="method-method-std-ds-stack-stack-push-function-push-value-std-ds-stack-ml-1856663047"></a>
### push

```ml
function push(value)
```

Pushes a value onto the stack.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/ds/stack.ml:189`

<a id="method-method-std-ds-stack-stack-pushall-function-pushall-values-std-ds-stack-ml-2011042572"></a>
### pushAll

```ml
function pushAll(values)
```

Pushes all values from an array onto the stack (in order).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `values` | `dynamic` | — | Values to process. |


Source: `std/ds/stack.ml:207`

<a id="method-method-std-ds-stack-stack-toarray-function-toarray-std-ds-stack-ml-1503124416"></a>
### toArray

```ml
function toArray()
```

Returns a shallow copy of the backing array.


Source: `std/ds/stack.ml:285`
