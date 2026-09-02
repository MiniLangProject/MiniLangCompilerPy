# `std.string_builder.StringBuilder`

[Home](README.md) · [Source file](File-std-string-builder-ml-412876577.md)

<a id="struct-struct-std-string-builder-stringbuilder-struct-stringbuilder-std-string-builder-ml-1911359275"></a>
## StringBuilder

```ml
struct StringBuilder
```

Mutable UTF-8 byte builder for append-heavy string construction.


Source: `std/string_builder.ml:41`

## Members

<a id="method-method-std-string-builder-stringbuilder-append-function-append-value-std-string-builder-ml-1611521868"></a>
### append

```ml
function append(value)
```

Convert a value with str() and append its textual representation.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/string_builder.ml:161`

<a id="method-method-std-string-builder-stringbuilder-appendline-function-appendline-value-std-string-builder-ml-1228486276"></a>
### appendLine

```ml
function appendLine(value)
```

Append a value followed by a newline byte.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/string_builder.ml:171`

<a id="method-method-std-string-builder-stringbuilder-appendslice-function-appendslice-s-offset-length-std-string-builder-ml-924904113"></a>
### appendSlice

```ml
function appendSlice(s, offset, length)
```

Append a clamped byte slice; negative offsets count from the end.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `offset` | `dynamic` | — | Zero-based starting offset. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/string_builder.ml:119`

<a id="method-method-std-string-builder-stringbuilder-appendstring-function-appendstring-s-std-string-builder-ml-1654662588"></a>
### appendString

```ml
function appendString(s)
```

Append a string without creating an intermediate concatenation.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/string_builder.ml:102`

<a id="field-field-std-string-builder-stringbuilder-buf-buf-std-string-builder-ml-2071105377"></a>
### buf

```ml
buf
```

Stores the buf member of `StringBuilder`.


Source: `std/string_builder.ml:43`

<a id="field-field-std-string-builder-stringbuilder-capacity-capacity-std-string-builder-ml-1642360177"></a>
### capacity

```ml
capacity
```

Stores the capacity member of `StringBuilder`.


Source: `std/string_builder.ml:47`

<a id="method-method-std-string-builder-stringbuilder-clear-function-clear-std-string-builder-ml-1859141821"></a>
### clear

```ml
function clear()
```

Reset the logical length while retaining allocated capacity.


Source: `std/string_builder.ml:73`

<a id="method-method-std-string-builder-stringbuilder-len-function-len-std-string-builder-ml-444722389"></a>
### len

```ml
function len()
```

Return the number of UTF-8 bytes currently stored.


Source: `std/string_builder.ml:68`

<a id="field-field-std-string-builder-stringbuilder-lenbytes-lenbytes-std-string-builder-ml-1199699105"></a>
### lenBytes

```ml
lenBytes
```

Stores the len bytes member of `StringBuilder`.


Source: `std/string_builder.ml:45`

<a id="static_method-static-method-std-string-builder-stringbuilder-new-static-function-new-std-string-builder-ml-1046518366"></a>
### new

```ml
static function new()
```

Create an empty builder with a practical default capacity.


Source: `std/string_builder.ml:50`

<a id="method-method-std-string-builder-stringbuilder-reserve-function-reserve-extra-std-string-builder-ml-1183173349"></a>
### reserve

```ml
function reserve(extra)
```

Ensure room for at least extra additional bytes.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `extra` | `dynamic` | — | Value supplied for `extra`. |


Source: `std/string_builder.ml:79`

<a id="method-method-std-string-builder-stringbuilder-tostring-function-tostring-std-string-builder-ml-1779129711"></a>
### toString

```ml
function toString()
```

Materialize exactly the initialized bytes as an immutable string.


Source: `std/string_builder.ml:177`

<a id="static_method-static-method-std-string-builder-stringbuilder-withcapacity-static-function-withcapacity-cap-std-string-builder-ml-306477140"></a>
### withCapacity

```ml
static function withCapacity(cap)
```

Create an empty builder with at least cap bytes of capacity.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `cap` | `dynamic` | — | Value supplied for `cap`. |


Source: `std/string_builder.ml:56`
