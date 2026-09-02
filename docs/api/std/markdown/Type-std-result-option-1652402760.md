# `std.result.Option`

[Home](README.md) · [Source file](File-std-result-ml-986518417.md)

<a id="struct-struct-std-result-option-struct-option-std-result-ml-912148509"></a>
## Option

```ml
struct Option
```

Std.result Minimal Option/Result data structures. NOTE (important for packages): Inside a `package`, names are qualified (e.g. std.result.Option). Therefore constructors inside this file must use fully-qualified names.


Source: `std/result.ml:22`

## Members

<a id="method-method-std-result-option-andthen-function-andthen-f-std-result-ml-1549329048"></a>
### andThen

```ml
function andThen(f)
```

Chains Options (flatMap).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `f` | `dynamic` | — | Function invoked by the operation. |


Source: `std/result.ml:86`

<a id="field-field-std-result-option-has-has-std-result-ml-1143621826"></a>
### has

```ml
has
```

Stores the has member of `Option`.


Source: `std/result.ml:24`

<a id="method-method-std-result-option-isnone-function-isnone-std-result-ml-2144417308"></a>
### isNone

```ml
function isNone()
```

Checks whether this Option is empty.


Source: `std/result.ml:45`

<a id="method-method-std-result-option-issome-function-issome-std-result-ml-965212188"></a>
### isSome

```ml
function isSome()
```

Checks whether this Option contains a value.


Source: `std/result.ml:40`

<a id="method-method-std-result-option-map-function-map-f-std-result-ml-1644523560"></a>
### map

```ml
function map(f)
```

Transforms the contained value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `f` | `dynamic` | — | Function invoked by the operation. |


Source: `std/result.ml:77`

<a id="static_method-static-method-std-result-option-none-static-function-none-std-result-ml-1586653"></a>
### None

```ml
static function None()
```

Creates an empty Option.


Source: `std/result.ml:35`

<a id="static_method-static-method-std-result-option-some-static-function-some-v-std-result-ml-1822127959"></a>
### Some

```ml
static function Some(v)
```

Creates an Option with a value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `v` | `dynamic` | — | Value supplied for `v`. |


Source: `std/result.ml:30`

<a id="method-method-std-result-option-unwrap-function-unwrap-std-result-ml-660767988"></a>
### unwrap

```ml
function unwrap()
```

Returns the contained value or void.


Source: `std/result.ml:59`

<a id="method-method-std-result-option-unwrapor-function-unwrapor-fallback-std-result-ml-1110684614"></a>
### unwrapOr

```ml
function unwrapOr(fallback)
```

Returns the contained value or fallback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `fallback` | `dynamic` | — | Value supplied for `fallback`. |


Source: `std/result.ml:51`

<a id="method-method-std-result-option-unwraporelse-function-unwraporelse-thunk-std-result-ml-183966738"></a>
### unwrapOrElse

```ml
function unwrapOrElse(thunk)
```

Returns the contained value or computes a fallback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `thunk` | `dynamic` | — | Value supplied for `thunk`. |


Source: `std/result.ml:68`

<a id="field-field-std-result-option-value-value-std-result-ml-527206490"></a>
### value

```ml
value
```

Stores the value member of `Option`.


Source: `std/result.ml:26`
