# `std.result.Result`

[Home](README.md) · [Source file](File-std-result-ml-986518417.md)

<a id="struct-struct-std-result-result-struct-result-std-result-ml-844390029"></a>
## Result

```ml
struct Result
```

Explicit success/error container for APIs that avoid automatic propagation.


Source: `std/result.ml:95`

## Members

<a id="method-method-std-result-result-andthen-function-andthen-f-std-result-ml-3241512"></a>
### andThen

```ml
function andThen(f)
```

Chains Results (flatMap).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `f` | `dynamic` | — | Function invoked by the operation. |


Source: `std/result.ml:153`

<a id="static_method-static-method-std-result-result-err-static-function-err-msg-std-result-ml-1963913706"></a>
### Err

```ml
static function Err(msg)
```

Creates a failed Result.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `msg` | `dynamic` | — | Value supplied for `msg`. |


Source: `std/result.ml:111`

<a id="method-method-std-result-result-iserr-function-iserr-std-result-ml-195507302"></a>
### isErr

```ml
function isErr()
```

Checks whether this Result is an error.


Source: `std/result.ml:121`

<a id="method-method-std-result-result-isok-function-isok-std-result-ml-1733939076"></a>
### isOk

```ml
function isOk()
```

Checks whether this Result is ok.


Source: `std/result.ml:116`

<a id="method-method-std-result-result-map-function-map-f-std-result-ml-1978001208"></a>
### map

```ml
function map(f)
```

Transforms the ok value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `f` | `dynamic` | — | Function invoked by the operation. |


Source: `std/result.ml:144`

<a id="field-field-std-result-result-message-message-std-result-ml-94570534"></a>
### message

```ml
message
```

Diagnostic message carried by `Result`.


Source: `std/result.ml:101`

<a id="field-field-std-result-result-ok-ok-std-result-ml-1635231818"></a>
### ok

```ml
ok
```

Whether `Result` represents a successful result.


Source: `std/result.ml:97`

<a id="static_method-static-method-std-result-result-ok-static-function-ok-v-std-result-ml-455002863"></a>
### Ok

```ml
static function Ok(v)
```

Creates a successful Result.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `v` | `dynamic` | — | Value supplied for `v`. |


Source: `std/result.ml:105`

<a id="method-method-std-result-result-unwrap-function-unwrap-std-result-ml-271790180"></a>
### unwrap

```ml
function unwrap()
```

Returns the value if ok, otherwise void.


Source: `std/result.ml:135`

<a id="method-method-std-result-result-unwrapor-function-unwrapor-fallback-std-result-ml-1349488118"></a>
### unwrapOr

```ml
function unwrapOr(fallback)
```

Returns the value if ok, otherwise fallback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `fallback` | `dynamic` | — | Value supplied for `fallback`. |


Source: `std/result.ml:127`

<a id="field-field-std-result-result-value-value-std-result-ml-727774254"></a>
### value

```ml
value
```

Value associated with `Result`.


Source: `std/result.ml:99`
