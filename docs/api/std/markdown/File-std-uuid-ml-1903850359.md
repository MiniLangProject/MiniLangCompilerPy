# `std/uuid.ml`

[Home](README.md) · [Files](Files.md)

Provides the std uuid package.

Package: [`std.uuid`](Package-std-uuid-358467167.md)

Reachable from entry: **no**

## Imports

- `std/crypto.ml` as `crypto` → [std/crypto.ml](File-std-crypto-ml-1263151193.md)
- `std/encoding/hex.ml` as `hex` → [std/encoding/hex.ml](File-std-encoding-hex-ml-900742095.md)
- `std/string.ml` as `string` → [std/string.ml](File-std-string-ml-1276545685.md)

## Declarations

<a id="function-function-std-uuid-format-function-format-raw-std-uuid-ml-2051708080"></a>
### format

```ml
function format(raw)
```

Converts format.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `raw` | `dynamic` | — | Value supplied for `raw`. |


Source: `std/uuid.ml:27`

<a id="function-function-std-uuid-isvalid-function-isvalid-text-std-uuid-ml-2002706769"></a>
### isValid

```ml
function isValid(text)
```

Reports whether is valid.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `text` | `dynamic` | — | Text to process. |


Source: `std/uuid.ml:64`

<a id="function-function-std-uuid-parse-function-parse-text-std-uuid-ml-99981495"></a>
### parse

```ml
function parse(text)
```

Returns parse.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `text` | `dynamic` | — | Text to process. |


Source: `std/uuid.ml:53`

<a id="constant-constant-std-uuid-uuid-err-const-uuid-err-266-std-uuid-ml-685764339"></a>
### UUID_ERR

```ml
const UUID_ERR = 266
```

Track the uuid err value used by this standard-library module.


Source: `std/uuid.ml:17`

<a id="function-function-std-uuid-v4-function-v4-std-uuid-ml-1680180020"></a>
### v4

```ml
function v4()
```

Provide the v4 operation for this standard-library module.


Source: `std/uuid.ml:43`

<a id="function-function-std-uuid-v4bytes-function-v4bytes-std-uuid-ml-166922686"></a>
### v4Bytes

```ml
function v4Bytes()
```

Provide the v4 bytes operation for this standard-library module.


Source: `std/uuid.ml:34`
