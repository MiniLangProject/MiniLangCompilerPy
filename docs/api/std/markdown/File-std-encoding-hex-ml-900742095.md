# `std/encoding/hex.ml`

[Home](README.md) · [Files](Files.md)

Provides the std encoding hex package.

Package: [`std.encoding.hex`](Package-std-encoding-hex-1931834162.md)

Reachable from entry: **no**

## Imports

- `std/string.ml` as `s` → [std/string.ml](File-std-string-ml-1276545685.md)

## Declarations

<a id="function-function-std-encoding-hex-decode-function-decode-s-std-encoding-hex-ml-994210004"></a>
### decode

```ml
function decode(s)
```

Decodes a hex string to bytes.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/encoding/hex.ml:58`

<a id="function-function-std-encoding-hex-decodeor-function-decodeor-s-fallbackbytes-std-encoding-hex-ml-1574510785"></a>
### decodeOr

```ml
function decodeOr(s, fallbackBytes)
```

Decodes a hex string or returns fallback bytes.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `fallbackBytes` | `dynamic` | — | Value supplied for `fallbackBytes`. |


Source: `std/encoding/hex.ml:72`

<a id="function-function-std-encoding-hex-decodeorerror-function-decodeorerror-s-std-encoding-hex-ml-1933310858"></a>
### decodeOrError

```ml
function decodeOrError(s)
```

Decodes a hex string or returns an error on failure.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/encoding/hex.ml:83`

<a id="function-function-std-encoding-hex-encode-function-encode-b-std-encoding-hex-ml-1999249601"></a>
### encode

```ml
function encode(b)
```

Encodes bytes to lowercase hex.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |


Source: `std/encoding/hex.ml:42`

<a id="function-function-std-encoding-hex-encodeupper-function-encodeupper-b-std-encoding-hex-ml-1884024969"></a>
### encodeUpper

```ml
function encodeUpper(b)
```

Encodes bytes to uppercase hex.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |


Source: `std/encoding/hex.ml:48`

<a id="constant-constant-std-encoding-hex-hex-err-const-hex-err-210-std-encoding-hex-ml-1612941011"></a>
### HEX_ERR

```ml
const HEX_ERR = 210
```

Lower/uppercase hexadecimal encoding plus strict, error-preserving decoding.


Source: `std/encoding/hex.ml:24`

<a id="function-function-std-encoding-hex-isvalid-function-isvalid-s-std-encoding-hex-ml-1745609812"></a>
### isValid

```ml
function isValid(s)
```

Checks whether a hex string is valid.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/encoding/hex.ml:64`
