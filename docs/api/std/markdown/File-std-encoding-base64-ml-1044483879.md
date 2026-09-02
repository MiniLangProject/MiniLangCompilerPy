# `std/encoding/base64.ml`

[Home](README.md) · [Files](Files.md)

Provides the std encoding base64 package.

Package: [`std.encoding.base64`](Package-std-encoding-base64-235857586.md)

Reachable from entry: **no**

## Declarations

<a id="constant-constant-std-encoding-base64-alphabet-const-alphabet-abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789-std-encoding-base64-ml-1253735771"></a>
### ALPHABET

```ml
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
```

Std.encoding.base64 Minimal Base64 (RFC 4648) utilities: toBase64(bytes) -> string fromBase64(string) -> bytes | void Notes: - fromBase64 ignores ASCII whitespace (space/tab/CR/LF). - returns void on invalid input.


Source: `std/encoding/base64.ml:22`

<a id="function-function-std-encoding-base64-frombase64-function-frombase64-text-std-encoding-base64-ml-1409232600"></a>
### fromBase64

```ml
function fromBase64(text)
```

Decoding: base64 string -> bytes (or void on error).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `text` | `dynamic` | — | Text to process. |


Source: `std/encoding/base64.ml:158`

<a id="function-function-std-encoding-base64-tobase64-function-tobase64-b-std-encoding-base64-ml-696343249"></a>
### toBase64

```ml
function toBase64(b)
```

Encoding: bytes -> base64 string (with '=' padding).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |


Source: `std/encoding/base64.ml:101`
