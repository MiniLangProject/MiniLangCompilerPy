# `std/compress/rle.ml`

[Home](README.md) · [Files](Files.md)

Portable byte run-length codec for sparse or highly repetitive data. Tokens 0..127 copy 1..128 literals; tokens 128..255 repeat the next byte 3..130 times. This is not a standardized interchange format.

Package: [`std.compress.rle`](Package-std-compress-rle-2043747507.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-compress-rle-decode-function-decode-block-expectedsize-std-compress-rle-ml-706272421"></a>
### decode

```ml
function decode(block, expectedSize)
```

Decode RLE into an exactly bounded output buffer.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `block` | `dynamic` | — | Encoded RLE bytes. |
| `expectedSize` | `dynamic` | — | Exact decoded byte count. |


Source: `std/compress/rle.ml:64`

<a id="function-function-std-compress-rle-encode-function-encode-input-std-compress-rle-ml-834631269"></a>
### encode

```ml
function encode(input)
```

Encode bytes using bounded literal and repeat runs.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `input` | `dynamic` | — | Bytes to compress. |


Source: `std/compress/rle.ml:29`

<a id="constant-constant-std-compress-rle-rle-err-const-rle-err-251-std-compress-rle-ml-517447994"></a>
### RLE_ERR

```ml
const RLE_ERR = 251
```

Error code for malformed RLE data.


Source: `std/compress/rle.ml:15`
