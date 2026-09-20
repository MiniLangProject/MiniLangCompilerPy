# `std/compress/lz4.ml`

[Home](README.md) · [Files](Files.md)

Portable LZ4 block compression. Blocks have no embedded size or checksum; use std.compress for a self-describing, checked container.

Package: [`std.compress.lz4`](Package-std-compress-lz4-182262044.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-compress-lz4-decode-function-decode-block-expectedsize-std-compress-lz4-ml-2051485663"></a>
### decode

```ml
function decode(block, expectedSize)
```

Decode one LZ4 block into exactly expectedSize bytes. The caller-provided size is an allocation bound; malformed or truncated blocks are rejected before any out-of-range copy.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `block` | `dynamic` | — | Encoded LZ4 bytes. |
| `expectedSize` | `dynamic` | — | Exact decoded byte count. |


Source: `std/compress/lz4.ml:112`

<a id="function-function-std-compress-lz4-encode-function-encode-input-std-compress-lz4-ml-1350653011"></a>
### encode

```ml
function encode(input)
```

Encode a standard, independently decodable LZ4 block. The caller must retain the original byte length for decode().

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `input` | `dynamic` | — | Bytes to compress. |


Source: `std/compress/lz4.ml:38`

<a id="constant-constant-std-compress-lz4-lz4-err-const-lz4-err-250-std-compress-lz4-ml-1926203895"></a>
### LZ4_ERR

```ml
const LZ4_ERR = 250
```

Error code for malformed input or an invalid size.


Source: `std/compress/lz4.ml:14`
