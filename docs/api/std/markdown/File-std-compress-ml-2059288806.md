# `std/compress.ml`

[Home](README.md) · [Files](Files.md)

Self-describing, portable byte compression for Windows and Linux. The MLC1 container uses a 16-byte header, a bounded output size, and CRC-32C for accidental corruption detection (not authentication).

Package: [`std.compress`](Package-std-compress-1111036712.md)

Reachable from entry: **no**

## Imports

- `std/checksum/crc32c.ml` as `crc32c` → [std/checksum/crc32c.ml](File-std-checksum-crc32c-ml-144026660.md)
- `std/compress/lz4.ml` as `lz4` → [std/compress/lz4.ml](File-std-compress-lz4-ml-637795625.md)
- `std/compress/rle.ml` as `rle` → [std/compress/rle.ml](File-std-compress-rle-ml-92459872.md)

## Declarations

<a id="function-function-std-compress-compact-function-compact-input-std-compress-ml-2062070970"></a>
### compact

```ml
function compact(input)
```

Select the smallest of LZ4, RLE, and raw encoding.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `input` | `dynamic` | — | Bytes to compress. |


Source: `std/compress.ml:91`

<a id="function-function-std-compress-compress-function-compress-input-mode-std-compress-ml-2059640593"></a>
### compress

```ml
function compress(input, mode)
```

Pack bytes into a checked container. "fast" tries LZ4; "compact" also tries RLE and selects the smallest result. Incompressible data stays raw.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `input` | `dynamic` | — | Bytes to compress. |
| `mode` | `dynamic` | — | Either "fast" or "compact". |


Source: `std/compress.ml:48`

<a id="constant-constant-std-compress-compress-err-const-compress-err-252-std-compress-ml-1386556140"></a>
### COMPRESS_ERR

```ml
const COMPRESS_ERR = 252
```

Error code for invalid containers and output limits.


Source: `std/compress.ml:19`

<a id="function-function-std-compress-decodedsize-function-decodedsize-container-std-compress-ml-1171283667"></a>
### decodedSize

```ml
function decodedSize(container)
```

Return the advertised decoded size without allocating the payload. Always enforce an application-specific limit before trusting untrusted data.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `container` | `dynamic` | — | MLC1 container bytes. |


Source: `std/compress.ml:98`

<a id="function-function-std-compress-decompress-function-decompress-container-maxoutputbytes-std-compress-ml-2025164771"></a>
### decompress

```ml
function decompress(container, maxOutputBytes)
```

Decompress with an explicit output cap and verify the CRC-32C checksum. The limit prevents a small hostile container from requesting huge memory.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `container` | `dynamic` | — | MLC1 container bytes. |
| `maxOutputBytes` | `dynamic` | — | Maximum accepted decoded byte length. |


Source: `std/compress.ml:120`

<a id="function-function-std-compress-fast-function-fast-input-std-compress-ml-1661306628"></a>
### fast

```ml
function fast(input)
```

Fast general-purpose compression with raw fallback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `input` | `dynamic` | — | Bytes to compress. |


Source: `std/compress.ml:85`

<a id="constant-constant-std-compress-header-size-const-header-size-16-std-compress-ml-965599368"></a>
### HEADER_SIZE

```ml
const HEADER_SIZE = 16
```

Header bytes in an MLC1 container.


Source: `std/compress.ml:21`

<a id="constant-constant-std-compress-lz4-const-lz4-1-std-compress-ml-1873543484"></a>
### LZ4

```ml
const LZ4 = 1
```

Standard LZ4 block payload.


Source: `std/compress.ml:25`

<a id="constant-constant-std-compress-raw-const-raw-0-std-compress-ml-901869187"></a>
### RAW

```ml
const RAW = 0
```

Uncompressed payload.


Source: `std/compress.ml:23`

<a id="constant-constant-std-compress-rle-const-rle-2-std-compress-ml-64406373"></a>
### RLE

```ml
const RLE = 2
```

MiniLang byte-run payload.


Source: `std/compress.ml:27`
