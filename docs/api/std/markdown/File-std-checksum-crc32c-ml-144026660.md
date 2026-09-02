# `std/checksum/crc32c.ml`

[Home](README.md) · [Files](Files.md)

Provides the std checksum crc32c package.

Package: [`std.checksum.crc32c`](Package-std-checksum-crc32c-986608595.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-checksum-crc32c-compute-function-compute-buffer-std-checksum-crc32c-ml-2124890769"></a>
### compute

```ml
function compute(buffer)
```

Compute CRC-32C over an entire bytes value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `buffer` | `dynamic` | — | Buffer to process. |


Source: `std/checksum/crc32c.ml:28`

<a id="function-function-std-checksum-crc32c-computerange-function-computerange-buffer-offset-length-std-checksum-crc32c-ml-1768014220"></a>
### computeRange

```ml
function computeRange(buffer, offset, length)
```

Compute CRC-32C over one validated byte range.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `buffer` | `dynamic` | — | Buffer to process. |
| `offset` | `dynamic` | — | Zero-based starting offset. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/checksum/crc32c.ml:37`

<a id="function-function-std-checksum-crc32c-update-function-update-previous-buffer-offset-length-std-checksum-crc32c-ml-1039557397"></a>
### update

```ml
function update(previous, buffer, offset, length)
```

Continue a finalized CRC-32C value over one byte range.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `previous` | `dynamic` | — | Value supplied for `previous`. |
| `buffer` | `dynamic` | — | Buffer to process. |
| `offset` | `dynamic` | — | Zero-based starting offset. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/checksum/crc32c.ml:47`

<a id="function-function-std-checksum-crc32c-verify-function-verify-buffer-expected-std-checksum-crc32c-ml-766353659"></a>
### verify

```ml
function verify(buffer, expected)
```

Compare the CRC-32C of an entire buffer with expected.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `buffer` | `dynamic` | — | Buffer to process. |
| `expected` | `dynamic` | — | Value supplied for `expected`. |


Source: `std/checksum/crc32c.ml:55`

<a id="function-function-std-checksum-crc32c-verifyrange-function-verifyrange-buffer-offset-length-expected-std-checksum-crc32c-ml-434060604"></a>
### verifyRange

```ml
function verifyRange(buffer, offset, length, expected)
```

Compare the CRC-32C of one range with expected.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `buffer` | `dynamic` | — | Buffer to process. |
| `offset` | `dynamic` | — | Zero-based starting offset. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |
| `expected` | `dynamic` | — | Value supplied for `expected`. |


Source: `std/checksum/crc32c.ml:66`
