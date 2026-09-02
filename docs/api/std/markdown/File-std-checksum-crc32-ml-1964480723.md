# `std/checksum/crc32.ml`

[Home](README.md) · [Files](Files.md)

Provides the std checksum crc32 package.

Package: [`std.checksum.crc32`](Package-std-checksum-crc32-894971042.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-checksum-crc32-compute-function-compute-buffer-std-checksum-crc32-ml-1928954823"></a>
### compute

```ml
function compute(buffer)
```

Compute CRC-32/IEEE over an entire bytes value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `buffer` | `dynamic` | — | Buffer to process. |


Source: `std/checksum/crc32.ml:28`

<a id="function-function-std-checksum-crc32-computerange-function-computerange-buffer-offset-length-std-checksum-crc32-ml-443299340"></a>
### computeRange

```ml
function computeRange(buffer, offset, length)
```

Compute CRC-32/IEEE over one validated byte range.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `buffer` | `dynamic` | — | Buffer to process. |
| `offset` | `dynamic` | — | Zero-based starting offset. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/checksum/crc32.ml:37`

<a id="function-function-std-checksum-crc32-update-function-update-previous-buffer-offset-length-std-checksum-crc32-ml-1170152687"></a>
### update

```ml
function update(previous, buffer, offset, length)
```

Continue a finalized CRC-32/IEEE value over one byte range.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `previous` | `dynamic` | — | Value supplied for `previous`. |
| `buffer` | `dynamic` | — | Buffer to process. |
| `offset` | `dynamic` | — | Zero-based starting offset. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/checksum/crc32.ml:47`

<a id="function-function-std-checksum-crc32-verify-function-verify-buffer-expected-std-checksum-crc32-ml-1834539753"></a>
### verify

```ml
function verify(buffer, expected)
```

Compare the CRC-32/IEEE of an entire buffer with expected.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `buffer` | `dynamic` | — | Buffer to process. |
| `expected` | `dynamic` | — | Value supplied for `expected`. |


Source: `std/checksum/crc32.ml:55`

<a id="function-function-std-checksum-crc32-verifyrange-function-verifyrange-buffer-offset-length-expected-std-checksum-crc32-ml-384566048"></a>
### verifyRange

```ml
function verifyRange(buffer, offset, length, expected)
```

Compare the CRC-32/IEEE of one range with expected.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `buffer` | `dynamic` | — | Buffer to process. |
| `offset` | `dynamic` | — | Zero-based starting offset. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |
| `expected` | `dynamic` | — | Value supplied for `expected`. |


Source: `std/checksum/crc32.ml:66`
