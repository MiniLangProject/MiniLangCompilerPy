# `std/bytes.ml`

[Home](README.md) · [Files](Files.md)

Provides the std bytes package.

Package: [`std.bytes`](Package-std-bytes-172183927.md)

Reachable from entry: **no**

## Imports

- `std/encoding/hex.ml` as `hx` → [std/encoding/hex.ml](File-std-encoding-hex-ml-900742095.md)

## Declarations

<a id="function-function-std-bytes-alloc-function-alloc-size-std-bytes-ml-1457681591"></a>
### alloc

```ml
function alloc(size)
```

Std.bytes Bytes helpers built on top of the built-in `bytes` type and operations.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `size` | `dynamic` | — | Value supplied for `size`. |


Source: `std/bytes.ml:38`

<a id="function-function-std-bytes-allocfill-function-allocfill-size-fill-std-bytes-ml-871437864"></a>
### allocFill

```ml
function allocFill(size, fill)
```

Allocate size bytes initialized to the low eight bits of fill.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `size` | `dynamic` | — | Value supplied for `size`. |
| `fill` | `dynamic` | — | Value supplied for `fill`. |


Source: `std/bytes.ml:51`

<a id="constant-constant-std-bytes-bytes-err-const-bytes-err-211-std-bytes-ml-888551107"></a>
### BYTES_ERR

```ml
const BYTES_ERR = 211
```

Stores the bytes err.


Source: `std/bytes.ml:22`

<a id="function-function-std-bytes-compare-function-compare-a-b-std-bytes-ml-1567382625"></a>
### compare

```ml
function compare(a, b)
```

Return a lexicographic three-way comparison result.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:329`

<a id="function-function-std-bytes-concat-function-concat-a-b-std-bytes-ml-1927135267"></a>
### concat

```ml
function concat(a, b)
```

Concatenate two byte sequences into newly allocated storage.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:133`

<a id="function-function-std-bytes-copy-function-copy-b-std-bytes-ml-1693844616"></a>
### copy

```ml
function copy(b)
```

Return a detached copy of a bytes value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:66`

<a id="function-function-std-bytes-ctequals-function-ctequals-a-b-std-bytes-ml-959200415"></a>
### ctEquals

```ml
function ctEquals(a, b)
```

Compare equal-length sequences without data-dependent early exit.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:159`

<a id="function-function-std-bytes-decodeutf16z-function-decodeutf16z-b-std-bytes-ml-1507867896"></a>
### decodeUtf16Z

```ml
function decodeUtf16Z(b)
```

Decode little-endian UTF-16 bytes up to the first zero code unit.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:394`

<a id="function-function-std-bytes-decodeutf8-function-decodeutf8-b-std-bytes-ml-1587911928"></a>
### decodeUtf8

```ml
function decodeUtf8(b)
```

Decode UTF-8 bytes, returning void on invalid input.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:367`

<a id="function-function-std-bytes-decodeutf8orerror-function-decodeutf8orerror-b-std-bytes-ml-396718180"></a>
### decodeUtf8OrError

```ml
function decodeUtf8OrError(b)
```

Decode UTF-8 bytes, preserving validation failures as errors.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:373`

<a id="function-function-std-bytes-decodeutf8z-function-decodeutf8z-b-std-bytes-ml-913051038"></a>
### decodeUtf8Z

```ml
function decodeUtf8Z(b)
```

Decode UTF-8 bytes up to the first zero terminator.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:387`

<a id="function-function-std-bytes-endswith-function-endswith-b-suffix-std-bytes-ml-1215280649"></a>
### endsWith

```ml
function endsWith(b, suffix)
```

Report whether b ends with suffix.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `suffix` | `dynamic` | — | Value supplied for `suffix`. |


Source: `std/bytes.ml:234`

<a id="function-function-std-bytes-equals-function-equals-a-b-std-bytes-ml-1472927903"></a>
### equals

```ml
function equals(a, b)
```

Compare two byte sequences with ordinary early-exit semantics.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:146`

<a id="function-function-std-bytes-fill-function-fill-b-value-std-bytes-ml-1020966655"></a>
### fill

```ml
function fill(b, value)
```

Replace every byte in b with the low eight bits of value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/bytes.ml:202`

<a id="function-function-std-bytes-fromhex-function-fromhex-s-std-bytes-ml-510091409"></a>
### fromHex

```ml
function fromHex(s)
```

Decode hexadecimal text, returning void on invalid input.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/bytes.ml:347`

<a id="function-function-std-bytes-fromhexorerror-function-fromhexorerror-s-std-bytes-ml-2035014311"></a>
### fromHexOrError

```ml
function fromHexOrError(s)
```

Decode hexadecimal text, preserving validation failures as errors.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/bytes.ml:353`

<a id="function-function-std-bytes-indexof-function-indexof-hay-needle-start-std-bytes-ml-154105993"></a>
### indexOf

```ml
function indexOf(hay, needle, start)
```

Find the first needle occurrence at or after start, or return -1.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `hay` | `dynamic` | — | Value supplied for `hay`. |
| `needle` | `dynamic` | — | Value supplied for `needle`. |
| `start` | `dynamic` | — | Value supplied for `start`. |


Source: `std/bytes.ml:300`

<a id="function-function-std-bytes-lastindexof-function-lastindexof-hay-needle-std-bytes-ml-26887577"></a>
### lastIndexOf

```ml
function lastIndexOf(hay, needle)
```

Find the final needle occurrence, or return -1.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `hay` | `dynamic` | — | Value supplied for `hay`. |
| `needle` | `dynamic` | — | Value supplied for `needle`. |


Source: `std/bytes.ml:316`

<a id="function-function-std-bytes-readu16be-function-readu16be-b-off-std-bytes-ml-388570013"></a>
### readU16BE

```ml
function readU16BE(b, off)
```

Read an unsigned big-endian 16-bit integer.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `off` | `dynamic` | — | Value supplied for `off`. |


Source: `std/bytes.ml:542`

<a id="function-function-std-bytes-readu16le-function-readu16le-b-off-std-bytes-ml-827175377"></a>
### readU16LE

```ml
function readU16LE(b, off)
```

Read an unsigned little-endian 16-bit integer.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `off` | `dynamic` | — | Value supplied for `off`. |


Source: `std/bytes.ml:523`

<a id="function-function-std-bytes-readu32be-function-readu32be-b-off-std-bytes-ml-157086745"></a>
### readU32BE

```ml
function readU32BE(b, off)
```

Read an unsigned big-endian 32-bit integer.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `off` | `dynamic` | — | Value supplied for `off`. |


Source: `std/bytes.ml:638`

<a id="function-function-std-bytes-readu32le-function-readu32le-b-off-std-bytes-ml-1814407613"></a>
### readU32LE

```ml
function readU32LE(b, off)
```

Read an unsigned little-endian 32-bit integer.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `off` | `dynamic` | — | Value supplied for `off`. |


Source: `std/bytes.ml:617`

<a id="function-function-std-bytes-readu8-function-readu8-b-off-std-bytes-ml-1101136119"></a>
### readU8

```ml
function readU8(b, off)
```

Read one unsigned byte or return a range/type error.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `off` | `dynamic` | — | Value supplied for `off`. |


Source: `std/bytes.ml:454`

<a id="function-function-std-bytes-startswith-function-startswith-b-prefix-std-bytes-ml-913248740"></a>
### startsWith

```ml
function startsWith(b, prefix)
```

Report whether b begins with prefix.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `prefix` | `dynamic` | — | Value supplied for `prefix`. |


Source: `std/bytes.ml:221`

<a id="function-function-std-bytes-sub-function-sub-b-offset-length-std-bytes-ml-46179299"></a>
### sub

```ml
function sub(b, offset, length)
```

Return a clamped slice, or void when the input is not bytes.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `offset` | `dynamic` | — | Zero-based starting offset. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/bytes.ml:77`

<a id="function-function-std-bytes-suborerror-function-suborerror-b-offset-length-std-bytes-ml-710702291"></a>
### subOrError

```ml
function subOrError(b, offset, length)
```

Return an exact validated slice or a descriptive error value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `offset` | `dynamic` | — | Zero-based starting offset. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/bytes.ml:95`

<a id="function-function-std-bytes-tohex-function-tohex-b-std-bytes-ml-835666772"></a>
### toHex

```ml
function toHex(b)
```

Encode bytes as lowercase hexadecimal text.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:341`

<a id="function-function-std-bytes-writeu16be-function-writeu16be-b-off-value-std-bytes-ml-1415343010"></a>
### writeU16BE

```ml
function writeU16BE(b, off, value)
```

Write an unsigned 16-bit integer in big-endian order.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `off` | `dynamic` | — | Value supplied for `off`. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/bytes.ml:498`

<a id="function-function-std-bytes-writeu16le-function-writeu16le-b-off-value-std-bytes-ml-623641502"></a>
### writeU16LE

```ml
function writeU16LE(b, off, value)
```

Write an unsigned 16-bit integer in little-endian order.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `off` | `dynamic` | — | Value supplied for `off`. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/bytes.ml:472`

<a id="function-function-std-bytes-writeu32be-function-writeu32be-b-off-value-std-bytes-ml-560161774"></a>
### writeU32BE

```ml
function writeU32BE(b, off, value)
```

Write an unsigned 32-bit integer in big-endian order.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `off` | `dynamic` | — | Value supplied for `off`. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/bytes.ml:590`

<a id="function-function-std-bytes-writeu32le-function-writeu32le-b-off-value-std-bytes-ml-720189578"></a>
### writeU32LE

```ml
function writeU32LE(b, off, value)
```

Write an unsigned 32-bit integer in little-endian order.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `off` | `dynamic` | — | Value supplied for `off`. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/bytes.ml:562`

<a id="function-function-std-bytes-writeu8-function-writeu8-b-off-value-std-bytes-ml-1748622230"></a>
### writeU8

```ml
function writeU8(b, off, value)
```

Write one unsigned byte and return the next offset.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `b` | `dynamic` | — | Second input value. |
| `off` | `dynamic` | — | Value supplied for `off`. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/bytes.ml:430`

<a id="function-function-std-bytes-xor-function-xor-a-b-std-bytes-ml-2027129921"></a>
### xor

```ml
function xor(a, b)
```

Return the bytewise XOR of two equal-length sequences.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:659`

<a id="function-function-std-bytes-xorinplace-function-xorinplace-a-b-std-bytes-ml-1831427983"></a>
### xorInPlace

```ml
function xorInPlace(a, b)
```

XOR b into a in place; both sequences must have equal length.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/bytes.ml:684`
