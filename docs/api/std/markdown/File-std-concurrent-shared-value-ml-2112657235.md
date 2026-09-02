# `std/concurrent/shared_value.ml`

[Home](README.md) · [Files](Files.md)

Provides the std concurrent shared_value package.

Package: [`std.concurrent.shared_value`](Package-std-concurrent-shared-value-321927234.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-concurrent-shared-value-allocate-function-allocate-size-std-concurrent-shared-value-ml-634200546"></a>
### allocate

```ml
function allocate(size)
```

Allocate a writable unmanaged block and return its native address.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `size` | `dynamic` | — | Value supplied for `size`. |


Source: `std/concurrent/shared_value.ml:60`

<a id="function-function-std-concurrent-shared-value-clearrecordat-function-clearrecordat-address-std-concurrent-shared-value-ml-353588477"></a>
### clearRecordAt

```ml
function clearRecordAt(address)
```

Zero a native record without releasing any referenced payload.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | `dynamic` | — | Value supplied for `address`. |


Source: `std/concurrent/shared_value.ml:198`

<a id="function-function-std-concurrent-shared-value-destroyat-function-destroyat-address-std-concurrent-shared-value-ml-875610501"></a>
### destroyAt

```ml
function destroyAt(address)
```

Release an owned payload and clear its native record.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | `dynamic` | — | Value supplied for `address`. |


Source: `std/concurrent/shared_value.ml:231`

<a id="function-function-std-concurrent-shared-value-encode-function-encode-value-std-concurrent-shared-value-ml-914447698"></a>
### encode

```ml
function encode(value)
```

Returns [ok, type, payload, length]. For string/bytes payload owns a native block which must either be written into a record or released.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/concurrent/shared_value.ml:142`

<a id="function-function-std-concurrent-shared-value-free-function-free-address-std-concurrent-shared-value-ml-384067739"></a>
### free

```ml
function free(address)
```

Release a block previously returned by allocate().

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | `dynamic` | — | Value supplied for `address`. |


Source: `std/concurrent/shared_value.ml:71`

<a id="function-function-std-concurrent-shared-value-isshareable-function-isshareable-value-std-concurrent-shared-value-ml-1922324316"></a>
### isShareable

```ml
function isShareable(value)
```

Report whether the legacy snapshot codec supports this value category.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/concurrent/shared_value.ml:135`

<a id="constant-constant-std-concurrent-shared-value-mem-commit-reserve-const-mem-commit-reserve-12288-std-concurrent-shared-value-ml-1429665989"></a>
### MEM_COMMIT_RESERVE

```ml
const MEM_COMMIT_RESERVE = 12288
```

Legacy native-value codec retained for compatibility. The managed concurrent collections no longer need it because every thread shares the same GC heap. It remains useful for explicit snapshots passed to unmanaged native memory.


Source: `std/concurrent/shared_value.ml:11`

<a id="constant-constant-std-concurrent-shared-value-mem-release-const-mem-release-32768-std-concurrent-shared-value-ml-1583557078"></a>
### MEM_RELEASE

```ml
const MEM_RELEASE = 32768
```

Stores the mem release.


Source: `std/concurrent/shared_value.ml:13`

<a id="function-function-std-concurrent-shared-value-move-function-move-destination-source-count-std-concurrent-shared-value-ml-334062803"></a>
### move

```ml
function move(destination, source, count)
```

Copy count bytes between two unmanaged addresses.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `destination` | `dynamic` | — | Value supplied for `destination`. |
| `source` | `dynamic` | — | Source value to process. |
| `count` | `dynamic` | — | Number of items to process. |


Source: `std/concurrent/shared_value.ml:85`

<a id="constant-constant-std-concurrent-shared-value-page-readwrite-const-page-readwrite-4-std-concurrent-shared-value-ml-8023826"></a>
### PAGE_READWRITE

```ml
const PAGE_READWRITE = 4
```

Stores the page readwrite.


Source: `std/concurrent/shared_value.ml:15`

<a id="function-function-std-concurrent-shared-value-readat-function-readat-address-std-concurrent-shared-value-ml-1679073383"></a>
### readAt

```ml
function readAt(address)
```

Materialize a managed value from one native snapshot record.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | `dynamic` | — | Value supplied for `address`. |


Source: `std/concurrent/shared_value.ml:213`

<a id="function-function-std-concurrent-shared-value-readi64at-function-readi64at-address-std-concurrent-shared-value-ml-591429923"></a>
### readI64At

```ml
function readI64At(address)
```

Read a signed 64-bit integer from an unmanaged address.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | `dynamic` | — | Value supplied for `address`. |


Source: `std/concurrent/shared_value.ml:127`

<a id="constant-constant-std-concurrent-shared-value-record-size-const-record-size-24-std-concurrent-shared-value-ml-968300124"></a>
### RECORD_SIZE

```ml
const RECORD_SIZE = 24
```

Stores the record size.


Source: `std/concurrent/shared_value.ml:17`

<a id="function-function-std-concurrent-shared-value-releaseencoded-function-releaseencoded-encoded-std-concurrent-shared-value-ml-645091353"></a>
### releaseEncoded

```ml
function releaseEncoded(encoded)
```

Release the payload owned by an encoded string or bytes snapshot.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `encoded` | `dynamic` | — | Value supplied for `encoded`. |


Source: `std/concurrent/shared_value.ml:172`

<a id="constant-constant-std-concurrent-shared-value-type-bool-const-type-bool-2-std-concurrent-shared-value-ml-924359988"></a>
### TYPE_BOOL

```ml
const TYPE_BOOL = 2
```

Stores the type bool.


Source: `std/concurrent/shared_value.ml:24`

<a id="constant-constant-std-concurrent-shared-value-type-bytes-const-type-bytes-4-std-concurrent-shared-value-ml-1012191940"></a>
### TYPE_BYTES

```ml
const TYPE_BYTES = 4
```

Stores the type bytes.


Source: `std/concurrent/shared_value.ml:28`

<a id="constant-constant-std-concurrent-shared-value-type-int-const-type-int-1-std-concurrent-shared-value-ml-1766864889"></a>
### TYPE_INT

```ml
const TYPE_INT = 1
```

Stores the type int.


Source: `std/concurrent/shared_value.ml:22`

<a id="constant-constant-std-concurrent-shared-value-type-string-const-type-string-3-std-concurrent-shared-value-ml-203158269"></a>
### TYPE_STRING

```ml
const TYPE_STRING = 3
```

Stores the type string.


Source: `std/concurrent/shared_value.ml:26`

<a id="constant-constant-std-concurrent-shared-value-type-void-const-type-void-0-std-concurrent-shared-value-ml-628289738"></a>
### TYPE_VOID

```ml
const TYPE_VOID = 0
```

Stores the type void.


Source: `std/concurrent/shared_value.ml:20`

<a id="function-function-std-concurrent-shared-value-writeencodedat-function-writeencodedat-address-encoded-std-concurrent-shared-value-ml-1480224945"></a>
### writeEncodedAt

```ml
function writeEncodedAt(address, encoded)
```

Write encoded metadata into a RECORD_SIZE native record.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | `dynamic` | — | Value supplied for `address`. |
| `encoded` | `dynamic` | — | Value supplied for `encoded`. |


Source: `std/concurrent/shared_value.ml:184`

<a id="function-function-std-concurrent-shared-value-writei64at-function-writei64at-address-value-std-concurrent-shared-value-ml-1649928982"></a>
### writeI64At

```ml
function writeI64At(address, value)
```

Store a signed 64-bit integer at an unmanaged address.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | `dynamic` | — | Value supplied for `address`. |
| `value` | `dynamic` | — | Value to process. |


Source: `std/concurrent/shared_value.ml:119`
