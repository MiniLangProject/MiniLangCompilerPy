# `std.io.file.FileHandle`

[Home](README.md) · [Source file](File-std-io-file-ml-2074692665.md)

<a id="struct-struct-std-io-file-filehandle-struct-filehandle-std-io-file-ml-898876378"></a>
## FileHandle

```ml
struct FileHandle
```

Represents file handle.


Source: `std/io/file.ml:27`

## Members

<a id="method-method-std-io-file-filehandle-append-function-append-source-sourceoffset-count-std-io-file-ml-1706463078"></a>
### append

```ml
function append(source, sourceOffset, count)
```

Append a byte range and return its starting file offset.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `source` | `dynamic` | — | Source byte buffer. |
| `sourceOffset` | `dynamic` | — | First source byte to write. |
| `count` | `dynamic` | — | Number of bytes to write. |


Source: `std/io/file.ml:118`

<a id="method-method-std-io-file-filehandle-close-function-close-std-io-file-ml-1593295218"></a>
### close

```ml
function close()
```

Close the native handle; a second method call is harmless.


Source: `std/io/file.ml:156`

<a id="field-field-std-io-file-filehandle-closed-closed-std-io-file-ml-2031826438"></a>
### closed

```ml
closed
```

Closed associated with `FileHandle`.


Source: `std/io/file.ml:39`

<a id="static_method-static-method-std-io-file-filehandle-create-static-function-create-path-std-io-file-ml-1622967168"></a>
### create

```ml
static function create(path)
```

Create or replace a writable file.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | File path to create. |


Source: `std/io/file.ml:65`

<a id="static_method-static-method-std-io-file-filehandle-createdurable-static-function-createdurable-path-std-io-file-ml-1941964896"></a>
### createDurable

```ml
static function createDurable(path)
```

Create or replace a file with durable write-through behavior.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | File path to create. |


Source: `std/io/file.ml:77`

<a id="static_method-static-method-std-io-file-filehandle-createnew-static-function-createnew-path-std-io-file-ml-891589276"></a>
### createNew

```ml
static function createNew(path)
```

Create a file only when the path does not yet exist.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | File path to create. |


Source: `std/io/file.ml:71`

<a id="static_method-static-method-std-io-file-filehandle-createnewdurable-static-function-createnewdurable-path-std-io-file-ml-1936737546"></a>
### createNewDurable

```ml
static function createNewDurable(path)
```

Create a new durable file without replacing an existing path.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | File path to create. |


Source: `std/io/file.ml:83`

<a id="field-field-std-io-file-filehandle-durable-durable-std-io-file-ml-116176266"></a>
### durable

```ml
durable
```

Durable associated with `FileHandle`.


Source: `std/io/file.ml:37`

<a id="method-method-std-io-file-filehandle-flush-function-flush-std-io-file-ml-1576395282"></a>
### flush

```ml
function flush()
```

Flush writable contents to the operating system.


Source: `std/io/file.ml:134`

<a id="method-method-std-io-file-filehandle-isclosed-function-isclosed-std-io-file-ml-1324571678"></a>
### isClosed

```ml
function isClosed()
```

Report whether the native handle has been closed.


Source: `std/io/file.ml:151`

<a id="method-method-std-io-file-filehandle-lock-function-lock-mode-wait-std-io-file-ml-1859906828"></a>
### lock

```ml
function lock(mode, wait)
```

Acquire an advisory whole-file lock.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `mode` | `dynamic` | — | Either "shared" or "exclusive". |
| `wait` | `dynamic` | — | Whether to wait for an existing lock. |


Source: `std/io/file.ml:141`

<a id="field-field-std-io-file-filehandle-lockmode-lockmode-std-io-file-ml-598704922"></a>
### lockMode

```ml
lockMode
```

Lock mode associated with `FileHandle`.


Source: `std/io/file.ml:41`

<a id="field-field-std-io-file-filehandle-nativehandle-nativehandle-std-io-file-ml-1461736816"></a>
### nativeHandle

```ml
nativeHandle
```

Native handle associated with `FileHandle`.


Source: `std/io/file.ml:31`

<a id="static_method-static-method-std-io-file-filehandle-openread-static-function-openread-path-std-io-file-ml-1325159872"></a>
### openRead

```ml
static function openRead(path)
```

Open an existing file for positional reads.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | File path to open. |


Source: `std/io/file.ml:45`

<a id="static_method-static-method-std-io-file-filehandle-openreadwrite-static-function-openreadwrite-path-createifmissing-std-io-file-ml-1919434595"></a>
### openReadWrite

```ml
static function openReadWrite(path, createIfMissing)
```

Open a file for positional reads and writes.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | File path to open. |
| `createIfMissing` | `dynamic` | — | Create the file when it does not exist. |


Source: `std/io/file.ml:52`

<a id="static_method-static-method-std-io-file-filehandle-openreadwritedurable-static-function-openreadwritedurable-path-createifmissing-std-io-file-ml-2146529015"></a>
### openReadWriteDurable

```ml
static function openReadWriteDurable(path, createIfMissing)
```

Open a read/write file with durable write-through behavior.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | File path to open. |
| `createIfMissing` | `dynamic` | — | Create the file when it does not exist. |


Source: `std/io/file.ml:59`

<a id="field-field-std-io-file-filehandle-path-path-std-io-file-ml-678813428"></a>
### path

```ml
path
```

Path associated with `FileHandle`.


Source: `std/io/file.ml:29`

<a id="field-field-std-io-file-filehandle-readable-readable-std-io-file-ml-1675808450"></a>
### readable

```ml
readable
```

Readable associated with `FileHandle`.


Source: `std/io/file.ml:33`

<a id="method-method-std-io-file-filehandle-readat-function-readat-fileoffset-destination-destinationoffset-count-std-io-file-ml-435346217"></a>
### readAt

```ml
function readAt(fileOffset, destination, destinationOffset, count)
```

Read into an existing byte buffer without an intermediate allocation.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `fileOffset` | `dynamic` | — | Absolute offset in the file. |
| `destination` | `dynamic` | — | Destination byte buffer. |
| `destinationOffset` | `dynamic` | — | First destination byte to overwrite. |
| `count` | `dynamic` | — | Maximum bytes to read. |


Source: `std/io/file.ml:92`

<a id="method-method-std-io-file-filehandle-readexactat-function-readexactat-fileoffset-destination-destinationoffset-count-std-io-file-ml-549780093"></a>
### readExactAt

```ml
function readExactAt(fileOffset, destination, destinationOffset, count)
```

Read exactly count bytes or return an end-of-file error.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `fileOffset` | `dynamic` | — | Absolute offset in the file. |
| `destination` | `dynamic` | — | Destination byte buffer. |
| `destinationOffset` | `dynamic` | — | First destination byte to overwrite. |
| `count` | `dynamic` | — | Required byte count. |


Source: `std/io/file.ml:101`

<a id="method-method-std-io-file-filehandle-size-function-size-std-io-file-ml-654964302"></a>
### size

```ml
function size()
```

Return the current file size.


Source: `std/io/file.ml:123`

<a id="method-method-std-io-file-filehandle-truncate-function-truncate-newsize-std-io-file-ml-1422349835"></a>
### truncate

```ml
function truncate(newSize)
```

Change the file size.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `newSize` | `dynamic` | — | New length in bytes. |


Source: `std/io/file.ml:129`

<a id="method-method-std-io-file-filehandle-unlock-function-unlock-std-io-file-ml-1568670926"></a>
### unlock

```ml
function unlock()
```

Release this handle's advisory lock.


Source: `std/io/file.ml:146`

<a id="field-field-std-io-file-filehandle-writable-writable-std-io-file-ml-254181134"></a>
### writable

```ml
writable
```

Writable associated with `FileHandle`.


Source: `std/io/file.ml:35`

<a id="method-method-std-io-file-filehandle-writeat-function-writeat-fileoffset-source-sourceoffset-count-std-io-file-ml-2075982205"></a>
### writeAt

```ml
function writeAt(fileOffset, source, sourceOffset, count)
```

Write bytes at an absolute offset.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `fileOffset` | `dynamic` | — | Absolute offset in the file. |
| `source` | `dynamic` | — | Source byte buffer. |
| `sourceOffset` | `dynamic` | — | First source byte to write. |
| `count` | `dynamic` | — | Number of bytes to write. |


Source: `std/io/file.ml:110`
