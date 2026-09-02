# `std/io/file.ml`

[Home](README.md) · [Files](Files.md)

Provides the std io file package.

Package: [`std.io.file`](Package-std-io-file-759994052.md)

Reachable from entry: **no**

## Imports

- `std/fs.ml` as `fs` → [std/fs.ml](File-std-fs-ml-1285967051.md)
- `std/path.ml` as `path_api` → [std/path.ml](File-std-path-ml-701536411.md)

## Declarations

<a id="function-function-std-io-file-append-function-append-file-source-sourceoffset-count-std-io-file-ml-1717912519"></a>
### append

```ml
function append(file, source, sourceOffset, count)
```

Updates append.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | `dynamic` | — | Value supplied for `file`. |
| `source` | `dynamic` | — | Source value to process. |
| `sourceOffset` | `dynamic` | — | Value supplied for `sourceOffset`. |
| `count` | `dynamic` | — | Number of items to process. |


Source: `std/io/file.ml:424`

<a id="function-function-std-io-file-atomicmove-function-atomicmove-source-destination-replaceexisting-std-io-file-ml-17044359"></a>
### atomicMove

```ml
function atomicMove(source, destination, replaceExisting)
```

Rename within one filesystem. With replaceExisting this is the primitive for publishing a fully flushed temporary file atomically.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `source` | `dynamic` | — | Source value to process. |
| `destination` | `dynamic` | — | Value supplied for `destination`. |
| `replaceExisting` | `dynamic` | — | Value supplied for `replaceExisting`. |


Source: `std/io/file.ml:639`

<a id="function-function-std-io-file-close-function-close-file-std-io-file-ml-1917059369"></a>
### close

```ml
function close(file)
```

Releases or resets close.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | `dynamic` | — | Value supplied for `file`. |


Source: `std/io/file.ml:528`

<a id="constant-constant-std-io-file-closed-handle-const-closed-handle-265-std-io-file-ml-18143127"></a>
### CLOSED_HANDLE

```ml
const CLOSED_HANDLE = 265
```

Stores the closed handle.


Source: `std/io/file.ml:22`

<a id="function-function-std-io-file-create-function-create-path-std-io-file-ml-118505396"></a>
### create

```ml
function create(path)
```

Creates create.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:320`

<a id="constant-constant-std-io-file-create-always-const-create-always-2-std-io-file-ml-1337061932"></a>
### CREATE_ALWAYS

```ml
const CREATE_ALWAYS = 2
```

Stores the create always.


Source: `std/io/file.ml:98`

<a id="constant-constant-std-io-file-create-new-const-create-new-1-std-io-file-ml-2052795847"></a>
### CREATE_NEW

```ml
const CREATE_NEW = 1
```

Stores the create new.


Source: `std/io/file.ml:96`

<a id="function-function-std-io-file-createdirectory-function-createdirectory-path-std-io-file-ml-1346524798"></a>
### createDirectory

```ml
function createDirectory(path)
```

Creates create directory.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:547`

<a id="function-function-std-io-file-createdurable-function-createdurable-path-std-io-file-ml-1821741618"></a>
### createDurable

```ml
function createDurable(path)
```

Creates create durable.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:332`

<a id="function-function-std-io-file-createnew-function-createnew-path-std-io-file-ml-1821480312"></a>
### createNew

```ml
function createNew(path)
```

Creates create new.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:326`

<a id="function-function-std-io-file-createnewdurable-function-createnewdurable-path-std-io-file-ml-825041504"></a>
### createNewDurable

```ml
function createNewDurable(path)
```

Creates create new durable.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:338`

<a id="function-function-std-io-file-deletepath-function-deletepath-path-std-io-file-ml-291993508"></a>
### deletePath

```ml
function deletePath(path)
```

Releases or resets delete path.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:590`

<a id="function-function-std-io-file-directoryexists-function-directoryexists-path-std-io-file-ml-1671780194"></a>
### directoryExists

```ml
function directoryExists(path)
```

Implements directory exists.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:584`

<a id="constant-constant-std-io-file-error-lock-violation-const-error-lock-violation-33-std-io-file-ml-606465282"></a>
### ERROR_LOCK_VIOLATION

```ml
const ERROR_LOCK_VIOLATION = 33
```

Stores the error lock violation.


Source: `std/io/file.ml:116`

<a id="constant-constant-std-io-file-file-attribute-normal-const-file-attribute-normal-128-std-io-file-ml-1674388885"></a>
### FILE_ATTRIBUTE_NORMAL

```ml
const FILE_ATTRIBUTE_NORMAL = 128
```

Stores the file attribute normal.


Source: `std/io/file.ml:104`

<a id="constant-constant-std-io-file-file-begin-const-file-begin-0-std-io-file-ml-571277004"></a>
### FILE_BEGIN

```ml
const FILE_BEGIN = 0
```

Stores the file begin.


Source: `std/io/file.ml:110`

<a id="constant-constant-std-io-file-file-err-const-file-err-263-std-io-file-ml-1292477923"></a>
### FILE_ERR

```ml
const FILE_ERR = 263
```

Stores the file err.


Source: `std/io/file.ml:18`

<a id="constant-constant-std-io-file-file-flag-backup-semantics-const-file-flag-backup-semantics-33554432-std-io-file-ml-182118807"></a>
### FILE_FLAG_BACKUP_SEMANTICS

```ml
const FILE_FLAG_BACKUP_SEMANTICS = 33554432
```

Stores the file flag backup semantics.


Source: `std/io/file.ml:108`

<a id="constant-constant-std-io-file-file-flag-write-through-const-file-flag-write-through-2147483648-std-io-file-ml-12646817"></a>
### FILE_FLAG_WRITE_THROUGH

```ml
const FILE_FLAG_WRITE_THROUGH = 2147483648
```

Stores the file flag write through.


Source: `std/io/file.ml:106`

<a id="constant-constant-std-io-file-file-share-all-const-file-share-all-7-std-io-file-ml-1906549635"></a>
### FILE_SHARE_ALL

```ml
const FILE_SHARE_ALL = 7
```

Stores the file share all.


Source: `std/io/file.ml:94`

<a id="function-function-std-io-file-fileexists-function-fileexists-path-std-io-file-ml-1075595960"></a>
### fileExists

```ml
function fileExists(path)
```

Implements file exists.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:578`

- [std.io.file.FileHandle](Type-std-io-file-filehandle-736043342.md) — struct
<a id="function-function-std-io-file-flush-function-flush-file-std-io-file-ml-1772033725"></a>
### flush

```ml
function flush(file)
```

Implements flush.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | `dynamic` | — | Value supplied for `file`. |


Source: `std/io/file.ml:464`

<a id="constant-constant-std-io-file-generic-read-const-generic-read-2147483648-std-io-file-ml-519446067"></a>
### GENERIC_READ

```ml
const GENERIC_READ = 2147483648
```

Stores the generic read.


Source: `std/io/file.ml:90`

<a id="constant-constant-std-io-file-generic-write-const-generic-write-1073741824-std-io-file-ml-1810060875"></a>
### GENERIC_WRITE

```ml
const GENERIC_WRITE = 1073741824
```

Stores the generic write.


Source: `std/io/file.ml:92`

<a id="function-function-std-io-file-joinpath-function-joinpath-left-right-std-io-file-ml-648345826"></a>
### joinPath

```ml
function joinPath(left, right)
```

Implements join path.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `left` | `dynamic` | — | Left input value. |
| `right` | `dynamic` | — | Right input value. |


Source: `std/io/file.ml:600`

<a id="function-function-std-io-file-lock-function-lock-file-mode-wait-std-io-file-ml-1414253107"></a>
### lock

```ml
function lock(file, mode, wait)
```

Acquire a whole-file advisory lock. mode is "shared" or "exclusive".

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | `dynamic` | — | Value supplied for `file`. |
| `mode` | `dynamic` | — | Value supplied for `mode`. |
| `wait` | `dynamic` | — | Value supplied for `wait`. |


Source: `std/io/file.ml:480`

<a id="constant-constant-std-io-file-lock-conflict-const-lock-conflict-264-std-io-file-ml-802934574"></a>
### LOCK_CONFLICT

```ml
const LOCK_CONFLICT = 264
```

Stores the lock conflict.


Source: `std/io/file.ml:20`

<a id="constant-constant-std-io-file-lockfile-exclusive-lock-const-lockfile-exclusive-lock-2-std-io-file-ml-1092840852"></a>
### LOCKFILE_EXCLUSIVE_LOCK

```ml
const LOCKFILE_EXCLUSIVE_LOCK = 2
```

Stores the lockfile exclusive lock.


Source: `std/io/file.ml:114`

<a id="constant-constant-std-io-file-lockfile-fail-immediately-const-lockfile-fail-immediately-1-std-io-file-ml-2085271419"></a>
### LOCKFILE_FAIL_IMMEDIATELY

```ml
const LOCKFILE_FAIL_IMMEDIATELY = 1
```

Stores the lockfile fail immediately.


Source: `std/io/file.ml:112`

<a id="constant-constant-std-io-file-max-io-count-const-max-io-count-2147483647-std-io-file-ml-1650857066"></a>
### MAX_IO_COUNT

```ml
const MAX_IO_COUNT = 2147483647
```

Stores the max io count.


Source: `std/io/file.ml:24`

<a id="constant-constant-std-io-file-movefile-replace-existing-const-movefile-replace-existing-1-std-io-file-ml-784108735"></a>
### MOVEFILE_REPLACE_EXISTING

```ml
const MOVEFILE_REPLACE_EXISTING = 1
```

Stores the movefile replace existing.


Source: `std/io/file.ml:118`

<a id="constant-constant-std-io-file-movefile-write-through-const-movefile-write-through-8-std-io-file-ml-17777282"></a>
### MOVEFILE_WRITE_THROUGH

```ml
const MOVEFILE_WRITE_THROUGH = 8
```

Stores the movefile write through.


Source: `std/io/file.ml:120`

<a id="function-function-std-io-file-movepath-function-movepath-source-destination-replaceexisting-std-io-file-ml-1359616939"></a>
### movePath

```ml
function movePath(source, destination, replaceExisting)
```

Implements move path.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `source` | `dynamic` | — | Source value to process. |
| `destination` | `dynamic` | — | Value supplied for `destination`. |
| `replaceExisting` | `dynamic` | — | Value supplied for `replaceExisting`. |


Source: `std/io/file.ml:657`

<a id="constant-constant-std-io-file-open-always-const-open-always-4-std-io-file-ml-533905138"></a>
### OPEN_ALWAYS

```ml
const OPEN_ALWAYS = 4
```

Stores the open always.


Source: `std/io/file.ml:102`

<a id="constant-constant-std-io-file-open-existing-const-open-existing-3-std-io-file-ml-1223724753"></a>
### OPEN_EXISTING

```ml
const OPEN_EXISTING = 3
```

Stores the open existing.


Source: `std/io/file.ml:100`

<a id="function-function-std-io-file-openread-function-openread-path-std-io-file-ml-808384584"></a>
### openRead

```ml
function openRead(path)
```

Implements open read.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:294`

<a id="function-function-std-io-file-openreadwrite-function-openreadwrite-path-createifmissing-std-io-file-ml-1630995317"></a>
### openReadWrite

```ml
function openReadWrite(path, createIfMissing)
```

Implements open read write.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |
| `createIfMissing` | `dynamic` | — | Value supplied for `createIfMissing`. |


Source: `std/io/file.ml:301`

<a id="function-function-std-io-file-openreadwritedurable-function-openreadwritedurable-path-createifmissing-std-io-file-ml-1261778099"></a>
### openReadWriteDurable

```ml
function openReadWriteDurable(path, createIfMissing)
```

Implements open read write durable.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |
| `createIfMissing` | `dynamic` | — | Value supplied for `createIfMissing`. |


Source: `std/io/file.ml:311`

<a id="function-function-std-io-file-pathexists-function-pathexists-path-std-io-file-ml-2037795076"></a>
### pathExists

```ml
function pathExists(path)
```

Implements path exists.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:572`

<a id="function-function-std-io-file-readallbytes-function-readallbytes-path-maximumbytes-std-io-file-ml-888056637"></a>
### readAllBytes

```ml
function readAllBytes(path, maximumBytes)
```

Returns read all bytes.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |
| `maximumBytes` | `dynamic` | — | Value supplied for `maximumBytes`. |


Source: `std/io/file.ml:607`

<a id="function-function-std-io-file-readalltext-function-readalltext-path-maximumbytes-std-io-file-ml-2121359345"></a>
### readAllText

```ml
function readAllText(path, maximumBytes)
```

Returns read all text.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |
| `maximumBytes` | `dynamic` | — | Value supplied for `maximumBytes`. |


Source: `std/io/file.ml:627`

<a id="function-function-std-io-file-readat-function-readat-file-fileoffset-destination-destinationoffset-count-std-io-file-ml-1658255612"></a>
### readAt

```ml
function readAt(file, fileOffset, destination, destinationOffset, count)
```

Returns read at.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | `dynamic` | — | Value supplied for `file`. |
| `fileOffset` | `dynamic` | — | Value supplied for `fileOffset`. |
| `destination` | `dynamic` | — | Value supplied for `destination`. |
| `destinationOffset` | `dynamic` | — | Value supplied for `destinationOffset`. |
| `count` | `dynamic` | — | Number of items to process. |


Source: `std/io/file.ml:348`

<a id="function-function-std-io-file-readexactat-function-readexactat-file-fileoffset-destination-destinationoffset-count-std-io-file-ml-560496664"></a>
### readExactAt

```ml
function readExactAt(file, fileOffset, destination, destinationOffset, count)
```

Returns read exact at.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | `dynamic` | — | Value supplied for `file`. |
| `fileOffset` | `dynamic` | — | Value supplied for `fileOffset`. |
| `destination` | `dynamic` | — | Value supplied for `destination`. |
| `destinationOffset` | `dynamic` | — | Value supplied for `destinationOffset`. |
| `count` | `dynamic` | — | Number of items to process. |


Source: `std/io/file.ml:376`

<a id="function-function-std-io-file-removedirectory-function-removedirectory-path-std-io-file-ml-253072106"></a>
### removeDirectory

```ml
function removeDirectory(path)
```

Releases or resets remove directory.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:560`

<a id="function-function-std-io-file-size-function-size-file-std-io-file-ml-1605500929"></a>
### size

```ml
function size(file)
```

Implements size.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | `dynamic` | — | Value supplied for `file`. |


Source: `std/io/file.ml:434`

<a id="function-function-std-io-file-syncdirectory-function-syncdirectory-path-std-io-file-ml-367043320"></a>
### syncDirectory

```ml
function syncDirectory(path)
```

Persist directory-entry updates after an atomic rename on POSIX. Windows MoveFileExW with MOVEFILE_WRITE_THROUGH already provides the matching fence.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/io/file.ml:663`

<a id="function-function-std-io-file-truncate-function-truncate-file-newsize-std-io-file-ml-718471930"></a>
### truncate

```ml
function truncate(file, newSize)
```

Implements truncate.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | `dynamic` | — | Value supplied for `file`. |
| `newSize` | `dynamic` | — | Value supplied for `newSize`. |


Source: `std/io/file.ml:450`

<a id="function-function-std-io-file-unlock-function-unlock-file-std-io-file-ml-810506305"></a>
### unlock

```ml
function unlock(file)
```

Implements unlock.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | `dynamic` | — | Value supplied for `file`. |


Source: `std/io/file.ml:512`

<a id="function-function-std-io-file-writeat-function-writeat-file-fileoffset-source-sourceoffset-count-std-io-file-ml-307314880"></a>
### writeAt

```ml
function writeAt(file, fileOffset, source, sourceOffset, count)
```

Updates write at.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | `dynamic` | — | Value supplied for `file`. |
| `fileOffset` | `dynamic` | — | Value supplied for `fileOffset`. |
| `source` | `dynamic` | — | Source value to process. |
| `sourceOffset` | `dynamic` | — | Value supplied for `sourceOffset`. |
| `count` | `dynamic` | — | Number of items to process. |


Source: `std/io/file.ml:393`
