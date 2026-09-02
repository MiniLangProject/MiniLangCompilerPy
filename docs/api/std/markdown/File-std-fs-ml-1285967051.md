# `std/fs.ml`

[Home](README.md) · [Files](Files.md)

Provides the std fs package.

Package: [`std.fs`](Package-std-fs-176676223.md)

Reachable from entry: **no**

## Imports

- `std/string.ml` as `s` → [std/string.ml](File-std-string-ml-1276545685.md)

## Declarations

- [std.fs.Access](Type-std-fs-access-569861977.md) — enum
<a id="function-function-std-fs-appendallbytes-function-appendallbytes-path-data-std-fs-ml-372563649"></a>
### appendAllBytes

```ml
function appendAllBytes(path, data)
```

Append bytes to a file (simple implementation: read + rewrite).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |
| `data` | `dynamic` | — | Data to process. |


Source: `std/fs.ml:782`

<a id="function-function-std-fs-appendalltext-function-appendalltext-path-text-std-fs-ml-1086283032"></a>
### appendAllText

```ml
function appendAllText(path, text)
```

Append text to a file (simple implementation: read + rewrite).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |
| `text` | `dynamic` | — | Text to process. |


Source: `std/fs.ml:802`

<a id="function-function-std-fs-copyfile-function-copyfile-sourcepath-destpath-overwrite-std-fs-ml-1522240000"></a>
### copyFile

```ml
function copyFile(sourcePath, destPath, overwrite)
```

Copy a file.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sourcePath` | `dynamic` | — | Value supplied for `sourcePath`. |
| `destPath` | `dynamic` | — | Value supplied for `destPath`. |
| `overwrite` | `dynamic` | — | Value supplied for `overwrite`. |


Source: `std/fs.ml:710`

- [std.fs.Creation](Type-std-fs-creation-832674482.md) — enum
<a id="function-function-std-fs-delete-function-delete-path-std-fs-ml-1227233521"></a>
### delete

```ml
function delete(path)
```

Delete a file (treats "already missing" as success).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/fs.ml:440`

<a id="constant-constant-std-fs-delete-retry-count-const-delete-retry-count-30-std-fs-ml-1202020222"></a>
### DELETE_RETRY_COUNT

```ml
const DELETE_RETRY_COUNT = 30
```

Track the delete retry count value used by this standard-library module.


Source: `std/fs.ml:174`

<a id="constant-constant-std-fs-delete-retry-sleep-ms-const-delete-retry-sleep-ms-5-std-fs-ml-1685798622"></a>
### DELETE_RETRY_SLEEP_MS

```ml
const DELETE_RETRY_SLEEP_MS = 5
```

Track the delete retry sleep ms value used by this standard-library module.


Source: `std/fs.ml:176`

<a id="constant-constant-std-fs-dword-size-const-dword-size-4-std-fs-ml-1756870543"></a>
### DWORD_SIZE

```ml
const DWORD_SIZE = 4
```

Track the dword size value used by this standard-library module.


Source: `std/fs.ml:170`

<a id="function-function-std-fs-exists-function-exists-path-std-fs-ml-72849833"></a>
### exists

```ml
function exists(path)
```

Check whether a file or directory exists.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/fs.ml:281`

- [std.fs.FileAttr](Type-std-fs-fileattr-1509238666.md) — enum
<a id="function-function-std-fs-filesize-function-filesize-path-std-fs-ml-274199189"></a>
### fileSize

```ml
function fileSize(path)
```

Get the size of a file in bytes.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/fs.ml:759`

<a id="constant-constant-std-fs-find-data-size-const-find-data-size-592-std-fs-ml-870133523"></a>
### FIND_DATA_SIZE

```ml
const FIND_DATA_SIZE = 592
```

Directory enumeration (FindFirstFileW/FindNextFileW).


Source: `std/fs.ml:244`

<a id="constant-constant-std-fs-find-name-len-const-find-name-len-520-std-fs-ml-689299188"></a>
### FIND_NAME_LEN

```ml
const FIND_NAME_LEN = 520
```

Track the find name len value used by this standard-library module.


Source: `std/fs.ml:248`

<a id="constant-constant-std-fs-find-name-off-const-find-name-off-44-std-fs-ml-172511087"></a>
### FIND_NAME_OFF

```ml
const FIND_NAME_OFF = 44
```

Track the find name off value used by this standard-library module.


Source: `std/fs.ml:246`

<a id="constant-constant-std-fs-invalid-file-attributes-const-invalid-file-attributes-4294967295-std-fs-ml-1562365268"></a>
### INVALID_FILE_ATTRIBUTES

```ml
const INVALID_FILE_ATTRIBUTES = 4294967295
```

Track the invalid file attributes value used by this standard-library module.


Source: `std/fs.ml:107`

<a id="constant-constant-std-fs-invalid-handle-value-const-invalid-handle-value-1-std-fs-ml-446181979"></a>
### INVALID_HANDLE_VALUE

```ml
const INVALID_HANDLE_VALUE = -1
```

Win32 constants (kept local to std.fs).


Source: `std/fs.ml:105`

<a id="constant-constant-std-fs-io-buf-size-const-io-buf-size-4096-std-fs-ml-1986717268"></a>
### IO_BUF_SIZE

```ml
const IO_BUF_SIZE = 4096
```

Track the io buf size value used by this standard-library module.


Source: `std/fs.ml:172`

<a id="function-function-std-fs-isdir-function-isdir-path-std-fs-ml-1982632259"></a>
### isDir

```ml
function isDir(path)
```

Check whether a path is a directory.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/fs.ml:291`

<a id="function-function-std-fs-isfile-function-isfile-path-std-fs-ml-137584197"></a>
### isFile

```ml
function isFile(path)
```

Check whether a path is a regular file.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/fs.ml:304`

<a id="function-function-std-fs-joinpath-function-joinpath-base-name-std-fs-ml-1871291558"></a>
### joinPath

```ml
function joinPath(base, name)
```

Join two path components using the Windows separator.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `base` | `dynamic` | — | Value supplied for `base`. |
| `name` | `dynamic` | — | Name of the requested item. |


Source: `std/fs.ml:314`

<a id="function-function-std-fs-listdir-function-listdir-path-std-fs-ml-1461247751"></a>
### listDir

```ml
function listDir(path)
```

List directory entries (names only, without '.' and '..').

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/fs.ml:393`

<a id="function-function-std-fs-movefile-function-movefile-sourcepath-destpath-overwrite-std-fs-ml-190963024"></a>
### moveFile

```ml
function moveFile(sourcePath, destPath, overwrite)
```

Move/rename a file.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sourcePath` | `dynamic` | — | Value supplied for `sourcePath`. |
| `destPath` | `dynamic` | — | Value supplied for `destPath`. |
| `overwrite` | `dynamic` | — | Value supplied for `overwrite`. |


Source: `std/fs.ml:733`

<a id="function-function-std-fs-readallbytes-function-readallbytes-path-std-fs-ml-290559245"></a>
### readAllBytes

```ml
function readAllBytes(path)
```

Read all bytes from a file.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/fs.ml:519`

<a id="function-function-std-fs-readalllines-function-readalllines-path-std-fs-ml-1313468293"></a>
### readAllLines

```ml
function readAllLines(path)
```

Read a file as lines (split by '\n', trims a trailing '\r').

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/fs.ml:821`

<a id="function-function-std-fs-readalltext-function-readalltext-path-std-fs-ml-1923171005"></a>
### readAllText

```ml
function readAllText(path)
```

Read all text from a file (assumes UTF-8).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/fs.ml:621`

- [std.fs.Share](Type-std-fs-share-399483706.md) — enum
<a id="constant-constant-std-fs-write-retry-count-const-write-retry-count-30-std-fs-ml-1411592692"></a>
### WRITE_RETRY_COUNT

```ml
const WRITE_RETRY_COUNT = 30
```

Track the write retry count value used by this standard-library module.


Source: `std/fs.ml:178`

<a id="constant-constant-std-fs-write-retry-sleep-ms-const-write-retry-sleep-ms-10-std-fs-ml-2115205390"></a>
### WRITE_RETRY_SLEEP_MS

```ml
const WRITE_RETRY_SLEEP_MS = 10
```

Track the write retry sleep ms value used by this standard-library module.


Source: `std/fs.ml:180`

<a id="function-function-std-fs-writeallbytes-function-writeallbytes-path-data-std-fs-ml-354087299"></a>
### writeAllBytes

```ml
function writeAllBytes(path, data)
```

Write all bytes to a file (overwrites if it exists).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |
| `data` | `dynamic` | — | Data to process. |


Source: `std/fs.ml:495`

<a id="function-function-std-fs-writealltext-function-writealltext-path-text-std-fs-ml-856051952"></a>
### writeAllText

```ml
function writeAllText(path, text)
```

Write all text to a file (overwrites if it exists).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |
| `text` | `dynamic` | — | Text to process. |


Source: `std/fs.ml:597`
