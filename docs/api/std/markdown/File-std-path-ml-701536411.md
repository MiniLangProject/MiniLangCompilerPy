# `std/path.ml`

[Home](README.md) · [Files](Files.md)

Provides the std path package.

Package: [`std.path`](Package-std-path-1355784099.md)

Reachable from entry: **no**

## Imports

- `std/platform.ml` as `platform` → [std/platform.ml](File-std-platform-ml-201801091.md)

## Declarations

<a id="function-function-std-path-changeextension-function-changeextension-path-newextension-std-path-ml-379942222"></a>
### changeExtension

```ml
function changeExtension(path, newExtension)
```

Provide the change extension operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |
| `newExtension` | `dynamic` | — | Value supplied for `newExtension`. |


Source: `std/path.ml:121`

<a id="function-function-std-path-directoryname-function-directoryname-path-std-path-ml-1704846025"></a>
### directoryName

```ml
function directoryName(path)
```

Provide the directory name operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/path.ml:89`

<a id="function-function-std-path-extension-function-extension-path-std-path-ml-598017679"></a>
### extension

```ml
function extension(path)
```

Provide the extension operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/path.ml:106`

<a id="function-function-std-path-filename-function-filename-path-std-path-ml-8033517"></a>
### fileName

```ml
function fileName(path)
```

Provide the file name operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/path.ml:72`

<a id="function-function-std-path-isabsolute-function-isabsolute-path-std-path-ml-2109808033"></a>
### isAbsolute

```ml
function isAbsolute(path)
```

Reports whether is absolute.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/path.ml:41`

<a id="function-function-std-path-join-function-join-left-right-std-path-ml-2015239089"></a>
### join

```ml
function join(left, right)
```

Provide the join operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `left` | `dynamic` | — | Left input value. |
| `right` | `dynamic` | — | Right input value. |


Source: `std/path.ml:56`

<a id="constant-constant-std-path-path-err-const-path-err-260-std-path-ml-35148953"></a>
### PATH_ERR

```ml
const PATH_ERR = 260
```

Track the path err value used by this standard-library module.


Source: `std/path.ml:16`

<a id="function-function-std-path-separator-function-separator-std-path-ml-1502985602"></a>
### separator

```ml
function separator()
```

Provide the separator operation for this standard-library module.


Source: `std/path.ml:25`
