# `std/process.ml`

[Home](README.md) · [Files](Files.md)

Provides the std process package.

Package: [`std.process`](Package-std-process-639159081.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-process-currentdirectory-function-currentdirectory-std-process-ml-1016102948"></a>
### currentDirectory

```ml
function currentDirectory()
```

Provide the current directory operation for this standard-library module.


Source: `std/process.ml:116`

<a id="function-function-std-process-environment-function-environment-name-std-process-ml-1459757785"></a>
### environment

```ml
function environment(name)
```

Return an environment value, or void when the variable is absent.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | `dynamic` | — | Name of the requested item. |


Source: `std/process.ml:94`

<a id="function-function-std-process-executablepath-function-executablepath-std-process-ml-649110652"></a>
### executablePath

```ml
function executablePath()
```

Return the absolute path of the currently running native image.


Source: `std/process.ml:77`

<a id="function-function-std-process-id-function-id-std-process-ml-156871044"></a>
### id

```ml
function id()
```

Provide the id operation for this standard-library module.


Source: `std/process.ml:68`

<a id="constant-constant-std-process-max-environment-bytes-const-max-environment-bytes-1048576-std-process-ml-229265976"></a>
### MAX_ENVIRONMENT_BYTES

```ml
const MAX_ENVIRONMENT_BYTES = 1048576
```

Track the max environment bytes value used by this standard-library module.


Source: `std/process.ml:17`

<a id="constant-constant-std-process-max-path-bytes-const-max-path-bytes-32768-std-process-ml-1282008749"></a>
### MAX_PATH_BYTES

```ml
const MAX_PATH_BYTES = 32768
```

Track the max path bytes value used by this standard-library module.


Source: `std/process.ml:19`

<a id="constant-constant-std-process-process-err-const-process-err-261-std-process-ml-699786150"></a>
### PROCESS_ERR

```ml
const PROCESS_ERR = 261
```

Track the process err value used by this standard-library module.


Source: `std/process.ml:15`

<a id="function-function-std-process-setcurrentdirectory-function-setcurrentdirectory-path-std-process-ml-2023618091"></a>
### setCurrentDirectory

```ml
function setCurrentDirectory(path)
```

Updates set current directory.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `dynamic` | — | Path to operate on. |


Source: `std/process.ml:132`
