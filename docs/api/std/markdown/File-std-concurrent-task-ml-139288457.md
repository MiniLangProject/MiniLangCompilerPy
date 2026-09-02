# `std/concurrent/task.ml`

[Home](README.md) · [Files](Files.md)

Provides the std concurrent task package.

Package: [`std.concurrent.task`](Package-std-concurrent-task-1232946368.md)

Reachable from entry: **no**

## Imports

- `std/concurrent/cancellation.ml` as `cancellation` → [std/concurrent/cancellation.ml](File-std-concurrent-cancellation-ml-1392694543.md)
- `std/concurrent/thread_pool.ml` as `threadPool` → [std/concurrent/thread_pool.ml](File-std-concurrent-thread-pool-ml-72857761.md)

## Declarations

- [std.concurrent.task.CancellableCall](Type-std-concurrent-task-cancellablecall-1113916868.md) — struct
- [std.concurrent.task.Future](Type-std-concurrent-task-future-1621495977.md) — struct
<a id="function-function-std-concurrent-task-run-function-run-pool-callback-data-std-concurrent-task-ml-576679120"></a>
### run

```ml
function run(pool, callback, data)
```

Schedule a conventional one-argument callback on an existing pool.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `pool` | `dynamic` | — | Value supplied for `pool`. |
| `callback` | `dynamic` | — | Value supplied for `callback`. |
| `data` | `dynamic` | — | Data to process. |


Source: `std/concurrent/task.ml:116`

<a id="function-function-std-concurrent-task-runcancellable-function-runcancellable-pool-callback-data-std-concurrent-task-ml-86407698"></a>
### runCancellable

```ml
function runCancellable(pool, callback, data)
```

Schedule callback(data, token) and return a future which can request cancel.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `pool` | `dynamic` | — | Value supplied for `pool`. |
| `callback` | `dynamic` | — | Value supplied for `callback`. |
| `data` | `dynamic` | — | Data to process. |


Source: `std/concurrent/task.ml:126`

<a id="constant-constant-std-concurrent-task-task-error-const-task-error-1651-std-concurrent-task-ml-1115029395"></a>
### TASK_ERROR

```ml
const TASK_ERROR = 1651
```

Track the task error value used by this standard-library module.


Source: `std/concurrent/task.ml:14`

<a id="function-function-std-concurrent-task-whenall-function-whenall-futures-std-concurrent-task-ml-504238549"></a>
### whenAll

```ml
function whenAll(futures)
```

Wait for every future in input order and return the equally ordered results.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `futures` | `dynamic` | — | Value supplied for `futures`. |


Source: `std/concurrent/task.ml:139`

<a id="function-function-std-concurrent-task-whenany-function-whenany-futures-std-concurrent-task-ml-1373291439"></a>
### whenAny

```ml
function whenAny(futures)
```

Provide the when any operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `futures` | `dynamic` | — | Value supplied for `futures`. |


Source: `std/concurrent/task.ml:177`

<a id="function-function-std-concurrent-task-whenanyfor-function-whenanyfor-futures-milliseconds-std-concurrent-task-ml-1029684509"></a>
### whenAnyFor

```ml
function whenAnyFor(futures, milliseconds)
```

Return the first completed future index, or -1 after the timeout. A negative timeout waits indefinitely; zero performs a non-blocking observation.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `futures` | `dynamic` | — | Value supplied for `futures`. |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/task.ml:156`
