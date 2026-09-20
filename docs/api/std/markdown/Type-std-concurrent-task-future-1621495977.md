# `std.concurrent.task.Future`

[Home](README.md) · [Source file](File-std-concurrent-task-ml-139288457.md)

<a id="struct-struct-std-concurrent-task-future-struct-future-std-concurrent-task-ml-992606502"></a>
## Future

```ml
struct Future
```

Future is a stable managed handle around a ThreadPoolJob and, optionally, a cooperative cancellation source. Result values remain rooted by the job.


Source: `std/concurrent/task.ml:37`

## Members

<a id="method-method-std-concurrent-task-future-cancel-function-cancel-std-concurrent-task-ml-1703225909"></a>
### Cancel

```ml
function Cancel()
```

Reports whether cancel.


Source: `std/concurrent/task.ml:108`

<a id="method-method-std-concurrent-task-future-cancel-function-cancel-std-concurrent-task-ml-175448501"></a>
### cancel

```ml
function cancel()
```

Queued work is removed directly; running work receives a cooperative token.


Source: `std/concurrent/task.ml:78`

<a id="field-field-std-concurrent-task-future-cancellationsource-cancellationsource-std-concurrent-task-ml-1956535131"></a>
### cancellationSource

```ml
cancellationSource
```

Cancellation source associated with `Future`.


Source: `std/concurrent/task.ml:41`

<a id="method-method-std-concurrent-task-future-close-function-close-std-concurrent-task-ml-615943313"></a>
### close

```ml
function close()
```

Releases the completed task's synchronization resources.


Source: `std/concurrent/task.ml:89`

<a id="field-field-std-concurrent-task-future-closed-closed-std-concurrent-task-ml-1571659435"></a>
### closed

```ml
closed
```

Closed associated with `Future`.


Source: `std/concurrent/task.ml:43`

<a id="method-method-std-concurrent-task-future-dispose-function-dispose-std-concurrent-task-ml-667536055"></a>
### Dispose

```ml
function Dispose()
```

Disposes this task through its PascalCase alias.


Source: `std/concurrent/task.ml:110`

<a id="method-method-std-concurrent-task-future-isdone-function-isdone-std-concurrent-task-ml-1810562205"></a>
### IsDone

```ml
function IsDone()
```

Thread reserves PascalCase Status/Result/Close at the language level; Future intentionally keeps those three operations lowercase.


Source: `std/concurrent/task.ml:106`

<a id="method-method-std-concurrent-task-future-isdone-function-isdone-std-concurrent-task-ml-1624872349"></a>
### isDone

```ml
function isDone()
```

Reports whether is done.


Source: `std/concurrent/task.ml:65`

<a id="field-field-std-concurrent-task-future-job-job-std-concurrent-task-ml-832511491"></a>
### job

```ml
job
```

Job associated with `Future`.


Source: `std/concurrent/task.ml:39`

<a id="method-method-std-concurrent-task-future-result-function-result-std-concurrent-task-ml-716603753"></a>
### result

```ml
function result()
```

Provide result behavior for this standard-library module.


Source: `std/concurrent/task.ml:71`

<a id="method-method-std-concurrent-task-future-status-function-status-std-concurrent-task-ml-1165235189"></a>
### status

```ml
function status()
```

Provide status behavior for this standard-library module.


Source: `std/concurrent/task.ml:59`

<a id="method-method-std-concurrent-task-future-wait-function-wait-std-concurrent-task-ml-850498977"></a>
### Wait

```ml
function Wait()
```

Exposes task completion waiting through a PascalCase alias.


Source: `std/concurrent/task.ml:101`

<a id="method-method-std-concurrent-task-future-wait-function-wait-std-concurrent-task-ml-1188844321"></a>
### wait

```ml
function wait()
```

Blocks until this task completes.


Source: `std/concurrent/task.ml:46`

<a id="method-method-std-concurrent-task-future-waitfor-function-waitfor-milliseconds-std-concurrent-task-ml-1086060791"></a>
### WaitFor

```ml
function WaitFor(milliseconds)
```

Exposes timed task waiting through a PascalCase alias.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/task.ml:104`

<a id="method-method-std-concurrent-task-future-waitfor-function-waitfor-milliseconds-std-concurrent-task-ml-1176137015"></a>
### waitFor

```ml
function waitFor(milliseconds)
```

Waits up to a bounded duration for this task to complete.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/task.ml:53`
