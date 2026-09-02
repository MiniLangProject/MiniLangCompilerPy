# `std.concurrent.thread_pool.ThreadPool`

[Home](README.md) · [Source file](File-std-concurrent-thread-pool-ml-72857761.md)

<a id="struct-struct-std-concurrent-thread-pool-threadpool-struct-threadpool-std-concurrent-thread-pool-ml-258727682"></a>
## ThreadPool

```ml
struct ThreadPool
```

Fixed-size worker set backed by an optionally bounded FIFO queue.


Source: `std/concurrent/thread_pool.ml:266`

## Members

<a id="field-field-std-concurrent-thread-pool-threadpool-accepting-accepting-std-concurrent-thread-pool-ml-902827030"></a>
### accepting

```ml
accepting
```

Accepting associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:284`

<a id="method-method-std-concurrent-thread-pool-threadpool-awaittermination-function-awaittermination-std-concurrent-thread-pool-ml-6637564"></a>
### AwaitTermination

```ml
function AwaitTermination()
```

Provide await termination behavior for this standard-library module.


Source: `std/concurrent/thread_pool.ml:506`

<a id="method-method-std-concurrent-thread-pool-threadpool-awaitterminationfor-function-awaitterminationfor-milliseconds-std-concurrent-thread-pool-ml-1960742116"></a>
### AwaitTerminationFor

```ml
function AwaitTerminationFor(milliseconds)
```

Provide await termination for behavior for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/thread_pool.ml:509`

<a id="method-method-std-concurrent-thread-pool-threadpool-close-function-close-std-concurrent-thread-pool-ml-1182797580"></a>
### close

```ml
function close()
```

Shut down, join and release all worker and synchronization handles.


Source: `std/concurrent/thread_pool.ml:474`

<a id="field-field-std-concurrent-thread-pool-threadpool-closed-closed-std-concurrent-thread-pool-ml-109960782"></a>
### closed

```ml
closed
```

Closed associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:290`

<a id="method-method-std-concurrent-thread-pool-threadpool-dispose-function-dispose-std-concurrent-thread-pool-ml-1118298946"></a>
### Dispose

```ml
function Dispose()
```

Provide dispose behavior for this standard-library module.


Source: `std/concurrent/thread_pool.ml:511`

<a id="field-field-std-concurrent-thread-pool-threadpool-guard-guard-std-concurrent-thread-pool-ml-304843242"></a>
### guard

```ml
guard
```

Guard associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:268`

<a id="method-method-std-concurrent-thread-pool-threadpool-isshutdown-function-isshutdown-std-concurrent-thread-pool-ml-1713408876"></a>
### IsShutdown

```ml
function IsShutdown()
```

Reports whether is shutdown.


Source: `std/concurrent/thread_pool.ml:500`

<a id="method-method-std-concurrent-thread-pool-threadpool-isshutdown-function-isshutdown-std-concurrent-thread-pool-ml-811388460"></a>
### isShutdown

```ml
function isShutdown()
```

Report whether the pool has stopped accepting new jobs.


Source: `std/concurrent/thread_pool.ml:396`

<a id="method-method-std-concurrent-thread-pool-threadpool-join-function-join-std-concurrent-thread-pool-ml-1493137732"></a>
### join

```ml
function join()
```

Wait indefinitely for all workers after shutdown has begun.


Source: `std/concurrent/thread_pool.ml:444`

<a id="method-method-std-concurrent-thread-pool-threadpool-joinfor-function-joinfor-milliseconds-std-concurrent-thread-pool-ml-663703616"></a>
### joinFor

```ml
function joinFor(milliseconds)
```

Wait for each worker with the supplied per-worker timeout.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/thread_pool.ml:459`

<a id="static_method-static-method-std-concurrent-thread-pool-threadpool-new-static-function-new-workercount-std-concurrent-thread-pool-ml-1759983018"></a>
### new

```ml
static function new(workerCount)
```

Create an unbounded pool with workerCount native workers.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `workerCount` | `dynamic` | — | Value supplied for `workerCount`. |


Source: `std/concurrent/thread_pool.ml:294`

<a id="method-method-std-concurrent-thread-pool-threadpool-pendingcount-function-pendingcount-std-concurrent-thread-pool-ml-1884661524"></a>
### PendingCount

```ml
function PendingCount()
```

Provide pending count behavior for this standard-library module.


Source: `std/concurrent/thread_pool.ml:496`

<a id="method-method-std-concurrent-thread-pool-threadpool-pendingcount-function-pendingcount-std-concurrent-thread-pool-ml-78633876"></a>
### pendingCount

```ml
function pendingCount()
```

Return the number of jobs that have not yet been claimed by workers.


Source: `std/concurrent/thread_pool.ml:383`

<a id="field-field-std-concurrent-thread-pool-threadpool-queue-queue-std-concurrent-thread-pool-ml-467937354"></a>
### queue

```ml
queue
```

Queue associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:274`

<a id="field-field-std-concurrent-thread-pool-threadpool-queuecapacity-queuecapacity-std-concurrent-thread-pool-ml-1555178226"></a>
### queueCapacity

```ml
queueCapacity
```

Queue capacity associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:282`

<a id="field-field-std-concurrent-thread-pool-threadpool-queuedcount-queuedcount-std-concurrent-thread-pool-ml-1341410970"></a>
### queuedCount

```ml
queuedCount
```

Queued count associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:280`

<a id="field-field-std-concurrent-thread-pool-threadpool-queuehead-queuehead-std-concurrent-thread-pool-ml-230070806"></a>
### queueHead

```ml
queueHead
```

Queue head associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:276`

<a id="field-field-std-concurrent-thread-pool-threadpool-queuetail-queuetail-std-concurrent-thread-pool-ml-254067894"></a>
### queueTail

```ml
queueTail
```

Queue tail associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:278`

<a id="method-method-std-concurrent-thread-pool-threadpool-shutdown-function-shutdown-std-concurrent-thread-pool-ml-648357004"></a>
### Shutdown

```ml
function Shutdown()
```

Provide shutdown behavior for this standard-library module.


Source: `std/concurrent/thread_pool.ml:502`

<a id="method-method-std-concurrent-thread-pool-threadpool-shutdown-function-shutdown-std-concurrent-thread-pool-ml-586367372"></a>
### shutdown

```ml
function shutdown()
```

Stop accepting jobs and drain the existing queue before worker exit.


Source: `std/concurrent/thread_pool.ml:404`

<a id="method-method-std-concurrent-thread-pool-threadpool-shutdownnow-function-shutdownnow-std-concurrent-thread-pool-ml-1083023640"></a>
### ShutdownNow

```ml
function ShutdownNow()
```

Provide shutdown now behavior for this standard-library module.


Source: `std/concurrent/thread_pool.ml:504`

<a id="field-field-std-concurrent-thread-pool-threadpool-signal-signal-std-concurrent-thread-pool-ml-1133216446"></a>
### signal

```ml
signal
```

Signal associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:270`

<a id="method-method-std-concurrent-thread-pool-threadpool-stop-function-stop-std-concurrent-thread-pool-ml-1402724008"></a>
### stop

```ml
function stop()
```

Stop accepting jobs and cancel every job that is still queued.


Source: `std/concurrent/thread_pool.ml:418`

<a id="field-field-std-concurrent-thread-pool-threadpool-stopped-stopped-std-concurrent-thread-pool-ml-88571118"></a>
### stopped

```ml
stopped
```

Stopped associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:288`

<a id="field-field-std-concurrent-thread-pool-threadpool-stopping-stopping-std-concurrent-thread-pool-ml-392538930"></a>
### stopping

```ml
stopping
```

Stopping associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:286`

<a id="method-method-std-concurrent-thread-pool-threadpool-submit-function-submit-callback-data-std-concurrent-thread-pool-ml-1887013117"></a>
### Submit

```ml
function Submit(callback, data)
```

PascalCase aliases provide the conventional pool API surface.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `callback` | `dynamic` | — | Value supplied for `callback`. |
| `data` | `dynamic` | — | Data to process. |


Source: `std/concurrent/thread_pool.ml:494`

<a id="method-method-std-concurrent-thread-pool-threadpool-submit-function-submit-callback-data-std-concurrent-thread-pool-ml-704351741"></a>
### submit

```ml
function submit(callback, data)
```

Queue a callback and return its job handle, or void when rejected.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `callback` | `dynamic` | — | Value supplied for `callback`. |
| `data` | `dynamic` | — | Data to process. |


Source: `std/concurrent/thread_pool.ml:350`

<a id="static_method-static-method-std-concurrent-thread-pool-threadpool-withqueuecapacity-static-function-withqueuecapacity-workercount-queuecapacity-std-concurrent-thread-pool-ml-10704545"></a>
### withQueueCapacity

```ml
static function withQueueCapacity(workerCount, queueCapacity)
```

Create a pool whose zero capacity means an unbounded pending queue.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `workerCount` | `dynamic` | — | Value supplied for `workerCount`. |
| `queueCapacity` | `dynamic` | — | Value supplied for `queueCapacity`. |


Source: `std/concurrent/thread_pool.ml:301`

<a id="method-method-std-concurrent-thread-pool-threadpool-workercount-function-workercount-std-concurrent-thread-pool-ml-609593798"></a>
### WorkerCount

```ml
function WorkerCount()
```

Provide worker count behavior for this standard-library module.


Source: `std/concurrent/thread_pool.ml:498`

<a id="method-method-std-concurrent-thread-pool-threadpool-workercount-function-workercount-std-concurrent-thread-pool-ml-724788614"></a>
### workerCount

```ml
function workerCount()
```

Return the fixed number of native workers created with this pool.


Source: `std/concurrent/thread_pool.ml:391`

<a id="field-field-std-concurrent-thread-pool-threadpool-workers-workers-std-concurrent-thread-pool-ml-1874553574"></a>
### workers

```ml
workers
```

Workers associated with `ThreadPool`.


Source: `std/concurrent/thread_pool.ml:272`
