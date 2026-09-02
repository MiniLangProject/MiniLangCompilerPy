# `std.concurrent.thread_pool.ThreadPoolJob`

[Home](README.md) · [Source file](File-std-concurrent-thread-pool-ml-72857761.md)

<a id="struct-struct-std-concurrent-thread-pool-threadpooljob-struct-threadpooljob-std-concurrent-thread-pool-ml-1808188346"></a>
## ThreadPoolJob

```ml
struct ThreadPoolJob
```

Handle for one submitted callback and its eventual result.


Source: `std/concurrent/thread_pool.ml:34`

## Members

<a id="field-field-std-concurrent-thread-pool-threadpooljob-callback-callback-std-concurrent-thread-pool-ml-1304300451"></a>
### callback

```ml
callback
```

Stores the callback member of `ThreadPoolJob`.


Source: `std/concurrent/thread_pool.ml:40`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-cancel-function-cancel-std-concurrent-thread-pool-ml-1381498503"></a>
### Cancel

```ml
function Cancel()
```

PascalCase aliases mirror the native Thread API naming style.


Source: `std/concurrent/thread_pool.ml:181`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-cancel-function-cancel-std-concurrent-thread-pool-ml-1078125767"></a>
### cancel

```ml
function cancel()
```

Cancel a job only while it is still queued.


Source: `std/concurrent/thread_pool.ml:105`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-close-function-close-std-concurrent-thread-pool-ml-957207643"></a>
### close

```ml
function close()
```

Release synchronization handles after the job has finished.


Source: `std/concurrent/thread_pool.ml:160`

<a id="field-field-std-concurrent-thread-pool-threadpooljob-closed-closed-std-concurrent-thread-pool-ml-1318207521"></a>
### closed

```ml
closed
```

Stores the closed member of `ThreadPoolJob`.


Source: `std/concurrent/thread_pool.ml:48`

<a id="field-field-std-concurrent-thread-pool-threadpooljob-data-data-std-concurrent-thread-pool-ml-5830593"></a>
### data

```ml
data
```

Stores the data member of `ThreadPoolJob`.


Source: `std/concurrent/thread_pool.ml:42`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-dispose-function-dispose-std-concurrent-thread-pool-ml-689250869"></a>
### Dispose

```ml
function Dispose()
```

Implements dispose.


Source: `std/concurrent/thread_pool.ml:196`

<a id="field-field-std-concurrent-thread-pool-threadpooljob-done-done-std-concurrent-thread-pool-ml-1526394129"></a>
### done

```ml
done
```

Stores the done member of `ThreadPoolJob`.


Source: `std/concurrent/thread_pool.ml:38`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-getresult-function-getresult-std-concurrent-thread-pool-ml-1209365721"></a>
### GetResult

```ml
function GetResult()
```

Returns get result.


Source: `std/concurrent/thread_pool.ml:190`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-getresult-function-getresult-std-concurrent-thread-pool-ml-1087002137"></a>
### getResult

```ml
function getResult()
```

Return the callback result; failures are represented as error values.


Source: `std/concurrent/thread_pool.ml:141`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-getstatus-function-getstatus-std-concurrent-thread-pool-ml-1285725111"></a>
### GetStatus

```ml
function GetStatus()
```

Returns get status.


Source: `std/concurrent/thread_pool.ml:188`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-getstatus-function-getstatus-std-concurrent-thread-pool-ml-223169015"></a>
### getStatus

```ml
function getStatus()
```

Return a stable JOB_* status snapshot under the job lock.


Source: `std/concurrent/thread_pool.ml:133`

<a id="field-field-std-concurrent-thread-pool-threadpooljob-guard-guard-std-concurrent-thread-pool-ml-435468325"></a>
### guard

```ml
guard
```

Stores the guard member of `ThreadPoolJob`.


Source: `std/concurrent/thread_pool.ml:36`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-iscancelled-function-iscancelled-std-concurrent-thread-pool-ml-1595104197"></a>
### IsCancelled

```ml
function IsCancelled()
```

Reports whether is cancelled.


Source: `std/concurrent/thread_pool.ml:194`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-iscancelled-function-iscancelled-std-concurrent-thread-pool-ml-502201925"></a>
### isCancelled

```ml
function isCancelled()
```

Report whether cancellation won before execution started.


Source: `std/concurrent/thread_pool.ml:155`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-isdone-function-isdone-std-concurrent-thread-pool-ml-666330559"></a>
### IsDone

```ml
function IsDone()
```

Reports whether is done.


Source: `std/concurrent/thread_pool.ml:192`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-isdone-function-isdone-std-concurrent-thread-pool-ml-1101974527"></a>
### isDone

```ml
function isDone()
```

Report whether the job reached any terminal state.


Source: `std/concurrent/thread_pool.ml:149`

<a id="static_method-static-method-std-concurrent-thread-pool-threadpooljob-new-static-function-new-callback-data-std-concurrent-thread-pool-ml-1751013359"></a>
### new

```ml
static function new(callback, data)
```

Create a queued job owned by the pool until it reaches a terminal state.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `callback` | `dynamic` | — | Value supplied for `callback`. |
| `data` | `dynamic` | — | Data to process. |


Source: `std/concurrent/thread_pool.ml:53`

<a id="field-field-std-concurrent-thread-pool-threadpooljob-result-result-std-concurrent-thread-pool-ml-215005431"></a>
### result

```ml
result
```

Stores the result member of `ThreadPoolJob`.


Source: `std/concurrent/thread_pool.ml:46`

<a id="field-field-std-concurrent-thread-pool-threadpooljob-status-status-std-concurrent-thread-pool-ml-1156362669"></a>
### status

```ml
status
```

Stores the status member of `ThreadPoolJob`.


Source: `std/concurrent/thread_pool.ml:44`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-wait-function-wait-std-concurrent-thread-pool-ml-1518778939"></a>
### Wait

```ml
function Wait()
```

Implements wait.


Source: `std/concurrent/thread_pool.ml:183`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-wait-function-wait-std-concurrent-thread-pool-ml-60910587"></a>
### wait

```ml
function wait()
```

Wait indefinitely for a terminal job state.


Source: `std/concurrent/thread_pool.ml:120`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-waitfor-function-waitfor-milliseconds-std-concurrent-thread-pool-ml-1383667777"></a>
### WaitFor

```ml
function WaitFor(milliseconds)
```

Implements wait for.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/thread_pool.ml:186`

<a id="method-method-std-concurrent-thread-pool-threadpooljob-waitfor-function-waitfor-milliseconds-std-concurrent-thread-pool-ml-378084097"></a>
### waitFor

```ml
function waitFor(milliseconds)
```

Wait up to the requested number of milliseconds.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/thread_pool.ml:127`
