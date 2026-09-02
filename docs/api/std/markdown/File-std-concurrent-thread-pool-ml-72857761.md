# `std/concurrent/thread_pool.ml`

[Home](README.md) · [Files](Files.md)

Provides the std concurrent thread_pool package.

Package: [`std.concurrent.thread_pool`](Package-std-concurrent-thread-pool-651855572.md)

Reachable from entry: **no**

## Imports

- `std/threading.ml` as `threading` → [std/threading.ml](File-std-threading-ml-508437988.md)

## Declarations

<a id="constant-constant-std-concurrent-thread-pool-job-cancelled-const-job-cancelled-cancelled-std-concurrent-thread-pool-ml-151839329"></a>
### JOB_CANCELLED

```ml
const JOB_CANCELLED = "Cancelled"
```

Track the job cancelled value used by this standard-library module.


Source: `std/concurrent/thread_pool.ml:24`

<a id="constant-constant-std-concurrent-thread-pool-job-completed-const-job-completed-completed-std-concurrent-thread-pool-ml-1244463415"></a>
### JOB_COMPLETED

```ml
const JOB_COMPLETED = "Completed"
```

Track the job completed value used by this standard-library module.


Source: `std/concurrent/thread_pool.ml:20`

<a id="constant-constant-std-concurrent-thread-pool-job-failed-const-job-failed-failed-std-concurrent-thread-pool-ml-919824707"></a>
### JOB_FAILED

```ml
const JOB_FAILED = "Failed"
```

Track the job failed value used by this standard-library module.


Source: `std/concurrent/thread_pool.ml:22`

<a id="constant-constant-std-concurrent-thread-pool-job-queued-const-job-queued-queued-std-concurrent-thread-pool-ml-897889123"></a>
### JOB_QUEUED

```ml
const JOB_QUEUED = "Queued"
```

Job states are stable strings so callers can persist and compare them.


Source: `std/concurrent/thread_pool.ml:16`

<a id="constant-constant-std-concurrent-thread-pool-job-running-const-job-running-running-std-concurrent-thread-pool-ml-1998481261"></a>
### JOB_RUNNING

```ml
const JOB_RUNNING = "Running"
```

Track the job running value used by this standard-library module.


Source: `std/concurrent/thread_pool.ml:18`

<a id="constant-constant-std-concurrent-thread-pool-max-portable-timeout-ms-const-max-portable-timeout-ms-2147483647-std-concurrent-thread-pool-ml-829161784"></a>
### MAX_PORTABLE_TIMEOUT_MS

```ml
const MAX_PORTABLE_TIMEOUT_MS = 2147483647
```

Track the max portable timeout ms value used by this standard-library module.


Source: `std/concurrent/thread_pool.ml:31`

<a id="constant-constant-std-concurrent-thread-pool-max-workers-const-max-workers-256-std-concurrent-thread-pool-ml-1708862501"></a>
### MAX_WORKERS

```ml
const MAX_WORKERS = 256
```

Track the max workers value used by this standard-library module.


Source: `std/concurrent/thread_pool.ml:27`

<a id="constant-constant-std-concurrent-thread-pool-signal-maximum-const-signal-maximum-2147483647-std-concurrent-thread-pool-ml-1516505488"></a>
### SIGNAL_MAXIMUM

```ml
const SIGNAL_MAXIMUM = 2147483647
```

Track the signal maximum value used by this standard-library module.


Source: `std/concurrent/thread_pool.ml:29`

- [std.concurrent.thread_pool.ThreadPool](Type-std-concurrent-thread-pool-threadpool-1892282200.md) — struct
- [std.concurrent.thread_pool.ThreadPoolJob](Type-std-concurrent-thread-pool-threadpooljob-859238811.md) — struct
