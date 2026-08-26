/*
   Copyright 2026 Nils Kopal
   Licensed under the Apache License, Version 2.0.
*/

package std.concurrent.thread_pool

import std.threading as threading

// Managed worker pool with optional queue backpressure. Jobs, callbacks and
// results stay in the process-wide GC heap; the native workers only own stacks.

// Job states are stable strings so callers can persist and compare them.
const JOB_QUEUED = "Queued"
const JOB_RUNNING = "Running"
const JOB_COMPLETED = "Completed"
const JOB_FAILED = "Failed"
const JOB_CANCELLED = "Cancelled"

const MAX_WORKERS = 256
const SIGNAL_MAXIMUM = 0x7FFFFFFF

// Handle for one submitted callback and its eventual result.
struct ThreadPoolJob
  guard
  done
  callback
  data
  status
  result
  closed

  // Create a queued job owned by the pool until it reaches a terminal state.
  static function new(callback, data)
    guard = threading.Lock.new()
    done = threading.Event.new(true, false)
    return ThreadPoolJob(
      guard,
      done,
      callback,
      data,
      JOB_QUEUED,
      void,
      false
    )
  end function

  // Atomically claim a queued job for exactly one worker.
  function _begin()
    if not this.guard.acquire() then return false end if
    ok = false
    if not this.closed and this.status == JOB_QUEUED then
      this.status = JOB_RUNNING
      ok = true
    end if
    this.guard.release()
    return ok
  end function

  // Run the callback and publish either its value or captured error.
  function _execute()
    callback = this.callback
    data = this.data
    value = try(callback(data))
    if not this.guard.acquire() then return false end if
    if this.closed or this.status != JOB_RUNNING then
      this.guard.release()
      return false
    end if
    this.result = value
    if typeof(value) == "error" then
      this.status = JOB_FAILED
    else
      this.status = JOB_COMPLETED
    end if
    this.callback = void
    this.data = void
    this.guard.release()
    this.done.set()
    return true
  end function

  // Cancel a job only while it is still queued.
  function cancel()
    if not this.guard.acquire() then return false end if
    if this.closed or this.status != JOB_QUEUED then
      this.guard.release()
      return false
    end if
    this.status = JOB_CANCELLED
    this.callback = void
    this.data = void
    this.guard.release()
    this.done.set()
    return true
  end function

  // Wait indefinitely for a terminal job state.
  function wait()
    if this.closed then return false end if
    return this.done.wait()
  end function

  // Wait up to the requested number of milliseconds.
  function waitFor(milliseconds)
    if this.closed then return false end if
    return this.done.waitFor(milliseconds)
  end function

  // Return a stable JOB_* status snapshot under the job lock.
  function getStatus()
    if not this.guard.acquire() then return JOB_FAILED end if
    value = this.status
    this.guard.release()
    return value
  end function

  // Return the callback result; failures are represented as error values.
  function getResult()
    if not this.guard.acquire() then return end if
    value = this.result
    this.guard.release()
    return value
  end function

  // Report whether the job reached any terminal state.
  function isDone()
    value = this.getStatus()
    return value == JOB_COMPLETED or value == JOB_FAILED or value == JOB_CANCELLED
  end function

  // Report whether cancellation won before execution started.
  function isCancelled()
    return this.getStatus() == JOB_CANCELLED
  end function

  // Release synchronization handles after the job has finished.
  function close()
    if not this.guard.acquire() then return false end if
    // Inspect the terminal state while guard is already held. Avoiding a
    // nested acquisition keeps disposal independent of recursive-lock details
    // and gives every platform one straightforward lock/unlock pair.
    terminal = this.status == JOB_COMPLETED or this.status == JOB_FAILED or this.status == JOB_CANCELLED
    if this.closed or not terminal then
      this.guard.release()
      return false
    end if
    this.closed = true
    this.callback = void
    this.data = void
    this.result = void
    this.guard.release()
    doneOk = this.done.close()
    guardOk = this.guard.close()
    return doneOk and guardOk
  end function

  // PascalCase aliases mirror the native Thread API naming style.
  function Cancel() return this.cancel() end function
  function Wait() return this.wait() end function
  function WaitFor(milliseconds) return this.waitFor(milliseconds) end function
  function GetStatus() return this.getStatus() end function
  function GetResult() return this.getResult() end function
  function IsDone() return this.isDone() end function
  function IsCancelled() return this.isCancelled() end function
  function Dispose() return this.close() end function
end struct

// Workers exit only after shutdown was requested and the queue is drained.
function _poolIsStopping(pool)
  if not pool.guard.acquire() then return true end if
  value = pool.stopping and pool.queuedCount == 0
  pool.guard.release()
  return value
end function

// Compact an already-locked queue after enough consumed slots accumulate.
function _poolCompactLocked(pool)
  if pool.queueHead < 64 or pool.queueHead * 2 < len(pool.queue) then return end if
  remaining = pool.queuedCount
  compacted = array(remaining)
  i = 0
  while i < remaining
    compacted[i] = pool.queue[pool.queueHead + i]
    i = i + 1
  end while
  pool.queue = compacted
  pool.queueHead = 0
end function

// Remove and return one queued job while preserving FIFO order.
function _poolTake(pool)
  if not pool.guard.acquire() then return end if
  job = void
  if pool.queuedCount > 0 then
    job = pool.queue[pool.queueHead]
    pool.queue[pool.queueHead] = 0
    pool.queueHead = pool.queueHead + 1
    pool.queuedCount = pool.queuedCount - 1
    _poolCompactLocked(pool)
  end if
  pool.guard.release()
  return job
end function

// Native worker entrypoint shared by all threads in a pool.
function _threadPoolWorker(pool)
  while true
    if not pool.signal.acquire() then return end if
    job = _poolTake(pool)
    if typeof(job) == "void" then
      if _poolIsStopping(pool) then return end if
    else
      if job._begin() then
        job._execute()
      end if
    end if
  end while
end function

// Fixed-size worker set backed by an optionally bounded FIFO queue.
struct ThreadPool
  guard
  signal
  workers
  queue
  queueHead
  queuedCount
  queueCapacity
  accepting
  stopping
  stopped
  closed

  // Create an unbounded pool with workerCount native workers.
  static function new(workerCount)
    return ThreadPool.withQueueCapacity(workerCount, 0)
  end function

  // Create a pool whose zero capacity means an unbounded pending queue.
  static function withQueueCapacity(workerCount, queueCapacity)
    if typeof(workerCount) != "int" or workerCount <= 0 or workerCount > MAX_WORKERS then
      return error(1630, "thread-pool worker count must be between 1 and 256")
    end if
    if typeof(queueCapacity) != "int" or queueCapacity < 0 then
      return error(1630, "thread-pool queue capacity must be a non-negative integer")
    end if

    pool = ThreadPool(
      threading.Lock.new(),
      threading.Semaphore.new(0, SIGNAL_MAXIMUM),
      [],
      [],
      0,
      0,
      queueCapacity,
      true,
      false,
      false,
      false
    )

    i = 0
    while i < workerCount
      worker = Thread(_threadPoolWorker, "thread-pool-" + i)
      pool.workers = pool.workers + [worker]
      if not worker.Start(pool) then
        pool.accepting = false
        pool.stopping = true
        pool.signal.releaseMany(len(pool.workers))
        j = 0
        while j < len(pool.workers)
          pool.workers[j].Join(5000)
          pool.workers[j].Close()
          j = j + 1
        end while
        pool.signal.close()
        pool.guard.close()
        return error(1630, "could not start a thread-pool worker")
      end if
      i = i + 1
    end while
    return pool
  end function

  // Queue a callback and return its job handle, or void when rejected.
  function submit(callback, data)
    job = ThreadPoolJob.new(callback, data)
    if not this.guard.acquire() then return end if
    if this.closed or not this.accepting then
      this.guard.release()
      job.cancel()
      job.close()
      return
    end if
    if this.queueCapacity > 0 and this.queuedCount >= this.queueCapacity then
      this.guard.release()
      job.cancel()
      job.close()
      return
    end if
    this.queue = this.queue + [job]
    this.queuedCount = this.queuedCount + 1
    this.guard.release()
    if not this.signal.release() then
      job.cancel()
      return
    end if
    return job
  end function

  // Return the number of jobs that have not yet been claimed by workers.
  function pendingCount()
    if not this.guard.acquire() then return 0 end if
    value = this.queuedCount
    this.guard.release()
    return value
  end function

  // Return the fixed number of native workers created with this pool.
  function workerCount()
    return len(this.workers)
  end function

  // Report whether the pool has stopped accepting new jobs.
  function isShutdown()
    if not this.guard.acquire() then return true end if
    value = not this.accepting
    this.guard.release()
    return value
  end function

  // Stop accepting jobs and drain the existing queue before worker exit.
  function shutdown()
    if not this.guard.acquire() then return false end if
    if this.closed or this.stopping then
      this.guard.release()
      return false
    end if
    this.accepting = false
    this.stopping = true
    count = len(this.workers)
    this.guard.release()
    return this.signal.releaseMany(count)
  end function

  // Stop accepting jobs and cancel every job that is still queued.
  function stop()
    if not this.guard.acquire() then return false end if
    if this.closed or this.stopping then
      this.guard.release()
      return false
    end if
    this.accepting = false
    this.stopping = true
    i = this.queueHead
    while i < len(this.queue)
      job = this.queue[i]
      if typeof(job) != "void" then job.cancel() end if
      this.queue[i] = 0
      i = i + 1
    end while
    this.queueHead = len(this.queue)
    this.queuedCount = 0
    count = len(this.workers)
    this.guard.release()
    return this.signal.releaseMany(count)
  end function

  // Wait indefinitely for all workers after shutdown has begun.
  function join()
    return this.joinFor(0xFFFFFFFF)
  end function

  // Wait for each worker with the supplied per-worker timeout.
  function joinFor(milliseconds)
    if typeof(milliseconds) != "int" or milliseconds < 0 then return false end if
    if not this.isShutdown() then return false end if
    i = 0
    while i < len(this.workers)
      if not this.workers[i].Join(milliseconds) then return false end if
      i = i + 1
    end while
    if not this.guard.acquire() then return false end if
    this.stopped = true
    this.guard.release()
    return true
  end function

  // Shut down, join and release all worker and synchronization handles.
  function close()
    if this.closed then return false end if
    if not this.isShutdown() then this.shutdown() end if
    if not this.join() then return false end if
    i = 0
    while i < len(this.workers)
      if not this.workers[i].Close() then return false end if
      i = i + 1
    end while
    this.workers = []
    this.queue = []
    this.closed = true
    signalOk = this.signal.close()
    guardOk = this.guard.close()
    return signalOk and guardOk
  end function

  // PascalCase aliases provide the conventional pool API surface.
  function Submit(callback, data) return this.submit(callback, data) end function
  function PendingCount() return this.pendingCount() end function
  function WorkerCount() return this.workerCount() end function
  function IsShutdown() return this.isShutdown() end function
  function Shutdown() return this.shutdown() end function
  function ShutdownNow() return this.stop() end function
  function AwaitTermination() return this.join() end function
  function AwaitTerminationFor(milliseconds) return this.joinFor(milliseconds) end function
  function Dispose() return this.close() end function
end struct
