/*
   Copyright 2026 Nils Kopal
   Licensed under the Apache License, Version 2.0.
*/

//! Provides the std concurrent task package.

package std.concurrent.task

import std.concurrent.cancellation as cancellation
import std.concurrent.thread_pool as threadPool

/// Track the task error value used by this standard-library module.
const TASK_ERROR = 1651

/// Represents cancellable call.
struct CancellableCall
  /// Callback associated with `CancellableCall`.
  callback
  /// Backing data owned by `CancellableCall`.
  data
  /// Token associated with `CancellableCall`.
  token
end struct

/// Internal adapter keeps the ordinary thread-pool callback ABI unchanged.
/// @internal
function _runCancellable(call)
  if call.token.IsCancellationRequested() then
    return error(cancellation.CANCELLED_ERROR, "task cancelled before execution")
  end if
  return call.callback(call.data, call.token)
end function

/// Future is a stable managed handle around a ThreadPoolJob and, optionally, a cooperative cancellation source. Result values remain rooted by the job.
struct Future
  /// Job associated with `Future`.
  job
  /// Cancellation source associated with `Future`.
  cancellationSource
  /// Closed associated with `Future`.
  closed

  /// Blocks until this task completes.
  function wait()
    if this.closed then return false end if
    return this.job.Wait()
  end function

  /// Waits up to a bounded duration for this task to complete.
  /// @param milliseconds Maximum duration in milliseconds.
  function waitFor(milliseconds)
    if this.closed then return false end if
    return this.job.WaitFor(milliseconds)
  end function

  /// Provide status behavior for this standard-library module.
  function status()
    if this.closed then return "Closed" end if
    return this.job.GetStatus()
  end function

  /// Reports whether is done.
  function isDone()
    if this.closed then return true end if
    return this.job.IsDone()
  end function

  /// Provide result behavior for this standard-library module.
  function result()
    if this.closed then return error(TASK_ERROR, "future is closed") end if
    if not this.job.IsDone() then return error(TASK_ERROR, "future is not complete") end if
    return this.job.GetResult()
  end function

  /// Queued work is removed directly; running work receives a cooperative token.
  function cancel()
    if this.closed then return false end if
    requested = false
    if typeof(this.cancellationSource) == "struct" then
      requested = this.cancellationSource.Cancel()
    end if
    if this.job.Cancel() then requested = true end if
    return requested
  end function

  /// Releases the completed task's synchronization resources.
  function close()
    if this.closed or not this.job.IsDone() then return false end if
    jobOk = this.job.Dispose()
    sourceOk = true
    if typeof(this.cancellationSource) == "struct" then
      sourceOk = this.cancellationSource.Dispose()
    end if
    if jobOk and sourceOk then this.closed = true end if
    return jobOk and sourceOk
  end function

  /// Exposes task completion waiting through a PascalCase alias.
  function Wait() return this.wait() end function
  /// Exposes timed task waiting through a PascalCase alias.
  /// @param milliseconds Maximum duration in milliseconds.
  function WaitFor(milliseconds) return this.waitFor(milliseconds) end function
  /// Thread reserves PascalCase Status/Result/Close at the language level; Future intentionally keeps those three operations lowercase.
  function IsDone() return this.isDone() end function
  /// Reports whether cancel.
  function Cancel() return this.cancel() end function
  /// Disposes this task through its PascalCase alias.
  function Dispose() return this.close() end function
end struct

/// Schedule a conventional one-argument callback on an existing pool.
/// @param pool Value supplied for `pool`.
/// @param callback Value supplied for `callback`.
/// @param data Data to process.
function run(pool, callback, data)
  job = pool.Submit(callback, data)
  if typeof(job) != "struct" then return error(TASK_ERROR, "task was rejected") end if
  return Future(job, void, false)
end function

/// Schedule callback(data, token) and return a future which can request cancel.
/// @param pool Value supplied for `pool`.
/// @param callback Value supplied for `callback`.
/// @param data Data to process.
function runCancellable(pool, callback, data)
  source = cancellation.CancellationTokenSource.new()
  call = CancellableCall(callback, data, source.Token())
  job = pool.Submit(_runCancellable, call)
  if typeof(job) != "struct" then
    source.Dispose()
    return error(TASK_ERROR, "task was rejected")
  end if
  return Future(job, source, false)
end function

/// Wait for every future in input order and return the equally ordered results.
/// @param futures Value supplied for `futures`.
function whenAll(futures)
  if typeof(futures) != "array" then return error(TASK_ERROR, "whenAll expects an array") end if
  results = array(len(futures))
  i = 0
  while i < len(futures)
    future = futures[i]
    if future is not Future then return error(TASK_ERROR, "whenAll expects Future values") end if
    if not future.wait() then return error(TASK_ERROR, "future wait failed") end if
    results[i] = future.result()
    i = i + 1
  end while
  return results
end function

/// Return the first completed future index, or -1 after the timeout. A negative timeout waits indefinitely; zero performs a non-blocking observation.
/// @param futures Value supplied for `futures`.
/// @param milliseconds Maximum duration in milliseconds.
function whenAnyFor(futures, milliseconds)
  if typeof(futures) != "array" or len(futures) == 0 then return error(TASK_ERROR, "whenAny expects a non-empty array") end if
  if typeof(milliseconds) != "int" then return error(TASK_ERROR, "whenAny timeout must be an integer") end if
  elapsed = 0
  while milliseconds < 0 or elapsed <= milliseconds
    i = 0
    while i < len(futures)
      future = futures[i]
      if future is not Future then return error(TASK_ERROR, "whenAny expects Future values") end if
      if future.isDone() then return i end if
      i = i + 1
    end while
    if elapsed == milliseconds then return -1 end if
    threadSleep(1)
    elapsed = elapsed + 1
  end while
  return -1
end function

/// Provide the when any operation for this standard-library module.
/// @param futures Value supplied for `futures`.
function whenAny(futures)
  return whenAnyFor(futures, -1)
end function
