import std.threading as threading
import std.concurrent.thread_pool as threadPool

struct Payload
  value
end struct

function directWorker(data)
  if threadLogicalId() != "direct-worker-2" then
    return error(1640, "logical thread id was not published")
  end if
  gc_collect()
  data.value = data.value + 1
  return data
end function

function zeroArgumentWorker()
  return 7
end function

function poolWorker(data)
  logicalId = threadLogicalId()
  if typeof(logicalId) != "string" or len(logicalId) < 13 then
    return error(1641, "pool worker has no logical id")
  end if
  if data < 0 then return error(1642, "intentional pool failure") end if
  if (data % 5) == 0 then gc_collect() end if
  return Payload(data * data)
end function

function blockingWorker(gate)
  if not gate.waitFor(5000) then return error(1643, "blocking job timed out") end if
  return 123
end function

function waitUntilRunning(job)
  i = 0
  while i < 5000
    if job.GetStatus() == "Running" then return true end if
    threadSleep(1)
    i = i + 1
  end while
  return false
end function

function main(args)
  if typeof(threadLogicalId()) != "void" then return 37 end if

  badZero = try(threadPool.ThreadPool.new(0))
  badMany = try(threadPool.ThreadPool.new(257))
  badCapacity = try(threadPool.ThreadPool.withQueueCapacity(1, -1))
  if typeof(badZero) != "error" or badZero.code != 1630 then return 1 end if
  if typeof(badMany) != "error" or badMany.code != 1630 then return 2 end if
  if typeof(badCapacity) != "error" or badCapacity.code != 1630 then return 3 end if

  // A one-argument entry point receives the exact managed object supplied to
  // Start(). LogicalId is user-defined; Id remains the native Win32 thread id.
  direct = Thread(directWorker, "direct-worker-1")
  if direct.LogicalId() != "direct-worker-1" or direct.Id() != 0 then return 4 end if
  if not direct.SetLogicalId("direct-worker-2") then return 5 end if
  if direct.Start() or direct.Status() != "Created" then return 6 end if
  payload = Payload(41)
  if not direct.Start(payload) or direct.SetLogicalId("too-late") then return 7 end if
  if not direct.Join(10000) or direct.Id() <= 0 then return 8 end if
  if direct.Status() != "Completed" or direct.LogicalId() != "direct-worker-2" then return 9 end if
  directResult = direct.Result()
  if typeof(directResult) != "struct" or directResult.value != 42 or payload.value != 42 then return 10 end if
  if not direct.Close() then return 11 end if

  // Start argument counts are checked in both directions without consuming
  // the Created state after a mismatch.
  zero = Thread(zeroArgumentWorker, "zero-argument-worker")
  if zero.Start(1) or zero.Status() != "Created" then return 33 end if
  if not zero.Start() or not zero.Join(10000) then return 34 end if
  if zero.Result() != 7 then return 35 end if
  if not zero.Close() then return 36 end if

  // Unbounded graceful pool: jobs may allocate and collect concurrently. A
  // returned error belongs to its job and does not kill the reusable worker.
  pool = threadPool.ThreadPool.new(4)
  if pool.WorkerCount() != 4 or pool.IsShutdown() then return 12 end if
  jobs = []
  i = 0
  while i < 40
    job = pool.Submit(poolWorker, i)
    if typeof(job) != "struct" then return 13 end if
    jobs = jobs + [job]
    i = i + 1
  end while
  failed = pool.Submit(poolWorker, -1)
  if typeof(failed) != "struct" then return 14 end if
  gc_collect()
  if not pool.Shutdown() or not pool.IsShutdown() then return 15 end if
  if typeof(pool.Submit(poolWorker, 99)) != "void" then return 16 end if
  if not pool.AwaitTerminationFor(20000) then return 17 end if
  i = 0
  while i < len(jobs)
    if not jobs[i].WaitFor(1000) or jobs[i].GetStatus() != "Completed" then
      print "job " + i + " ended as " + jobs[i].GetStatus()
      wi = 0
      while wi < len(pool.workers)
        print "worker " + wi + " ended as " + pool.workers[wi].Status() + " result=" + pool.workers[wi].Result()
        wi = wi + 1
      end while
      return 18
    end if
    value = jobs[i].GetResult()
    if typeof(value) != "struct" or value.value != i * i then return 19 end if
    if not jobs[i].Dispose() then return 20 end if
    i = i + 1
  end while
  if not failed.WaitFor(1000) or failed.GetStatus() != "Failed" then return 21 end if
  failedResult = try(failed.GetResult())
  if typeof(failedResult) != "error" or not failed.Dispose() then return 22 end if
  if not pool.Dispose() then return 23 end if

  // A bounded queue provides backpressure. Cancellation is reliable while the
  // only worker is occupied by the first job.
  gate = threading.Event.new(true, false)
  bounded = threadPool.ThreadPool.withQueueCapacity(1, 1)
  blocker = bounded.Submit(blockingWorker, gate)
  if typeof(blocker) != "struct" or not waitUntilRunning(blocker) then return 24 end if
  cancelled = bounded.Submit(poolWorker, 5)
  if typeof(cancelled) != "struct" or bounded.PendingCount() != 1 then return 25 end if
  if typeof(bounded.Submit(poolWorker, 6)) != "void" then return 26 end if
  if not cancelled.Cancel() or not cancelled.WaitFor(1000) then return 27 end if
  if cancelled.GetStatus() != "Cancelled" or not cancelled.IsCancelled() then return 28 end if
  if not gate.set() or not blocker.WaitFor(5000) or blocker.GetResult() != 123 then return 29 end if
  if not bounded.ShutdownNow() or not bounded.AwaitTerminationFor(10000) then return 30 end if
  if not blocker.Dispose() or not cancelled.Dispose() then return 31 end if
  if not bounded.Dispose() or not gate.close() then return 32 end if

  // Immediate shutdown cancels work which has not started, while allowing the
  // callback already running on a worker to finish normally.
  immediateGate = threading.Event.new(true, false)
  immediate = threadPool.ThreadPool.withQueueCapacity(1, 2)
  immediateRunning = immediate.Submit(blockingWorker, immediateGate)
  if typeof(immediateRunning) != "struct" or not waitUntilRunning(immediateRunning) then return 38 end if
  immediateQueued = immediate.Submit(poolWorker, 7)
  if typeof(immediateQueued) != "struct" or immediate.PendingCount() != 1 then return 39 end if
  if not immediate.ShutdownNow() then return 40 end if
  if not immediateQueued.WaitFor(1000) or immediateQueued.GetStatus() != "Cancelled" then return 41 end if
  if immediateRunning.Cancel() then return 42 end if
  if not immediateGate.set() or not immediateRunning.WaitFor(5000) then return 43 end if
  if immediateRunning.GetStatus() != "Completed" or immediateRunning.GetResult() != 123 then return 44 end if
  if not immediate.AwaitTerminationFor(10000) then return 45 end if
  if not immediateRunning.Dispose() or not immediateQueued.Dispose() then return 46 end if
  if not immediate.Dispose() or not immediateGate.close() then return 47 end if

  print "[OK] thread arguments, logical ids and managed thread pool"
  return 0
end function
