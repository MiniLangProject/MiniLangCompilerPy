/// Publication boundaries retire handoffs, including indirect GC and idle workers.
import std.concurrent.thread_pool as pools
synchronized idleReady = false
synchronized idleExit = false

function makeGarbage()
  graph = [bytes(8 * 1024 * 1024, 17)]
  return graph[0][0]
end function

function idleWorker()
  global idleReady, idleExit
  makeGarbage()
  idleReady = true
  while not idleExit
    threadSleep(1)
  end while
end function

function makePoolResult(ignored)
  return bytes(8 * 1024 * 1024, 29)
end function

function completedJob(pool)
  job = pool.submit(makePoolResult, 0)
  if not job.waitFor(10000) then return false end if
  if job.getResult()[0] != 29 then return false end if
  // Keep only native-resource wrappers for explicit cleanup, not the job.
  // Calling job.close() here would clear its result and mask a worker that
  // accidentally retains the completed job while waiting for more work.
  return [job.done, job.guard]
end function

/// Allow a signalled worker to publish its native wait without timing assumptions.
function collectBelow(limit)
  for attempt = 0 to 999
    gc_collect()
    if gc_stat(1) <= limit then return true end if
    threadSleep(1)
  end for
  return false
end function

function main(args)
  global idleReady, idleExit
  gc_collect()
  baseline = gc_stat(1)
  makeGarbage()
  gc_collect()
  if gc_stat(1) > baseline + 4096 then return 1 end if
  makeGarbage()
  collect = gc_collect
  collect()
  if gc_stat(1) > baseline + 4096 then return 2 end if
  worker = Thread(idleWorker)
  if not worker.Start() then return 3 end if
  for i = 0 to 9999
    if idleReady then break end if
    threadSleep(1)
  end for
  if not idleReady or not collectBelow(baseline + 16384) then return 4 end if
  idleExit = true
  if not worker.Join(10000) or not worker.Close() then return 5 end if
  pool = pools.ThreadPool.new(1)
  handles = completedJob(pool)
  if typeof(handles) != "array" then return 6 end if
  if not collectBelow(baseline + 65536) then return 7 end if
  if not handles[0].close() or not handles[1].close() then return 9 end if
  if not pool.close() then return 8 end if
  print "GC HANDOFF LIFETIME [OK]"
  return 0
end function
