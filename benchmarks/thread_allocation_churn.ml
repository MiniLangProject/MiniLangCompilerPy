/* Parallel short-lived allocation benchmark for server-style object churn. */

extern function GetTickCount64() from "kernel32.dll" returns u64

synchronized workersReady = 0
synchronized startWorkers = false

struct ChurnNode
  values
  tag
end struct

struct ChurnTask
  iterations
  seed
end struct

struct ChurnResult
  checksum
  liveRing
  count
end struct

function synchronized signalReady()
  global workersReady
  workersReady = workersReady + 1
end function

function churnWorker(task)
  signalReady()
  while not startWorkers
    threadSleep(0)
  end while

  // The bounded ring makes allocations observable while allowing old entries
  // to become garbage, similar to per-request temporary object graphs.
  liveRing = array(256, void)
  checksum = 0
  for index = 0 to task.iterations - 1
    node = ChurnNode([task.seed + index, index, index + 1], index)
    liveRing[index % 256] = node
    checksum = checksum + (node.values[0] % 251) + (node.values[2] % 241)
  end for
  return ChurnResult(checksum, liveRing, task.iterations)
end function

function selectedThreadCount(args)
  if len(args) == 0 then return 12 end if
  if args[0] == "1" then return 1 end if
  if args[0] == "2" then return 2 end if
  if args[0] == "4" then return 4 end if
  if args[0] == "8" then return 8 end if
  if args[0] == "12" then return 12 end if
  if args[0] == "24" then return 24 end if
  return 0
end function

function main(args)
  global startWorkers
  threadCount = selectedThreadCount(args)
  if threadCount == 0 then return 10 end if

  iterations = 1000000
  threads = array(threadCount, void)
  for index = 0 to threadCount - 1
    threads[index] = Thread(churnWorker, "churn-" + index)
    task = ChurnTask(iterations, (index + 1) * 1000003)
    if not threads[index].Start(task) then return 11 end if
  end for

  while workersReady != threadCount
    threadSleep(0)
  end while

  started = GetTickCount64()
  startWorkers = true

  checksum = 0
  for index = 0 to threadCount - 1
    if not threads[index].Join(120000) then return 12 end if
    if threads[index].Status() != "Completed" then return 13 end if
    result = threads[index].Result()
    if result.count != iterations or len(result.liveRing) != 256 then return 15 end if
    checksum = checksum + result.checksum
    if not threads[index].Close() then return 14 end if
  end for
  elapsed = GetTickCount64() - started

  gc_collect()
  print "threads=" + threadCount
  print "iterations_per_thread=" + iterations
  print "allocations=" + (threadCount * iterations * 2)
  print "elapsed_ms=" + elapsed
  print "checksum=" + checksum
  print "heap_used_after_gc=" + heap_bytes_used()
  print "heap_committed=" + heap_bytes_committed()
  return 0
end function
