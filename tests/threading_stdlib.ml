import std.threading as threading
import std.ds.concurrent_list as concurrentList
import std.ds.concurrent_hashmap as concurrentMap

sharedLock = threading.Lock.new()
startGate = threading.Semaphore.new(0, 2)
workerDone = threading.Event.new(true, false)
sharedList = concurrentList.ThreadSafeList.withCapacity(1)
sharedMap = concurrentMap.ThreadSafeHashMap.withCapacity(4)
lockCount = 0

struct SharedPayload
  name
  values
end struct

function concurrentWorker()
  global lockCount
  if not startGate.acquireFor(5000) then
    return error(1630, "worker start gate timed out")
  end if
  i = 0
  while i < 200
    if not sharedList.add("worker-value-" + i) then
      return error(1631, "shared list add failed")
    end if
    if typeof(sharedMap.increment("hits", 1)) != "int" then
      return error(1632, "shared map increment failed")
    end if
    if not sharedMap.set("last-bytes", bytes("payload-" + i)) then
      return error(1633, "shared map set failed")
    end if
    if not sharedLock.acquire() then
      return error(1634, "shared lock acquire failed")
    end if
    lockCount = lockCount + 1
    sharedLock.release()
    i = i + 1
  end while
  workerDone.set()
end function

function main(args)
  badSemaphore = try(threading.Semaphore.new(-1, 1))
  badEvent = try(threading.Event.new(1, false))
  badList = try(concurrentList.ThreadSafeList.withCapacity(-1))
  badMap = try(concurrentMap.ThreadSafeHashMap.withCapacity(-1))
  if typeof(badSemaphore) != "error" or badSemaphore.code != 1601 then return 40 end if
  if typeof(badEvent) != "error" or badEvent.code != 1602 then return 41 end if
  if typeof(badList) != "error" or badList.code != 1610 then return 42 end if
  if typeof(badMap) != "error" or badMap.code != 1620 then return 43 end if

  // Lock: recursive acquire, timeout path and PascalCase aliases.
  localLock = threading.Lock.new()
  if not localLock.Acquire() or not localLock.TryAcquire() then return 1 end if
  if not localLock.Release() or not localLock.Release() then return 2 end if
  if not localLock.close() or localLock.close() then return 3 end if

  // Semaphore and manual-reset event basics.
  sem = threading.Semaphore.new(0, 3)
  if sem.tryAcquire() then return 4 end if
  if not sem.releaseMany(2) then return 5 end if
  if not sem.acquireFor(100) or not sem.acquireFor(100) then return 6 end if
  if sem.tryAcquire() then return 7 end if
  if not sem.close() then return 8 end if

  event = threading.Event.new(true, false)
  if event.tryWait() then return 9 end if
  if not event.set() or not event.waitFor(100) or not event.tryWait() then return 10 end if
  if not event.reset() or event.tryWait() then return 11 end if
  if not event.close() then return 12 end if

  // Full collection API on the main thread, including arbitrary managed values.
  probe = concurrentList.ThreadSafeList.fromArray([1, true, "abc", bytes("xyz")])
  if probe.len() != 4 or probe.get(0) != 1 or not probe.get(1) then return 13 end if
  if probe.get(2) != "abc" or decode(probe.get(3)) != "xyz" then return 14 end if
  if not probe.insert(1, "inserted") or probe.removeAt(1) != "inserted" then return 15 end if
  if not probe.set(0, -7) or probe.first() != -7 or decode(probe.last()) != "xyz" then return 16 end if
  payload = SharedPayload("shared", [1, 2, 3])
  if not probe.add(payload) or probe.get(4).values[2] != 3 then return 17 end if
  if not probe.reserve(64) or probe.toArray()[4].name != "shared" then return 18 end if
  if not probe.close() or probe.add(1) then return 19 end if

  mapProbe = concurrentMap.ThreadSafeHashMap.new()
  if not mapProbe.set(1, "one") or not mapProbe.set("two", bytes("two")) then return 20 end if
  if not mapProbe.set(bytes("three"), true) then return 21 end if
  if mapProbe.get(1) != "one" or decode(mapProbe.get("two")) != "two" then return 22 end if
  if not mapProbe.get(bytes("three")) or mapProbe.count() != 3 then return 23 end if
  if mapProbe.set(true, 1) or not mapProbe.set("object", payload) then return 24 end if
  if mapProbe.get("object").values[0] != 1 then return 44 end if
  if mapProbe.increment("counter", 4) != 4 or mapProbe.increment("counter", -1) != 3 then return 25 end if
  if not mapProbe.has("counter") or not mapProbe.delete(1) or mapProbe.has(1) then return 26 end if
  if len(mapProbe.keysArray()) != 4 or len(mapProbe.valuesArray()) != 4 or len(mapProbe.entriesArray()) != 4 then return 27 end if
  if not mapProbe.clear() or not mapProbe.isEmpty() or not mapProbe.close() then return 28 end if

  // Two real workers concurrently mutate managed containers in the global heap.
  a = Thread(concurrentWorker)
  b = Thread(concurrentWorker)
  if not a.Start() or not b.Start() then return 29 end if
  if not startGate.releaseMany(2) then return 30 end if
  if not workerDone.waitFor(5000) then return 31 end if
  if not a.Join(10000) or not b.Join(10000) then return 32 end if
  if a.Status() != "Completed" or b.Status() != "Completed" then return 33 end if
  if sharedList.count() != 400 or sharedMap.get("hits") != 400 or lockCount != 400 then return 34 end if
  if typeof(sharedList.get(0)) != "string" then return 35 end if
  lastBytes = sharedMap.get("last-bytes")
  if typeof(lastBytes) != "bytes" or len(lastBytes) < 9 then return 36 end if
  if not a.Close() or not b.Close() then return 37 end if

  if not sharedList.close() or not sharedMap.close() then return 38 end if
  if not workerDone.close() or not startGate.close() or not sharedLock.close() then return 39 end if

  print "[OK] thread-safe stdlib collections and synchronization primitives"
  return 0
end function
