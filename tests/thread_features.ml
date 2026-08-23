synchronized sharedCount = 0
synchronized synchronizedCount = 0
synchronized sharedHeapCount = 0
synchronized unwindCount = 0
synchronized heapPublishCount = 0
synchronized stringificationFailures = 0
synchronized sharedText = ""
synchronized publishedObjects = []

struct PublishedBox
  number
  payload
end struct

struct StringifyTask
  value
  expected
end struct

function synchronized bumpSynchronizedFunction()
  global synchronizedCount
  synchronizedCount = synchronizedCount + 1
end function

function worker()
  global sharedCount, sharedHeapCount
  scratch = array(2048, 7)
  if len(scratch) == 2048 and heap_bytes_used() > 0 and heap_bytes_committed() >= 16777216 and heap_bytes_reserved() >= heap_bytes_committed() then
    sharedHeapCount = sharedHeapCount + 1
  end if
  i = 0
  while i < 5000
    sharedCount = sharedCount + 1
    bumpSynchronizedFunction()
    i = i + 1
  end while
end function

function spinner()
  while true
    threadSleep(1)
  end while
end function

function failingWorker()
  return error(999, "worker failed")
end function

function synchronized returnsSynchronizedError()
  return error(998, "expected synchronized function error")
end function

function catchesSynchronizedError()
  caught = try(returnsSynchronizedError())
end function

function incrementsAfterError()
  global unwindCount
  unwindCount = unwindCount + 1
end function

function assignsHeapToSynchronizedGlobal()
  global sharedText
  sharedText = "heap objects are process-wide"
end function

function verifiesHeapValuePublication()
  global heapPublishCount, sharedText
  assignsHeapToSynchronizedGlobal()
  if sharedText == "heap objects are process-wide" then
    heapPublishCount = heapPublishCount + 1
  end if
end function

function synchronized publishObject(value)
  global publishedObjects
  publishedObjects = publishedObjects + [value]
end function

function objectPublisher()
  value = PublishedBox(42, ["survives", bytes([1, 2, 3, 4])])
  publishObject(value)
  // Exercise stop-the-world collection while another OS thread owns the main stack.
  for i = 0 to 2000
    garbage = [i, "temporary-" + i]
    if (i % 100) == 0 then gc_collect() end if
  end for
  gc_collect()
end function

function synchronized printFromWorker()
  print "[OK] synchronized worker output"
end function

function outputWorker()
  printFromWorker()
end function

function synchronized recordStringificationFailure()
  global stringificationFailures
  stringificationFailures = stringificationFailures + 1
end function

function stringifyWorker(task)
  for iteration = 0 to 9999
    actual = "table-t" + task.value + ".tbl"
    if actual != task.expected then
      recordStringificationFailure()
      return
    end if
  end for
end function

function main(args)
  neverStarted = Thread(worker)
  if neverStarted.Status() != "Created" then return 1 end if
  if neverStarted.IsAlive() then return 2 end if
  if neverStarted.Join(0) then return 3 end if
  if neverStarted.Stop() then return 4 end if

  a = Thread(worker)
  b = Thread(worker)
  if typeof(a) != "thread" or typeName(a) != "thread" then return 5 end if
  if not a.Start() or not b.Start() then return 6 end if
  if a.Id() <= 0 or b.Id() <= 0 then return 7 end if
  if a.Start() then return 8 end if
  if not a.Join() or not b.Join() then return 9 end if
  if sharedCount != 10000 then return 10 end if
  if synchronizedCount != 10000 then return 11 end if
  if sharedHeapCount != 2 then return 12 end if
  if a.Status() != "Completed" or b.Status() != "Completed" then return 13 end if
  if a.IsAlive() or b.IsAlive() then return 14 end if
  if a.Start() then return 25 end if
  if a.Status() != "Completed" then return 26 end if
  if not a.Close() or a.Close() then return 15 end if

  spin = Thread(spinner)
  if not spin.Start() then return 16 end if
  if spin.Join(1) then return 17 end if
  if not spin.Stop() then return 18 end if
  if not spin.Join() then return 19 end if
  if spin.Status() != "Stopped" or spin.IsAlive() then return 20 end if
  if not spin.Close() then return 21 end if

  failed = Thread(failingWorker)
  if not failed.Start() or not failed.Join() then return 22 end if
  if failed.Status() != "Failed" or failed.IsAlive() then return 23 end if
  if not failed.Close() then return 24 end if

  unwind = Thread(catchesSynchronizedError)
  if not unwind.Start() or not unwind.Join() then return 27 end if
  afterError = Thread(incrementsAfterError)
  if not afterError.Start() or not afterError.Join(1000) then return 28 end if
  if unwindCount != 1 then return 29 end if
  if not unwind.Close() or not afterError.Close() then return 30 end if

  heapPublish = Thread(verifiesHeapValuePublication)
  if not heapPublish.Start() or not heapPublish.Join() then return 31 end if
  if heapPublish.Status() != "Completed" or heapPublishCount != 1 then return 32 end if
  if not heapPublish.Close() then return 33 end if

  for publicationRound = 0 to 9
    publisher = Thread(objectPublisher)
    publisher2 = Thread(objectPublisher)
    if not publisher.Start() or not publisher2.Start() then return 36 end if
    if not publisher.Join() or not publisher2.Join() then return 37 end if
    if publisher.Status() != "Completed" or publisher2.Status() != "Completed" then return 38 end if
    expectedPublishedLength = (publicationRound + 1) * 2
    publishedLengthBeforeGc = len(publishedObjects)
    if publishedLengthBeforeGc != expectedPublishedLength then
      print "[FAIL] published object count before main GC"
      print publishedLengthBeforeGc
      return 43
    end if
    publishedBeforeGc = publishedObjects[publishedLengthBeforeGc - 1]
    if publishedBeforeGc.number != 42 then return 44 end if
    gc_collect()
    publishedLength = len(publishedObjects)
    if publishedLength != expectedPublishedLength then
      print "[FAIL] published object count"
      print publishedLength
      return 39
    end if
    published = publishedObjects[publishedLength - 1]
    if published.number != 42 or published.payload[0] != "survives" then return 40 end if
    if len(published.payload[1]) != 4 or published.payload[1][3] != 4 then return 41 end if
    if not publisher.Close() or not publisher2.Close() then return 42 end if
  end for

  output = Thread(outputWorker)
  if not output.Start() or not output.Join() then return 34 end if
  if output.Status() != "Completed" or not output.Close() then return 35 end if

  stringifyThreads = [
    Thread(stringifyWorker), Thread(stringifyWorker), Thread(stringifyWorker), Thread(stringifyWorker),
    Thread(stringifyWorker), Thread(stringifyWorker), Thread(stringifyWorker), Thread(stringifyWorker)
  ]
  stringifyTasks = [
    StringifyTask(21, "table-t21.tbl"), StringifyTask(62, "table-t62.tbl"),
    StringifyTask(105, "table-t105.tbl"), StringifyTask(-7, "table-t-7.tbl"),
    StringifyTask(4096, "table-t4096.tbl"), StringifyTask(99991, "table-t99991.tbl"),
    StringifyTask(-123456, "table-t-123456.tbl"), StringifyTask(7000001, "table-t7000001.tbl")
  ]
  for index = 0 to 7
    if not stringifyThreads[index].Start(stringifyTasks[index]) then return 45 end if
  end for
  for each stringifyThread in stringifyThreads
    if not stringifyThread.Join(30000) or stringifyThread.Status() != "Completed" then return 46 end if
    if not stringifyThread.Close() then return 47 end if
  end for
  if stringificationFailures != 0 then return 48 end if
  floatThreads = [Thread(stringifyWorker), Thread(stringifyWorker), Thread(stringifyWorker), Thread(stringifyWorker)]
  floatTasks = [
    StringifyTask(1.5, "table-t1.5.tbl"), StringifyTask(-25.125, "table-t-25.125.tbl"),
    StringifyTask(0.25, "table-t0.25.tbl"), StringifyTask(4096.75, "table-t4096.75.tbl")
  ]
  for index = 0 to 3
    if not floatThreads[index].Start(floatTasks[index]) then return 49 end if
  end for
  for each floatThread in floatThreads
    if not floatThread.Join(30000) or floatThread.Status() != "Completed" then return 50 end if
    if not floatThread.Close() then return 51 end if
  end for
  if stringificationFailures != 0 then return 52 end if

  print "[OK] native threads, global GC heap and synchronization"
  return 0
end function
