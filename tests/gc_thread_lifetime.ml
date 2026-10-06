/// Thread objects are managed; the native context registry must be weak.
synchronized activeGo = false
synchronized activeDone = 0
synchronized activeFailed = false
synchronized raceGo = false
synchronized raceExit = false

function simpleWorker()
  return [stringRepeat("result", 10000), bytes(4096, 71)]
end function

function activeWorker(payload)
  global activeGo, activeDone, activeFailed
  while not activeGo
    threadSleep(0)
  end while
  gc_collect()
  id = threadLogicalId()
  if len(id) != 1024 or id[0] != "z" or payload[1023] != 77 then activeFailed = true end if
  activeDone += 1
end function

function abandonCreated()
  for i = 0 to 15
    abandoned = Thread(simpleWorker, stringRepeat("x", 1024 * 1024))
  end for
  // Unreachable cycles involving a Thread must also be collectible.
  cycle = [void, bytes(1024 * 1024, 11)]
  abandoned = Thread(simpleWorker, cycle)
  cycle[0] = abandoned
end function

function checkCreatedAndAliases()
  worker = Thread(simpleWorker, [bytes(4096, 39)])
  aliases = [worker]
  gc_collect()
  if worker.LogicalId()[0][4095] != 39 or aliases[0].Status() != "Created" then return false end if
  if not worker.Close() or worker.Close() then return false end if
  gc_collect()
  if aliases[0].Status() != "Stopped" or aliases[0].LogicalId() != void then return false end if
  if worker.Start() or worker.SetLogicalId("too late") then return false end if
  return true
end function

function checkCompleted()
  worker = Thread(simpleWorker, "retained")
  if not worker.Start() or not worker.Join(10000) then return false end if
  gc_collect()
  result = worker.Result()
  if len(result[0]) != 60000 or result[1][4095] != 71 then return false end if
  if worker.Status() != "Completed" or worker.LogicalId() != "retained" then return false end if
  if not worker.Close() or worker.Close() then return false end if
  gc_collect()
  return worker.Status() == "Completed" and worker.Result() == void
end function

function launchUnreferenced()
  for i = 0 to 11
    worker = Thread(activeWorker, stringRepeat("z", 1024))
    if not worker.Start(bytes(1024, 77)) then return false end if
  end for
  return true
end function

function abandonCompleted()
  for i = 0 to 99
    worker = Thread(simpleWorker)
    if not worker.Start() or not worker.Join(10000) then return false end if
    // Deliberately omit Close: unreachable terminated handles are GC-finalized.
  end for
  return true
end function

function collectUntilEmpty()
  for i = 0 to 999
    gc_collect()
    if gc_stat(15) == 0 then return true end if
    threadSleep(1)
  end for
  return false
end function

function constructionUnderPressure()
  gc_set_limit(1)
  for i = 0 to 31
    worker = Thread(simpleWorker, [bytes(1024, i)])
    gc_collect()
    if worker.LogicalId()[0][1023] != i then return false end if
    if not worker.Close() then return false end if
  end for
  gc_set_limit(0)
  return true
end function


/// Start and Close must make an atomic, exclusive choice on Created objects.
function raceWorker()
  global raceExit
  while not raceExit
    threadSleep(0)
  end while
end function

function raceStarter(victim)
  global raceGo
  while not raceGo
    threadSleep(0)
  end while
  return victim.Start()
end function

function raceCloser(victim)
  global raceGo
  while not raceGo
    threadSleep(0)
  end while
  return victim.Close()
end function

function raceCreatedClose()
  global raceGo, raceExit
  for round = 0 to 63
    raceGo = false
    raceExit = false
    victim = Thread(raceWorker, bytes(1024, 23))
    starter = Thread(raceStarter)
    closer = Thread(raceCloser)
    if not starter.Start(victim) or not closer.Start(victim) then return false end if
    raceGo = true
    gc_collect()
    if not starter.Join(10000) or not closer.Join(10000) then return false end if
    if starter.Result() == closer.Result() then return false end if
    if starter.Result() then
      raceExit = true
      if not victim.Join(10000) or not victim.Close() then return false end if
    else
      if victim.Status() != "Stopped" or victim.LogicalId() != void then return false end if
    end if
    if not starter.Close() or not closer.Close() then return false end if
  end for
  return true
end function

function main(args)
  global activeGo, activeDone, activeFailed
  gc_collect()
  baseline = gc_stat(1)
  abandonCreated()
  if not collectUntilEmpty() or gc_stat(1) > baseline + 4096 then return 1 end if
  if not checkCreatedAndAliases() then return 2 end if
  if not checkCompleted() then return 3 end if
  if not collectUntilEmpty() then return 4 end if
  if not constructionUnderPressure() or not collectUntilEmpty() then return 5 end if
  if not launchUnreferenced() then return 6 end if
  gc_collect()
  if gc_stat(15) != 12 then return 7 end if
  activeGo = true
  for i = 0 to 9999
    if activeDone == 12 then break end if
    gc_collect()
    threadSleep(1)
  end for
  if activeDone != 12 or activeFailed then return 8 end if
  if not collectUntilEmpty() then return 9 end if
  if not abandonCompleted() or not collectUntilEmpty() then return 10 end if
  if gc_stat(1) > baseline + 4096 then return 11 end if
  if not raceCreatedClose() or not collectUntilEmpty() then return 12 end if
  print "GC THREAD LIFETIME [OK]"
  return 0
end function
