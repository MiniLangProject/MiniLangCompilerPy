// Exercise publication and cleanup operations from independent native workers.
synchronized closeReady = 0
synchronized closeGo = false
synchronized configReady = 0
synchronized configGo = false
synchronized joinReady = 0
synchronized joinGo = false
synchronized releaseWorker = false
synchronized mixedReady = 0
synchronized mixedGo = false
synchronized gcCloseRun = false

function immediateWorker()
  return 17
end function

function logicalIdWorker()
  return threadLogicalId()
end function

function joinWhenPublished(victim)
  while victim.Status() == "Created"
    threadSleep(0)
  end while
  return victim.Join(10000)
end function

function closeTogether(victim)
  global closeReady, closeGo
  closeReady = closeReady + 1
  while not closeGo
    threadSleep(0)
  end while
  return victim.Close()
end function

function setIdTogether(payload)
  global configReady, configGo
  configReady = configReady + 1
  while not configGo
    threadSleep(0)
  end while
  return payload[0].SetLogicalId(payload[1])
end function

function startTogether(victim)
  global configReady, configGo
  configReady = configReady + 1
  while not configGo
    threadSleep(0)
  end while
  return victim.Start()
end function

function slowWorker()
  threadSleep(2)
  return 9
end function

function joinTogether(victim)
  global joinReady, joinGo
  joinReady = joinReady + 1
  while not joinGo
    threadSleep(0)
  end while
  return victim.Join(10000)
end function

function cooperativeWorker()
  global releaseWorker
  while not releaseWorker and not threadStopRequested()
    threadSleep(0)
  end while
end function

function startVictim(victim)
  return victim.Start()
end function

function joinOrCloseTogether(payload)
  global mixedReady, mixedGo
  mixedReady = mixedReady + 1
  while not mixedGo
    threadSleep(0)
  end while
  if payload[1] then return payload[0].Close() end if
  return payload[0].Join(10000)
end function

function allocatingWorker()
  // Leave a live TLAB tail for the terminal epilogue to retire.
  return ["worker-result", [1, 2, 3, 4]]
end function

function closeGcCollector()
  global gcCloseRun
  while gcCloseRun
    gc_collect()
    threadSleep(0)
  end while
end function

function main(args)
  global closeReady, closeGo, configReady, configGo, joinReady, joinGo, releaseWorker
  global mixedReady, mixedGo, gcCloseRun

  // Status() deliberately maps the internal Starting state to Running. Join()
  // must nevertheless wait until Start() has published a nonzero OS handle.
  for round = 0 to 499
    victim = Thread(immediateWorker)
    observer = Thread(joinWhenPublished)
    if not observer.Start(victim) then return 10 end if
    if not victim.Start() then return 11 end if
    if not observer.Join(10000) or observer.Result() != true then return 12 end if
    if not victim.Join(10000) or victim.Result() != 17 then return 13 end if
    if not observer.Close() or not victim.Close() then return 14 end if
  end for

  // Only one of two concurrent Close() calls may claim the native handle.
  for round = 0 to 249
    victim = Thread(immediateWorker)
    if not victim.Start() or not victim.Join(10000) then return 20 end if
    closeReady = 0
    closeGo = false
    first = Thread(closeTogether)
    second = Thread(closeTogether)
    if not first.Start(victim) or not second.Start(victim) then return 21 end if
    while closeReady < 2
      threadSleep(0)
    end while
    closeGo = true
    if not first.Join(10000) or not second.Join(10000) then return 22 end if
    wins = 0
    if first.Result() == true then wins = wins + 1 end if
    if second.Result() == true then wins = wins + 1 end if
    if wins != 1 then return 23 end if
    if not first.Close() or not second.Close() then return 24 end if
  end for

  // A successful SetLogicalId() racing Start() must be visible to the worker;
  // otherwise Start won the state claim and the setter must report false.
  for round = 0 to 249
    victim = Thread(logicalIdWorker, "initial")
    wanted = "configured-" + round
    configReady = 0
    configGo = false
    setter = Thread(setIdTogether)
    starter = Thread(startTogether)
    if not setter.Start([victim, wanted]) or not starter.Start(victim) then return 30 end if
    while configReady < 2
      threadSleep(0)
    end while
    configGo = true
    if not setter.Join(10000) or not starter.Join(10000) then return 31 end if
    if starter.Result() != true then return 32 end if
    if not victim.Join(10000) then return 33 end if
    if setter.Result() == true and victim.Result() != wanted then return 34 end if
    if not setter.Close() or not starter.Close() or not victim.Close() then return 35 end if
  end for

  // pthread_join is a single-owner operation. Both public Join() calls must
  // still observe the same successful completion.
  for round = 0 to 99
    joinReady = 0
    joinGo = false
    victim = Thread(slowWorker)
    first = Thread(joinTogether)
    second = Thread(joinTogether)
    if not victim.Start() or not first.Start(victim) or not second.Start(victim) then return 40 end if
    while joinReady < 2
      threadSleep(0)
    end while
    joinGo = true
    if not first.Join(10000) or not second.Join(10000) then return 41 end if
    if first.Result() != true or second.Result() != true then return 42 end if
    if not first.Close() or not second.Close() or not victim.Close() then return 43 end if
  end for

  // STARTING maps to the public Running/alive state, so Stop() must also own
  // that short publication window instead of returning a contradictory false.
  for round = 0 to 249
    releaseWorker = false
    victim = Thread(cooperativeWorker)
    starter = Thread(startVictim)
    if not starter.Start(victim) then return 50 end if
    while victim.Status() == "Created"
      threadSleep(0)
    end while
    // A zero-timeout Join must include the handle-publication wait and remain
    // nonblocking even when it observes the internal STARTING state.
    if victim.Join(0) then return 51 end if
    if victim.IsAlive() and not victim.Stop() then return 52 end if
    releaseWorker = true
    if not starter.Join(10000) or not victim.Join(10000) then return 53 end if
    if not starter.Close() or not victim.Close() then return 54 end if
  end for

  // A terminal public status is published just before the native entry
  // epilogue returns. Close() must wait for that epilogue before releasing the
  // OS handle, even when no caller performed Join() first.
  for round = 0 to 499
    victim = Thread(immediateWorker)
    if not victim.Start() then return 60 end if
    while victim.IsAlive()
      threadSleep(0)
    end while
    if not victim.Close() then return 61 end if
  end for

  // Join and Close may start against the same terminal handle. Join either
  // acquires a handle reference and completes, or observes the Close claim and
  // returns false; neither path may wait on or dereference a released handle.
  for round = 0 to 249
    victim = Thread(slowWorker)
    if not victim.Start() then return 70 end if
    while victim.IsAlive()
      threadSleep(0)
    end while
    mixedReady = 0
    mixedGo = false
    first = Thread(joinOrCloseTogether)
    second = Thread(joinOrCloseTogether)
    closer = Thread(joinOrCloseTogether)
    if not first.Start([victim, false]) or not second.Start([victim, false]) then return 71 end if
    if not closer.Start([victim, true]) then return 72 end if
    while mixedReady < 3
      threadSleep(0)
    end while
    mixedGo = true
    if not first.Join(10000) or not second.Join(10000) or not closer.Join(10000) then return 73 end if
    if typeof(first.Result()) != "bool" or typeof(second.Result()) != "bool" then return 74 end if
    if closer.Result() != true then return 75 end if
    if not first.Close() or not second.Close() or not closer.Close() then return 76 end if
  end for

  // Repeated collections must be able to finish while the main thread closes a
  // worker whose terminal epilogue still has a TLAB tail to retire. A closer
  // published as RUNNING would deadlock this cycle at the worker safepoint.
  gcCloseRun = true
  collector = Thread(closeGcCollector)
  if not collector.Start() then return 80 end if
  for round = 0 to 299
    victim = Thread(allocatingWorker)
    if not victim.Start() then return 81 end if
    while victim.IsAlive()
      threadSleep(0)
    end while
    if not victim.Close() then return 82 end if
  end for
  gcCloseRun = false
  if not collector.Join(10000) or not collector.Close() then return 83 end if

  print "[OK] thread lifecycle publication and cleanup races"
  return 0
end function
