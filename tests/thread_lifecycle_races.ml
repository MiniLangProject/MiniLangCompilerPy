// Exercise publication and cleanup operations from independent native workers.
synchronized closeReady = 0
synchronized closeGo = false
synchronized configReady = 0
synchronized configGo = false

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

function main(args)
  global closeReady, closeGo, configReady, configGo

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

  print "[OK] thread lifecycle publication and cleanup races"
  return 0
end function
