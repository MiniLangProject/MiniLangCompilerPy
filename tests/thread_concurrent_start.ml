// Starting one Thread object is a one-shot operation, even when callers race.
synchronized ready = 0
synchronized go = false
synchronized starts = 0
synchronized executions = 0

function victimWorker()
  global executions
  executions = executions + 1
  threadSleep(2)
end function

function starter(victim)
  global ready, go, starts
  ready = ready + 1
  while not go
    threadSleep(0)
  end while
  if victim.Start() then starts = starts + 1 end if
end function

function main(args)
  global ready, go, starts, executions
  for round = 0 to 999
    ready = 0
    go = false
    starts = 0
    executions = 0
    victim = Thread(victimWorker)
    first = Thread(starter)
    second = Thread(starter)
    if not first.Start(victim) or not second.Start(victim) then return 10 end if
    while ready < 2
      threadSleep(0)
    end while
    go = true
    if not first.Join(10000) or not second.Join(10000) then return 11 end if
    if not victim.Join(10000) then return 12 end if
    if starts != 1 or executions != 1 then return 20 end if
    first.Close()
    second.Close()
    victim.Close()
  end for
  print "[OK] atomic same-object Thread.Start"
  return 0
end function
