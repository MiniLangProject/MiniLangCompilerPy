import std.threading as threading

evalCount = 0

struct SharedCounter
  lock
  value
end struct

function incrementMany(counter)
  i = 0
  while i < 1000
    synchronized(counter.lock)
      inside = counter.value
      counter.value = inside + 1
    end synchronized
    i = i + 1
  end while
  return counter.value
end function

function returnInside(lock)
  synchronized(lock)
    return 17
  end synchronized
end function

function failInside(lock)
  synchronized(lock)
    return error(1660, "intentional synchronized failure")
  end synchronized
end function

function countLockEvaluation(lock)
  global evalCount
  evalCount = evalCount + 1
  return lock
end function

function useCountedLock(lock)
  synchronized(countLockEvaluation(lock))
    return true
  end synchronized
end function

function useClosedLock(lock)
  synchronized(lock)
    return true
  end synchronized
end function

function localControlFlow(lock)
  value = 0
  synchronized(lock)
    for i = 0 to 10
      if i == 2 then continue end if
      if i == 5 then break end if
      value = value + i
    end for
    switch 1
      case 1
        value = value + 10
        break
      end case
    end switch
  end synchronized
  return value
end function

function main(args)
  counter = SharedCounter(threading.Lock.new(), 0)
  a = Thread(incrementMany)
  b = Thread(incrementMany)
  if not a.Start(counter) or not b.Start(counter) then return 1 end if
  if not a.Join(10000) or not b.Join(10000) then return 2 end if
  if counter.value != 2000 then return 3 end if
  if returnInside(counter.lock) != 17 then return 4 end if
  failure = try(failInside(counter.lock))
  if typeof(failure) != "error" or failure.code != 1660 then return 7 end if
  if not useCountedLock(counter.lock) or evalCount != 1 then return 8 end if
  if localControlFlow(counter.lock) != 18 then return 10 end if
  if not counter.lock.tryAcquire() or not counter.lock.release() then return 5 end if
  if not a.Close() or not b.Close() or not counter.lock.close() then return 6 end if
  closedFailure = try(useClosedLock(counter.lock))
  if typeof(closedFailure) != "error" or closedFailure.code != 1101 then return 9 end if
  print "[OK] fine-grained synchronized(lock)"
  return 0
end function
