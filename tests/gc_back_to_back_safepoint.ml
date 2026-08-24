/* Regression for back-to-back stop-the-world requests at safepoint resume. */

struct GcSafepointNode
  values
  next
end struct

function gcSafepointChurn(seed)
  head = void
  for index = 0 to 2047
    head = GcSafepointNode([seed + index, index, index + 1], head)
    // Concurrent explicit collections make resumed workers race immediately
    // with the next stop-the-world request.
    if (index % 64) == 0 then gc_collect() end if
  end for
  return head
end function

function main(args)
  threadCount = 24
  workers = array(threadCount, void)

  for index = 0 to threadCount - 1
    workers[index] = Thread(gcSafepointChurn, "gc-race-" + index)
    if not workers[index].Start((index + 1) * 100003) then return 1 end if
  end for

  for index = 0 to threadCount - 1
    if not workers[index].Join(15000) then return 2 end if
    if workers[index].Status() != "Completed" then return 3 end if
    head = workers[index].Result()
    expected = ((index + 1) * 100003) + 2047
    if head == void or head.values[0] != expected then return 4 end if
    if head.values[1] != 2047 or head.values[2] != 2048 then return 5 end if
    if not workers[index].Close() then return 6 end if
  end for

  gc_collect()
  print "[OK] back-to-back GC safepoint state publication"
  return 0
end function
