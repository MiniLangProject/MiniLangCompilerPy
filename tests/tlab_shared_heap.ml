/* TLAB regression: refill, cross-thread publication and GC root ownership. */

struct TlabNode
  value
  next
end struct

function buildTlabChain(seed)
  head = void
  for index = 0 to 5999
    // A TlabNode is deliberately small enough for the lock-free TLAB path.
    head = TlabNode(seed + index, head)
    if (index % 257) == 0 then threadSleep(0) end if
  end for
  return head
end function

function verifyTlabChain(head, seed)
  cursor = head
  expected = seed + 5999
  count = 0
  while cursor != void
    if typeof(cursor) != "struct" then return false end if
    if cursor.value != expected then return false end if
    cursor = cursor.next
    expected = expected - 1
    count = count + 1
  end while
  return count == 6000
end function

function main(args)
  first = Thread(buildTlabChain)
  second = Thread(buildTlabChain)
  third = Thread(buildTlabChain)
  fourth = Thread(buildTlabChain)

  if not first.Start(100000) or not second.Start(200000) then return 1 end if
  if not third.Start(300000) or not fourth.Start(400000) then return 2 end if

  // Collect while workers refill their private allocation ranges.
  for collection = 0 to 7
    gc_collect()
    threadSleep(0)
  end for

  if not first.Join(30000) or not second.Join(30000) then return 3 end if
  if not third.Join(30000) or not fourth.Join(30000) then return 4 end if

  // Completed thread contexts retain results until Result()/Close().
  gc_collect()
  head1 = first.Result()
  head2 = second.Result()
  head3 = third.Result()
  head4 = fourth.Result()

  if not first.Close() or not second.Close() then return 5 end if
  if not third.Close() or not fourth.Close() then return 6 end if

  // Local stack roots now own the cross-thread graphs.
  gc_collect()
  if not verifyTlabChain(head1, 100000) then return 7 end if
  if not verifyTlabChain(head2, 200000) then return 8 end if
  if not verifyTlabChain(head3, 300000) then return 9 end if
  if not verifyTlabChain(head4, 400000) then return 10 end if

  // Large objects deliberately bypass TLABs and must share the same GC rules.
  large = bytes(8192, 90)
  gc_collect()
  if len(large) != 8192 or large[0] != 90 or large[8191] != 90 then return 11 end if

  print "[OK] TLAB shared-heap allocation, refill and retirement"
  return 0
end function
