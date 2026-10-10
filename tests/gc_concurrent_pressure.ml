// Allocation failure must wait outside the recursive heap monitor, recycle
// old free blocks, and preserve roots while multiple managed threads allocate.
function pressureWorker(seed)
  retained = array(32, void)
  for i = 0 to 1499
    retained[i % 32] = bytes(16384, seed)
  end for
  for i = 0 to 31
    if retained[i][16383] != seed then return error(1912, "worker root corrupted") end if
  end for
  return seed
end function

function main(args)
  gc_set_limit(0)
  first = Thread(pressureWorker)
  second = Thread(pressureWorker)
  if not first.Start(71) or not second.Start(93) then return 1 end if
  retained = array(8, void)
  for i = 0 to 159
    retained[i % 8] = bytes(1024 * 1024, i % 251)
    if i % 11 == 0 then threadSleep(0) end if
  end for
  if not first.Join(30000) or not second.Join(30000) then return 2 end if
  if first.Result() != 71 or second.Result() != 93 then return 3 end if
  if not first.Close() or not second.Close() then return 4 end if
  gc_collect()
  for i = 152 to 159
    value = retained[i % 8]
    if value[0] != i % 251 or value[len(value) - 1] != i % 251 then return 5 end if
  end for
  if gc_stat(16) < 2 then return 6 end if
  if heap_bytes_committed() > heap_bytes_reserved() then return 7 end if
  print "GC CONCURRENT PRESSURE [OK] completed=" + gc_stat(16)
  return 0
end function
