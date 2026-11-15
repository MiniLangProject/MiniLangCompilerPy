function main(args)
  initial = heap_bytes_committed()
  roots = array(8)
  for i = 0 to 7
    roots[i] = bytes(8 * 1024 * 1024, i + 1)
  end for
  grown = heap_bytes_committed()
  if grown <= initial then return 1 end if
  gc_collect()
  for i = 0 to 7
    if roots[i][0] != i + 1 or roots[i][8 * 1024 * 1024 - 1] != i + 1 then return 2 end if
  end for
  roots = void
  gc_collect()
  gc_collect()
  if heap_bytes_committed() >= grown then return 3 end if
  // Recommit decommitted pages, then verify zeroing and fresh writes.
  payload = bytes(48 * 1024 * 1024, 0)
  if payload[0] != 0 or payload[len(payload) - 1] != 0 then return 4 end if
  payload[0] = 123
  payload[len(payload) - 1] = 231
  gc_collect()
  if payload[0] != 123 or payload[len(payload) - 1] != 231 then return 5 end if
  print "heap-reserve-grow-decommit-recommit=ok"
  return 37
end function
