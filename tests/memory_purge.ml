/// Interior dead pages must be discardable without losing metadata or neighbors.
/// Run with --heap-shrink --heap-shrink-min 1m.
function hole()
  blocks = [bytes(123, 11), bytes(16 * 1024 * 1024, 71), bytes(123, 22)]
  blocks[1] = void
  gc_collect()
  if gc_stat(14) < 15 * 1024 * 1024 then return false end if
  if gc_stat(3) < 16 * 1024 * 1024 then return false end if
  if blocks[0][122] != 11 or blocks[2][122] != 22 then return false end if
  // Reuse, split, fill and traverse the discarded range repeatedly. Windows
  // MEM_RESET does not promise zeros; object constructors must initialize it.
  values = array(128, void)
  for i = 0 to 127
    values[i] = bytes(65536, i)
  end for
  gc_collect()
  for i = 0 to 127
    if values[i][0] != i or values[i][65535] != i then return false end if
  end for
  return blocks[0][0] == 11 and blocks[2][0] == 22
end function

function main(args)
  gc_set_limit(0)
  if not hole() then return 1 end if
  gc_collect()
  if heap_bytes_committed() > 2 * 1024 * 1024 then return 2 end if
  // Recommit a trimmed top and ensure that growth initializes new pages.
  refill = bytes(20 * 1024 * 1024, 93)
  if refill[0] != 93 or refill[len(refill) - 1] != 93 then return 3 end if
  print "MEMORY PURGE [OK]"
  return 0
end function
