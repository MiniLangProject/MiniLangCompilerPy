// Exercise partial bitmap words, adjacent/unsorted free entries, a run ending
// at an exact bitmap-page boundary, and multiple mutators reusing old holes.
reuseAnchors = void
reuseStable = void

function fragmentSize(index)
  return 1 + ((index * 997) % 8193)
end function

function prepareFragments()
  global reuseAnchors, reuseStable
  reuseStable = array(600000, void)
  for i = 0 to 599999
    reuseStable[i] = [i, i + 1]
  end for
  reuseAnchors = array(2048, void)
  garbage = array(2048, void)
  for i = 0 to 2047
    garbage[i] = bytes(fragmentSize(i), i % 251)
    reuseAnchors[i] = [i, bytes(33, 61)]
  end for
end function

function boundaryHole()
  // A bytes block uses an eight-byte GC header plus eight object-header bytes.
  padding = 524288 - ((heap_bytes_used() + 16) % 262144)
  payload = bytes(padding, 29)
  if heap_bytes_used() % 262144 != 0 then return 1 end if
  if payload[len(payload) - 1] != 29 then return 2 end if
  return 0
end function

function fragmentWorker(seed)
  ring = array(32, void)
  for i = 0 to 7999
    index = i % 32
    ring[index] = [seed, bytes(fragmentSize(i), seed)]
    if ring[index][1][len(ring[index][1]) - 1] != seed then return -1 end if
    if i % 113 == 0 then threadSleep(0) end if
  end for
  for i = 0 to 31
    if ring[i][0] != seed or ring[i][1][0] != seed then return -2 end if
  end for
  return seed
end function

function clearAnchors()
  global reuseAnchors
  reuseAnchors = void
end function

function main(args)
  gc_set_limit(0)
  if typeof(gc_stat(17)) != "int" then return 1 end if
  prepareFragments()
  if boundaryHole() != 0 then return 2 end if
  gc_collect()
  // The second cycle protects the just-freed boundary hole and its final bit.
  gc_collect()
  first = Thread(fragmentWorker)
  second = Thread(fragmentWorker)
  if not first.Start(71) or not second.Start(93) then return 3 end if
  for round = 1 to 24
    gc_collect()
    for i = 0 to 2047
      if reuseAnchors[i][0] != i or reuseAnchors[i][1][32] != 61 then return 4 end if
    end for
  end for
  if not first.Join(30000) or not second.Join(30000) then return 5 end if
  if first.Result() != 71 or second.Result() != 93 then return 6 end if
  if not first.Close() or not second.Close() then return 7 end if
  clearAnchors()
  gc_collect()
  gc_collect()
  // Free holes separated by formerly-live anchors must coalesce next cycle.
  if gc_stat(3) < 4 * 1024 * 1024 then return 8 end if
  if reuseStable[599999][1] != 600000 then return 9 end if
  if gc_stat(20) != 0 then return 10 end if
  print "GC CONCURRENT REUSE FRAGMENTS [OK]"
  return 0
end function
