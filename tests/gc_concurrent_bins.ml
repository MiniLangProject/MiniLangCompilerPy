// Size-class reuse and partial TLABs must preserve a large contiguous hole.
binAnchors = array(132, void)
binRoots = array(100000, void)
binLarge = void

function seedBinHoles()
  global binAnchors
  for i = 0 to 127
    // 65,504 total bytes: just too small for the old fixed 64 KiB refill.
    hole = bytes(65488 + heap_bytes_used() % 8, 31)
    binAnchors[i] = bytes(131072 + heap_bytes_used() % 64, i % 251)
    if hole[len(hole) - 1] != 31 then return 1 end if
  end for
  largeHole = bytes(16 * 1024 * 1024 + heap_bytes_used() % 8, 47)
  for i = 128 to 131
    binAnchors[i] = bytes(131072 + heap_bytes_used() % 64, i % 251)
  end for
  return largeHole[len(largeHole) - 1]
end function

function fillBinHoles()
  global binRoots, binLarge
  for i = 0 to 99999
    binRoots[i] = [i, i + 1]
  end for
  binLarge = bytes(16 * 1024 * 1024 + heap_bytes_used() % 8, 53)
end function

function main(args)
  gc_set_limit(0)
  if seedBinHoles() != 47 then return 1 end if
  gc_collect()
  gc_collect()
  before = heap_bytes_used()
  if heap_free_bytes() < 23 * 1024 * 1024 or heap_free_blocks() < 129 then return 2 end if
  requested = gc_stat(12)
  fillBinHoles()
  growth = heap_bytes_used() - before
  requested = gc_stat(12) - requested
  // Account actual capacity, not 64 KiB for every smaller refill.
  if requested > 21 * 1024 * 1024 then return 3 end if
  gc_collect()
  for i = 0 to 99999
    if binRoots[i][0] != i or binRoots[i][1] != i + 1 then return 4 end if
  end for
  for i = 0 to 131
    if binAnchors[i][131071] != i % 251 then return 5 end if
  end for
  if binLarge[len(binLarge) - 1] != 53 then return 6 end if
  if growth > 1024 * 1024 then return 9 end if
  if gc_stat(20) != 0 then return 10 end if
  print "GC CONCURRENT BINS [OK] growth=" + growth + " requested=" + requested
  return 0
end function
