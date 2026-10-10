// Regression: crossing a committed-heap boundary grows the heap before an
// emergency full collection. Periodic collection remains controlled by the
// configured GC byte limit.
function main(args)
  baseline = heap_bytes_committed()
  scratch = void
  for i = 0 to 6000
    scratch = bytes(4096)
  end for

  grown = heap_bytes_committed()
  if grown <= baseline then
    print "[FAIL] heap did not grow before emergency GC"
    return 1
  end if

  print "[OK] heap growth precedes emergency GC"
  return 0
end function
