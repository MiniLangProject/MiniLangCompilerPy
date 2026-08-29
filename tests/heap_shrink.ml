// Verify that an explicit full collection decommits unused top-of-heap pages.
function main(args)
  before = heap_bytes_committed()
  payload = bytes(32 << 20)
  if len(payload) != (32 << 20) then
    print "[FAIL] heap shrink allocation"
    return 1
  end if

  payload = void
  gc_collect()
  after = heap_bytes_committed()
  if after >= before then
    print "[FAIL] heap shrink did not reduce committed bytes"
    return 1
  end if
  if after < (16 << 20) then
    print "[FAIL] heap shrink crossed configured minimum"
    return 1
  end if

  print "[OK] heap shrink decommits unused pages"
  return 0
end function
