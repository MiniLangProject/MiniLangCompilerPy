// Run with a small fixed heap: exhausting the comparison workspace must take
// the allocator's fatal OOM path, never return the valid Boolean false.
function chain(depth)
  value=[71,"leaf"]
  for i=0 to depth-1
    value=[value,i]
  end for
  return value
end function
function main(args)
  gc_set_limit(0)
  left=chain(1024) right=chain(1024)
  gc_collect()
  available=heap_bytes_committed()-heap_bytes_used()
  ballast=bytes(available-128,91)
  print "ARRAY EQUALITY entering exhausted workspace"
  result=left==right
  // Keep every byte live across the comparison; either result is a test bug.
  if ballast[0]==91 then print "[FAIL] comparison returned "+result end if
  return 98
end function
