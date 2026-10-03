/// Observe resident memory before/after reclaiming an interior allocation.
/// Compile both versions with --heap-shrink --heap-shrink-min 1m.
function main(args)
  gc_set_limit(0)
  blocks = [bytes(123, 11), bytes(64 * 1024 * 1024, 71), bytes(123, 22)]
  print "allocated"
  input()
  blocks[1] = void
  gc_collect()
  print "collected"
  input()
  if blocks[0][122] != 11 or blocks[2][122] != 22 then return 1 end if
  print "RESIDENCY [OK]"
  return 0
end function
