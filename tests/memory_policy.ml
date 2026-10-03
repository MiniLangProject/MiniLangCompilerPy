/// Explicit compile-time policies must never be replaced by adaptive defaults.
function main(args)
  if gc_stat(11) != 0 then return 1 end if
  limit = gc_stat(9)
  if gc_stat(10) != limit then return 2 end if
  if args[0] == "fixed" and limit != 1048576 then return 3 end if
  if args[0] == "disabled" and limit != -1 then return 4 end if
  keep = bytes(40 * 1024 * 1024, 11)
  gc_collect()
  if gc_stat(9) != limit or gc_stat(10) != limit then return 5 end if
  if keep[len(keep) - 1] != 11 then return 6 end if
  print "MEMORY POLICY [OK]"
  return 0
end function
