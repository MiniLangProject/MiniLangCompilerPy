/// Requests below the reserved ceiling must not fail because of the growth quantum.
function main(args)
  size = 34 * 1024 * 1024
  if len(args) > 0 and args[0] == "alignment" then size = 32 * 1024 * 1024 + 512 end if
  if len(args) > 0 and args[0] == "overflow" then size = 42 * 1024 * 1024 end if
  value = bytes(size, 43)
  if value[0] != 43 or value[len(value) - 1] != 43 then return 1 end if
  if heap_bytes_committed() > heap_bytes_reserved() then return 2 end if
  if heap_bytes_committed() % 4096 != 0 then return 3 end if
  if len(args) > 0 and args[0] == "full-reserve" and heap_bytes_committed() != heap_bytes_reserved() then return 4 end if
  print "MEMORY CEILING [OK]"
  return 0
end function
