/// First-class-only diagnostic references must retain counter instrumentation.
struct StatsNode
  value
end struct

function selectStats()
  return gc_stat
end function

function main(args)
  read = selectStats()
  if read(11) != 1 then return 1 end if
  graph = array(20000, void)
  for i = 0 to 19999
    graph[i] = StatsNode(i)
  end for
  central = read(5)
  probe = bytes(1048576, 71)
  if read(5) <= central then return 2 end if
  gc_collect()
  if read(4) < 20000 then return 3 end if
  if graph[19999].value != 19999 or probe[1048575] != 71 then return 4 end if
  print "MEMORY INDIRECT [OK]"
  return 0
end function
