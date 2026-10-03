/// Memory policy, tracing worklist growth and allocation-free diagnostics.
struct MemoryNode
  value
  next
end struct

function makeGraph(n)
  graph = array(n, void)
  for i = 0 to n - 1
    graph[i] = MemoryNode(i, void)
  end for
  return graph
end function

function fragmented()
  keep = array(2000, void)
  for i = 0 to 1999
    keep[i] = bytes(128, i % 251)
  end for
  for i = 0 to 999
    keep[i * 2] = void
  end for
  gc_collect()
  probes = gc_stat(6)
  // None of the small holes can satisfy these large requests. Only the first
  // miss should walk the full list; later misses use the negative-fit cache.
  for i = 0 to 99
    temporary = bytes(16384, i)
    if temporary[0] != i then return false end if
  end for
  if gc_stat(6) - probes > 2500 then return false end if
  for i = 0 to 999
    if keep[i * 2 + 1][0] != ((i * 2 + 1) % 251) then return false end if
  end for
  return true
end function

function main(args)
  if gc_stat(11) != 1 then return 1 end if
  if gc_stat(-1) != void or gc_stat(1000) != void or gc_stat("x") != void then return 2 end if
  used = heap_bytes_used()
  diagnostic = gc_stat
  for i = 0 to 99
    if diagnostic(0) != gc_stat(0) then return 3 end if
  end for
  if heap_bytes_used() != used then return 4 end if

  // A broad graph, not just a deep chain, crosses the initial worklist capacity.
  graph = makeGraph(20000)
  before = gc_stat(0)
  gc_collect()
  if gc_stat(0) != before + 1 then return 5 end if
  if gc_stat(4) < 20000 or gc_stat(13) < 20000 then return 6 end if
  for i = 0 to 19999
    if graph[i].value != i then return 7 end if
  end for

  large = bytes(40 * 1024 * 1024, 71)
  gc_collect()
  if gc_stat(1) < 40 * 1024 * 1024 or gc_stat(10) < 10 * 1024 * 1024 then return 8 end if
  if large[0] != 71 or large[len(large) - 1] != 71 then return 9 end if
  gc_set_limit(123456)
  gc_collect()
  if gc_stat(11) != 0 or gc_stat(9) != 123456 or gc_stat(10) != 123456 then return 10 end if
  gc_set_limit(0)
  if not fragmented() then return 11 end if
  gc_collect()
  if graph[123].value != 123 then return 12 end if
  print "MEMORY MANAGEMENT [OK]"
  return 0
end function
