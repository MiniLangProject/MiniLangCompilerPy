/// --heap-shrink reclaims worklist/bitmap peaks without trimming live metadata.
struct MetadataNode
  value
end struct

function broadGraph()
  graph = array(20000, void)
  for i = 0 to 19999
    graph[i] = MetadataNode(i)
  end for
  for i = 0 to 9
    gc_collect()
  end for
  if gc_stat(13) < 20000 or graph[19999].value != 19999 then return false end if
  large = bytes(40 * 1024 * 1024, 67)
  gc_collect()
  return large[0] == 67 and large[len(large) - 1] == 67
end function

function main(args)
  for round = 0 to 2
    if not broadGraph() then return 1 end if
    gc_collect()
    // One quiet collection must not discard the recent worklist peak.
    if gc_stat(13) < 20000 then return 2 end if
    for i = 0 to 9
      gc_collect()
    end for
    if gc_stat(13) != 8192 or heap_bytes_committed() > 2 * 1024 * 1024 then return 3 end if
  end for
  print "GC METADATA [OK]"
  return 0
end function
