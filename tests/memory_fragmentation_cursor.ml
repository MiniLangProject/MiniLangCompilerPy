/// Exact-size search cursors must survive splits and invalidate on GC/size changes.
function fragmentedHeap()
  blockers = array(4000, void)
  holes = array(4000, void)
  for i = 0 to 3999
    holes[i] = bytes(8192, i % 251)
    blockers[i] = bytes(8, 19)
  end for
  return blockers
end function

function main(args)
  blockers = fragmentedHeap()
  results = array(4000, void)
  gc_collect()
  probes = gc_stat(6)
  for i = 0 to 3999
    results[i] = bytes(4096, i % 251)
  end for
  if gc_stat(6) - probes > 12000 then return 1 end if
  for i = 0 to 3999
    if results[i][4095] != i % 251 or blockers[i][0] != 19 then return 2 end if
  end for
  for round = 0 to 3
    for i = 0 to 3999
      if i % 3 == round % 3 then results[i] = void end if
    end for
    gc_collect()
    for i = 0 to 3999
      if results[i] == void then
        size = 32 + ((i * 997) % 9000)
        results[i] = bytes(size, i % 251)
      end if
    end for
    for i = 0 to 3999
      if results[i][len(results[i]) - 1] != i % 251 or blockers[i][0] != 19 then return 3 end if
    end for
  end for
  print "MEMORY CURSOR [OK]"
  return 0
end function
