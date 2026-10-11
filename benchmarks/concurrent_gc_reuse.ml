// Fixed live graph, a large reusable hole, and one short-lived
// allocation per cycle. Argument "wait" allocates only after cycle completion.
struct ProbeNode
  value
  child
end struct

probeGraph = void

function prepare()
  global probeGraph
  probeGraph = array(800000, void)
  for i = 0 to 799999
    probeGraph[i] = ProbeNode(i, [i, i + 1])
  end for
end function

function seedHole()
  buffer = bytes(128 * 1024 * 1024, 31)
  return buffer[len(buffer) - 1]
end function

function churn()
  buffer = bytes(1024 * 1024, 73)
  return buffer[len(buffer) - 1]
end function

function report(round)
  print "PROBE round=" + round + " frontier=" + heap_bytes_used() + " committed=" + heap_bytes_committed() + " live=" + gc_stat(1) + " free=" + heap_free_bytes() + " largest=" + gc_stat(3)
end function

function main(args)
  gc_set_limit(0)
  prepare()
  if seedHole() != 31 then return 1 end if
  gc_collect()
  report(0)
  concurrent = typeof(gc_stat(17)) == "int"
  waitFirst = len(args) > 0 and args[0] == "wait"
  observed = 0
  for round = 1 to 64
    gc_collect_async()
    if concurrent then
      while gc_stat(17) == 3
        threadSleep(0)
      end while
      if waitFirst then
        while gc_stat(17) != 0
          threadSleep(0)
        end while
      end if
      if gc_stat(17) != 0 then observed += 1 end if
    end if
    if churn() != 73 then return 2 end if
    if concurrent then
      while gc_stat(17) != 0
        threadSleep(0)
      end while
    end if
    if round % 16 == 0 then report(round) end if
  end for
  gc_collect()
  report(65)
  if probeGraph[799999].child[1] != 800000 then return 3 end if
  print "PROBE [OK] concurrent_allocations=" + observed
  return 0
end function
