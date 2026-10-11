// A fixed live set must not acquire another MiB of committed heap every cycle.
// Snapshot-free ranges must protect new bytes/arrays/structs/TLABs and Threads,
// then become ordinary traceable objects at the following snapshot.
struct ReuseNode
  value
  child
end struct

reuseGraph = void
reuseRing = void

function prepareReuseGraph()
  global reuseGraph, reuseRing
  reuseGraph = array(800000, void)
  for i = 0 to 799999
    reuseGraph[i] = ReuseNode(i, [i, i + 1])
  end for
  reuseRing = array(8, void)
end function

function seedReusableHole()
  payload = bytes(128 * 1024 * 1024, 31)
  return payload[len(payload) - 1]
end function

function reuseWorker(payload)
  return payload.child[1][1023]
end function

function allocateDuringSnapshot(round)
  // All these objects can live BELOW the frozen allocation frontier.
  global reuseRing
  payload = bytes(1024 * 1024, 73)
  node = ReuseNode(round, [reuseGraph[round], bytes(1024, round)])
  thread = Thread(reuseWorker)
  reuseRing[round % 8] = [node, thread]
  if payload[len(payload) - 1] != 73 then return 1 end if
  return 0
end function

function main(args)
  gc_set_limit(0)
  if typeof(gc_stat(17)) != "int" then return 1 end if
  prepareReuseGraph()
  if seedReusableHole() != 31 then return 2 end if
  gc_collect()
  baseline = heap_bytes_committed()
  frontier = heap_bytes_used()
  progress = 0
  for round = 1 to 64
    gc_collect_async()
    while gc_stat(17) == 3
      threadSleep(0)
    end while
    if gc_stat(17) == 1 or gc_stat(17) == 2 then progress += 1 end if
    if allocateDuringSnapshot(round) != 0 then return 3 end if
    while gc_stat(17) != 0
      threadSleep(0)
    end while
    entry = reuseRing[round % 8]
    if entry[0].child[0].value != round or entry[0].child[1][1023] != round then return 4 end if
    // A newly created Thread must remain registered/usable after weak sweeping.
    if not entry[1].Start(entry[0]) or not entry[1].Join(10000) then return 5 end if
    if entry[1].Result() != round or not entry[1].Close() then return 6 end if
  end for
  gc_collect()
  for round = 57 to 64
    entry = reuseRing[round % 8]
    if entry[0].value != round or entry[0].child[1][1023] != round then return 7 end if
  end for
  if progress < 8 then return 8 end if
  // Allow bounded bookkeeping, not the old one-MiB-per-cycle ratchet.
  if heap_bytes_committed() > baseline + 8 * 1024 * 1024 then return 9 end if
  if heap_bytes_used() > frontier + 8 * 1024 * 1024 then return 10 end if
  if gc_stat(20) != 0 then return 11 end if
  print "GC CONCURRENT REUSE [OK] progress=" + progress + " growth=" + (heap_bytes_committed() - baseline)
  return 0
end function
