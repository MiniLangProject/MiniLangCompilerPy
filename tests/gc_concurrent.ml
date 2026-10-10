// SATB regressions: graph transfers, closures, new allocations, worker roots,
// and deterministic log overflow. Run with --gc-concurrent; "overflow" uses
// --gc-satb-limit 64. Raw byte payloads are checked after free-list reuse.
struct ConcurrentNode
  value
  payload
end struct

struct ConcurrentBox
  value
end struct

struct ConcurrentState
  source
  box
  graph
  destination
end struct

concurrentState = void

function makeAccessors(initial)
  captured = initial
  function get()
    return captured
  end function
  function set(value)
    // Read before writing selects the outer binding in MiniLang; a first
    // assignment alone would introduce a shadowing local.
    if captured != value then captured = value end if
  end function
  return [get, set]
end function

function allocationWorker(seed)
  ring = array(64, void)
  for i = 0 to 4999
    ring[i % 64] = ConcurrentNode(i, bytes(80, seed))
    if (i % 113) == 0 then threadSleep(0) end if
  end for
  return [ring[4999 % 64].value, ring[4999 % 64].payload[79]]
end function

function check(condition, message)
  if not condition then return error(1910, message) end if
end function

function setupState()
  global concurrentState
  concurrentState = ConcurrentState(void, void, void, void)
  concurrentState.graph = array(600000, void)
  for i = 0 to 599999
    concurrentState.graph[i] = ConcurrentNode(i, [i, i + 1])
  end for
  concurrentState.source = array(4096, void)
  concurrentState.destination = array(4096, void)
  for i = 0 to 4095
    concurrentState.source[i] = ConcurrentNode(i, bytes(72, i % 251))
  end for
  concurrentState.box = ConcurrentBox(void)
end function

function setupBulkSource()
  global concurrentState
  concurrentState.source = array(4096, void)
  concurrentState.destination = array(4096, void)
  for i = 0 to 4095
    concurrentState.source[i] = ConcurrentNode(30000 + i, bytes(72, i % 251))
  end for
end function

function main(args)
  global concurrentState
  gc_set_limit(0)
  // Construct outside this frame so cached indexing temporaries from setup
  // cannot independently root the source array and mask a missing barrier.
  setupState()
  access = makeAccessors(ConcurrentNode(-1, bytes(8, 0)))
  get = access[0]
  set = access[1]
  gc_collect()
  initialCompleted = gc_stat(16)
  workers = array(3, void)
  for i = 0 to 2
    workers[i] = Thread(allocationWorker)
    check(workers[i].Start(70 + i), "allocation worker started")
  end for
  // Exercise the first-class builtin as well as the direct spelling.
  startCollection = gc_collect_async
  startCollection()
  while gc_stat(17) == 3
    threadSleep(0)
  end while
  // State fields are pushed in order. Let the worker scan the empty
  // destination first, then spend time on the large graph before the source.
  while gc_stat(17) == 1 and gc_stat(21) < 5000
    threadSleep(0)
  end while
  progress = 0
  for i = 0 to 4095
    if gc_stat(17) == 1 or gc_stat(17) == 4 then progress += 1 end if
    // Move a white child into a potentially already-scanned destination, then
    // erase its old edge. SATB must preserve the overwritten source reference.
    value = concurrentState.source[i]
    concurrentState.destination[i] = value
    concurrentState.source[i] = void
    concurrentState.box.value = value
    set(value)
    // New objects must stay outside the worker's sweep frontier, even when
    // their TLAB is retired and reallocated before the collection finishes.
    replacement = ConcurrentNode(i + 10000, [bytes(128, 37)])
    if replacement.payload[0][127] != 37 then return error(1911, "new allocation corrupted") end if
  end for
  while gc_stat(16) == initialCompleted
    threadSleep(0)
  end while
  check(progress > 0, "mutator progressed during concurrent marking or overflow retention")
  for i = 0 to 2
    check(workers[i].Join(10000), "allocation worker joined")
    result = workers[i].Result()
    check(result[0] == 4999 and result[1] == 70 + i, "worker result survived collection")
    check(workers[i].Close(), "worker handle closed")
  end for
  overflowMode = len(args) > 0 and args[0] == "overflow"
  gc_collect()
  for i = 0 to 4095
    node = concurrentState.destination[i]
    check(node.value == i and node.payload[71] == i % 251, "transferred child survived free-list reuse")
  end for
  check(concurrentState.graph[599999].payload[1] == 600000, "large graph survived")
  check(concurrentState.box.value.value == 4095, "member write survived")
  check(get().value == 4095, "captured box write survived")
  setupBulkSource()
  blank = array(4096, void)
  initialCompleted = gc_stat(16)
  gc_collect_async()
  while gc_stat(17) == 3 or (gc_stat(17) == 1 and gc_stat(21) < 5000)
    threadSleep(0)
  end while
  copyArray(concurrentState.destination, 0, concurrentState.source, 0, 4096)
  copyArray(concurrentState.source, 0, blank, 0, 4096)
  while gc_stat(16) == initialCompleted
    threadSleep(0)
  end while
  for i = 0 to 4095
    node = concurrentState.destination[i]
    check(node.value == 30000 + i and node.payload[71] == i % 251, "bulk-transferred child survived")
  end for
  if overflowMode then check(gc_stat(20) > 0, "small log exercised conservative overflow") end if
  if not overflowMode then check(gc_stat(20) == 0, "default reference log did not overflow") end if
  print "GC CONCURRENT [OK] progress=" + progress + " completed=" + gc_stat(16) + " overflows=" + gc_stat(20)
  return 0
end function
