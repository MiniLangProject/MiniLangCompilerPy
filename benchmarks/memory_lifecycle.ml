/// Reproducible GC lifecycle, handoff and metadata high-water measurements.
#if TARGET_OS == "windows"
extern function counter(output as bytes) from "kernel32.dll" symbol "QueryPerformanceCounter" returns i32
extern function frequency(output as bytes) from "kernel32.dll" symbol "QueryPerformanceFrequency" returns i32
extern function process() from "kernel32.dll" symbol "GetCurrentProcess" returns ptr
extern function memoryInfo(handle as ptr, output as bytes, size as u32) from "psapi.dll" symbol "GetProcessMemoryInfo" returns i32
#else
extern function counter(clockId as i32, output as bytes) from "libc.so.6" symbol "clock_gettime" returns i32
#endif

function read64(buffer, offset as int) returns int
  value = 0
  for i = 0 to 7
    value = value | (buffer[offset + i] << (8 * i))
  end for
  return value
end function

function ticks(buffer) returns int
#if TARGET_OS == "windows"
  counter(buffer)
  return read64(buffer, 0)
#else
  counter(1, buffer)
  return read64(buffer, 0) * 1000000000 + read64(buffer, 8)
#endif
end function

function emptyWorker()
  return 0
end function

function flushHandoffs()
  sum = 0
  for i = 0 to 15
    small = bytes(8, i)
    sum += small[0]
  end for
  return sum
end function

function createdThreads(count, withPayload, clearPayload, startAndClose)
  closed = 0
  for i = 0 to count - 1
    id = i
    if withPayload then id = stringRepeat("x", 1024 * 1024) end if
    worker = Thread(emptyWorker, id)
    if clearPayload then worker.SetLogicalId(0) end if
    if startAndClose then
      if not worker.Start() then return -1 end if
      if not worker.Join() then return -2 end if
    end if
    if startAndClose then
      if worker.Close() then closed += 1 end if
    end if
  end for
  return closed
end function

function droppedGraph()
  graph = [bytes(16 * 1024 * 1024, 17)]
  return graph[0][0]
end function

struct Node
  value
end struct

function broadGraph()
  graph = array(200000, void)
  for i = 0 to 199999
    graph[i] = Node(i)
  end for
  gc_collect()
  print "broad_live=" + gc_stat(1)
  print "broad_worklist_bytes=" + gc_stat(13) * 8
  return graph[199999].value
end function

function gcSample(timer, perSecond, memory)
  flushHandoffs()
  gc_collect()
  live = gc_stat(1)
  committed = heap_bytes_committed()
  nativeCommit = 0
#if TARGET_OS == "windows"
  if memoryInfo(process(), memory, 80) == 0 then return -1 end if
  nativeCommit = read64(memory, 72)
#endif
  started = ticks(timer)
  for i = 0 to 49
    gc_collect()
  end for
  elapsed = ticks(timer) - started
  print "live=" + live
  print "heap_committed=" + committed
  print "private_commit=" + nativeCommit
  print "gc50_ms=" + elapsed * 1000 / perSecond
  return 0
end function

function main(args)
  mode = args[0]
  timer = bytes(16)
  memory = bytes(80)
  perSecond = 1000000000
#if TARGET_OS == "windows"
  frequency(timer)
  perSecond = read64(timer, 0)
#endif
  if mode == "contexts" or mode == "closed-contexts" then
    gcSample(timer, perSecond, memory)
    count = 50000
    startAndClose = false
    if mode == "closed-contexts" then
      count = 1000
      startAndClose = true
    end if
    for batch = 1 to 2
      print "closed=" + createdThreads(count, false, false, startAndClose)
      print "contexts=" + count * batch
      gcSample(timer, perSecond, memory)
    end for
  else if mode == "ids" or mode == "cleared-ids" then
    flushHandoffs()
    gc_collect()
    print "before_live=" + gc_stat(1)
    print "closed=" + createdThreads(16, true, mode == "cleared-ids", false)
    flushHandoffs()
    gc_collect()
    print "after_live=" + gc_stat(1)
  else if mode == "handoff" then
    flushHandoffs()
    gc_collect()
    print "before_live=" + gc_stat(1)
    droppedGraph()
    gc_collect()
    retained = gc_stat(1)
    flushHandoffs()
    gc_collect()
    released = gc_stat(1)
    print "dropped_graph_live=" + retained
    print "flushed_live=" + released
  else if mode == "worklist" then
    print "before_worklist_bytes=" + gc_stat(13) * 8
    broadGraph()
    flushHandoffs()
    gc_collect()
    for i = 0 to 8
      gc_collect()
    end for
    print "after_live=" + gc_stat(1)
    print "after_worklist_bytes=" + gc_stat(13) * 8
  else
    return 99
  end if
  return 0
end function
