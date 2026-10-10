// Identical fixture for baseline/full-stop and optional concurrent collectors.
extern function counter(output as bytes) from "kernel32.dll" symbol "QueryPerformanceCounter" returns i32
extern function frequency(output as bytes) from "kernel32.dll" symbol "QueryPerformanceFrequency" returns i32

struct PauseNode
  value
  child
end struct

pauseGraph = void
synchronized collectorStarted = false

function readTicks(buffer)
  value = 0
  for i = 0 to 7
    value = value | (buffer[i] << (8 * i))
  end for
  return value
end function

function ticks(buffer)
  counter(buffer)
  return readTicks(buffer)
end function

function collectWorker()
  global collectorStarted
  collectorStarted = true
  for i = 0 to 11
    gc_collect()
    threadSleep(1)
  end for
end function

function main(args)
  global pauseGraph
  gc_set_limit(0)
  pauseGraph = array(800000, void)
  for i = 0 to 799999
    pauseGraph[i] = PauseNode(i, [i, i + 1])
  end for
  gc_collect()
  timer = bytes(8)
  frequency(timer)
  hz = readTicks(timer)
  worker = Thread(collectWorker)
  if not worker.Start() then return 20 end if
  maximum = 0
  iterations = 0
  markProgress = 0
  previous = ticks(timer)
  while worker.IsAlive()
    current = ticks(timer)
    interval = current - previous
    if interval > maximum then maximum = interval end if
    previous = current
    iterations += 1
    if gc_stat(17) == 1 then markProgress += 1 end if
  end while
  if not worker.Join(10000) or not worker.Close() then return 21 end if
  if pauseGraph[799999].child[1] != 800000 then return 22 end if
  maxPauseTicks = gc_stat(19)
  if typeof(maxPauseTicks) != "int" then maxPauseTicks = -1 end if
  print "CONCURRENT_PAUSES frames=" + iterations + " mark_progress=" + markProgress + " max_ms=" + maximum * 1000.0 / hz + " pause_max_ticks=" + maxPauseTicks + " frequency=" + hz
  return 0
end function
