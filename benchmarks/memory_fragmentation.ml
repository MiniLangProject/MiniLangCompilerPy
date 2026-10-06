/// Measure successful free-list searches with unusable split remainders.
#if TARGET_OS == "windows"
extern function counter(output as bytes) from "kernel32.dll" symbol "QueryPerformanceCounter" returns i32
extern function frequency(output as bytes) from "kernel32.dll" symbol "QueryPerformanceFrequency" returns i32
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

function fragmentedHeap(smallCount, requestCount)
  blockers = array(smallCount + requestCount, void)
  holes = array(smallCount + requestCount, void)
  for i = 0 to smallCount - 1
    holes[i] = bytes(128, i % 251)
    blockers[i] = bytes(8, 19)
  end for
  for i = 0 to requestCount - 1
    holes[smallCount + i] = bytes(8192, i % 251)
    blockers[smallCount + i] = bytes(8, 19)
  end for
  return blockers
end function

function main(args)
  timer = bytes(16)
  perSecond = 1000000000
#if TARGET_OS == "windows"
  frequency(timer)
  perSecond = read64(timer, 0)
#endif
  count = 0
  requestCount = 1000
  if args[0] == "double" then requestCount = 2000 end if
  if args[0] == "quadruple" then requestCount = 4000 end if
  if args[0] == "many" then count = 5000 end if
  blockers = fragmentedHeap(count, requestCount)
  results = array(requestCount, void)
  gc_collect()
  probes = gc_stat(6)
  started = ticks(timer)
  for i = 0 to requestCount - 1
    results[i] = bytes(4096, i % 251)
  end for
  elapsed = ticks(timer) - started
  probes = gc_stat(6) - probes
  for i = 0 to requestCount - 1
    if results[i][4095] != i % 251 then return 1 end if
  end for
  for i = 0 to len(blockers) - 1
    if blockers[i][0] != 19 then return 2 end if
  end for
  print "small_holes=" + count
  print "allocations=" + requestCount
  print "free_list_probes=" + probes
  print "allocation_ms=" + elapsed * 1000 / perSecond
  return 0
end function
