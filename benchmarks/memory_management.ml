/// Isolated allocation/GC workloads; compare identical sources across compilers.
#if TARGET_OS == "windows"
extern function counter(output as bytes) from "kernel32.dll" symbol "QueryPerformanceCounter" returns i32
extern function frequency(output as bytes) from "kernel32.dll" symbol "QueryPerformanceFrequency" returns i32
#else
extern function counter(clockId as i32, output as bytes) from "libc.so.6" symbol "clock_gettime" returns i32
#endif

function readCounter(buffer, offset as int) returns int
  value = 0
  for i = 0 to 7
    value = value | (buffer[offset + i] << (8 * i))
  end for
  return value
end function

function ticks(buffer) returns int
#if TARGET_OS == "windows"
  counter(buffer)
  return readCounter(buffer, 0)
#else
  counter(1, buffer)
  return readCounter(buffer, 0) * 1000000000 + readCounter(buffer, 8)
#endif
end function

struct BenchNode
  value
  payload
end struct

function main(args)
  mode = args[0]
  timer = bytes(16)
  perSecond = 1000000000
#if TARGET_OS == "windows"
  frequency(timer)
  perSecond = readCounter(timer, 0)
#endif
  keep = []
  ring = array(256, void)
  if mode == "leaf-mark" or mode == "graph-mark" or mode == "pause-samples" then
    keep = array(100000, void)
    for i = 0 to 99999
      if mode == "leaf-mark" then keep[i] = bytes(64, i % 251)
      else keep[i] = BenchNode(i, [i, i + 1])
      end if
    end for
  end if
  if mode == "large-live" then
    keep = array(400000, void)
    for i = 0 to 399999
      keep[i] = BenchNode(i, bytes(128, i % 251))
    end for
  end if
  if mode == "fragmented" then
    keep = array(12000, void)
    for i = 0 to 11999
      keep[i] = bytes(128, i % 251)
    end for
    for i = 0 to 5999
      keep[i * 2] = void
    end for
  end if
  gc_collect()
  if mode == "pause-samples" then
    pauses = array(100, 0)
    for sample = 0 to 99
      pauseStart = ticks(timer)
      gc_collect()
      pauses[sample] = ticks(timer) - pauseStart
    end for
    // Validate roots after all timed collections and print only afterward.
    if keep[99999].value != 99999 then return 21 end if
    print "frequency=" + perSecond
    for sample = 0 to 99
      print pauses[sample]
    end for
    return 0
  end if
  checksum = 0
  started = ticks(timer)
  if mode == "small-churn" or mode == "large-live" then
    for i = 0 to 4999999
      ring[i % 256] = bytes(64, i % 251)
      checksum += ring[i % 256][0]
    end for
  end if
  if mode == "fragmented" then
    for i = 0 to 3999
      ring[i % 256] = bytes(8192, i % 251)
      checksum += ring[i % 256][0]
    end for
  end if
  if mode == "leaf-mark" or mode == "graph-mark" then
    for i = 0 to 39
      gc_collect()
    end for
    if mode == "leaf-mark" then
      for i = 0 to 99999
        checksum += keep[i][0]
      end for
    else
      for i = 0 to 99999
        checksum += keep[i].payload[1]
      end for
    end if
  end if
  if mode == "control" then
    for i = 0 to 4999999
      checksum += (i div 7) % 251
    end for
  end if
  elapsed = (ticks(timer) - started) * 1000.0 / perSecond
  // Keep the retained graph observable across the complete timed workload.
  if mode == "large-live" then checksum += keep[399999].value end if
  if mode == "fragmented" then checksum += keep[11999][0] end if
  print mode + " ms=" + elapsed + " bytes=" + heap_bytes_committed() + " checksum=" + checksum
  return 0
end function
