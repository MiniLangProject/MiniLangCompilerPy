/// Runtime and allocation benchmark; run before/after binaries alternately.
/// Heap deltas measure bump-pointer growth, not cumulative allocation or RSS.
#if TARGET_OS == "windows"
extern function counter(output as bytes) from "kernel32.dll" symbol "QueryPerformanceCounter" returns i32
extern function frequency(output as bytes) from "kernel32.dll" symbol "QueryPerformanceFrequency" returns i32
#else
extern function counter(clockId as i32, output as bytes) from "libc.so.6" symbol "clock_gettime" returns i32
#endif

/// Decode the native timer's nonnegative 64-bit fields without allocating.
function readCounter(buffer, offset as int) returns int
  value = 0
  for i = 0 to 7
    value = value | (buffer[offset + i] << (8 * i))
  end for
  return value
end function

/// Reuse caller-owned scratch memory, keeping timing out of the heap delta.
function ticks(buffer) returns int
#if TARGET_OS == "windows"
  counter(buffer)
  return readCounter(buffer, 0)
#else
  counter(1, buffer)
  return readCounter(buffer, 0) * 1000000000 + readCounter(buffer, 8)
#endif
end function

struct Box
  value
end struct
function identity(value)
  return value
end function
function typed(value as int) returns int
  return value + 1
end function
function tags(values as array, n as int) returns int
  count = 0
  for i = 0 to n - 1
    value = values[i & 15]
    if typeof(value) == "int" then count += 1 end if
  end for
  return count
end function
function headers(values as array, n as int) returns int
  count = 0
  for i = 0 to n - 1
    value = values[i & 15]
    if typeof(value) == "string" then count += 1 end if
    if typeof(value) != "array" then count += 2 end if
    if "struct" == typeof(value) then count += 4 end if
  end for
  return count
end function
function guards(values as array, n as int) returns int
  count = 0
  for i = 0 to n - 1
    count += typed(values[i & 15])
  end for
  return count
end function
function control(values as array, n as int) returns int
  count = 0
  for i = 0 to n - 1
    count += i & 15
  end for
  return count
end function
function main(args)
  mode = args[0]
  values = [1, 2, true, false, "a", "b", [1], [2], Box(3), Box(4), bytes(2), identity, void, 1.5, "", 7]
  integers = array(16, 7)
  timer = bytes(16)
  ticksPerSecond = 1000000000
#if TARGET_OS == "windows"
  frequency(timer)
  ticksPerSecond = readCounter(timer, 0)
#endif
  gc_collect()
  before = heap_bytes_used()
  started = ticks(timer)
  checksum = 0
  if mode == "tag" then checksum = tags(values, 40000000) end if
  if mode == "header" then checksum = headers(values, 40000000) end if
  if mode == "guard" then checksum = guards(integers, 40000000) end if
  if mode == "control" then checksum = control(integers, 120000000) end if
  elapsed = (ticks(timer) - started) * 1000 / ticksPerSecond
  delta = heap_bytes_used() - before
  if mode == "tag" and checksum != 7500000 then return 1 end if
  if mode == "header" and checksum != 97500000 then return 2 end if
  if mode == "guard" and checksum != 320000000 then return 3 end if
  if mode == "control" and checksum != 900000000 then return 4 end if
  print mode + " ms=" + elapsed + " bytes=" + delta + " checksum=" + checksum
  return 0
end function
