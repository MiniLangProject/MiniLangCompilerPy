/// Measure monomorphic and polymorphic method dispatch without loop allocations.
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

final class Only
  function value() returns int
    return 3
  end function
end class

class First
  function other() returns int
    return 3
  end function
end class

class Second
  function other() returns int
    return 5
  end function
end class

/// A parameter has no concrete constructor fact, forcing runtime method lookup.
function mono(receiver, n as int) returns int
  total = 0
  for i = 0 to n - 1
    total += receiver.value()
  end for
  return total
end function

function typed(receiver as Only, n as int) returns int
  total = 0
  for i = 0 to n - 1
    total += receiver.value()
  end for
  return total
end function

function poly(receivers, n as int) returns int
  total = 0
  for i = 0 to n - 1
    total += receivers[i & 1].other()
  end for
  return total
end function

function control(n as int) returns int
  total = 0
  for i = 0 to n - 1
    total += 3
  end for
  return total
end function

function main(args)
  mode = args[0]
  timer = bytes(16)
  rate = 1000000000
#if TARGET_OS == "windows"
  frequency(timer)
  rate = readCounter(timer, 0)
#endif
  receiver = Only()
  others = [First(), Second()]
  gc_collect()
  before = heap_bytes_used()
  start = ticks(timer)
  result = 0
  if mode == "mono" then result = mono(receiver, 20000000) end if
  if mode == "typed" then result = typed(receiver, 20000000) end if
  if mode == "poly" then result = poly(others, 20000000) end if
  if mode == "control" then result = control(20000000) end if
  elapsed = (ticks(timer) - start) * 1000 / rate
  if mode == "mono" and result != 60000000 then return 1 end if
  if mode == "typed" and result != 60000000 then return 4 end if
  if mode == "poly" and result != 80000000 then return 2 end if
  if mode == "control" and result != 60000000 then return 3 end if
  print mode + " ms=" + elapsed + " bytes=" + (heap_bytes_used() - before) + " checksum=" + result
  return 0
end function
