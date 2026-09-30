/// Runtime and allocation benchmark; run before/after binaries alternately.
/// Heap deltas count allocated MiniLang heap bytes, not process working set.
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

function arithmetic(n as int) returns int
  sum = 0
  for i = 0 to n - 1
    x = i - 4000000
    sum += (x div 8) + (x div 1024)
  end for
  return sum
end function

function main(args)
  mode = "division"
  if len(args) > 0 then mode = args[0] end if
  source = stringRepeat("abcd", 1024)
  singleton = [source]
  small = stringRepeat("a", 1)
  pieces = ["a", "b", "c"]
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
  if mode == "division" then
    checksum = arithmetic(24000000)
  end if
  if mode == "division-constants" then
    for i = 0 to 5999999
      x = i - 3000000
      checksum += (x div 3) + (x div 10) + (x div 31)
    end for
  end if
  if mode == "local-cse" then
    for i = 0 to 5999999
      x = i & 1023
      checksum += (x + 3) * (x + 3)
    end for
  end if
  if mode == "division-wide" then
    seed = 20260930
    for i = 0 to 5999999
      seed = seed * 1103515245 + 12345
      checksum += (seed div 3) + (seed div 10) + (seed div 31)
    end for
  end if
  if mode == "integer-format-small" then
    for i = 0 to 999999
      text = str(i & 31)
      checksum += len(text)
    end for
  end if
  if mode == "integer-format" then
    for i = 0 to 999999
      text = str(i - 1152921504606846975)
      checksum += len(text)
    end for
  end if
  if mode == "repeat" then
    for i = 0 to 511
      s = stringRepeat("abc", 32768)
      checksum += len(s)
    end for
  end if
  if mode == "repeat-one" then
    for i = 0 to 19999
      s = stringRepeat(source, 1)
      checksum += len(s)
    end for
  end if
  if mode == "concat-empty" then
    empty = ""
    for i = 0 to 19999
      s = source + empty
      checksum += len(s)
    end for
  end if
  if mode == "join-one" then
    for i = 0 to 19999
      s = stringJoin(singleton, ",")
      checksum += len(s)
    end for
  end if
  if mode == "concat-control" then
    for i = 0 to 19999
      s = source + "x"
      checksum += len(s)
    end for
  end if
  if mode == "concat-small-control" then
    for i = 0 to 999999
      s = small + "b"
      checksum += len(s)
    end for
  end if
  if mode == "repeat-two-control" then
    for i = 0 to 999999
      s = stringRepeat(small, 2)
      checksum += len(s)
    end for
  end if
  if mode == "repeat-two-multi-control" then
    for i = 0 to 999999
      s = stringRepeat("abc", 2)
      checksum += len(s)
    end for
  end if
  if mode == "join-control" then
    for i = 0 to 199999
      s = stringJoin(pieces, ",")
      checksum += len(s)
    end for
  end if
  finished = ticks(timer)
  allocated = heap_bytes_used() - before
  elapsed = ((finished - started) * 1000) / ticksPerSecond
  print mode + " ms=" + elapsed + " bytes=" + allocated + " checksum=" + checksum
  return 0
end function
