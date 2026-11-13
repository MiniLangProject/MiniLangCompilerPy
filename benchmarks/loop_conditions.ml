/// Measure loop bodies mirrored from the optimizer regression suite.
/// Run preserved before/after executables with compare_loop_conditions.py.
function single_use_dynamic_loop(values as array) returns int
  total = 0
  for i = 0 to len(values) - 1
    total = total + values[i]
  end for
  return total
end function

function elif_index_loop(values as array, mode as int) returns int
  total = 0
  for i = 0 to len(values) - 1
    total += values[i]
    if mode < 0 then
      total += 10
    else if values[i] > 1 then
      total += 1
    end if
  end for
  return total
end function

function byte_elif_index_loop(values as bytes, mode as int) returns int
  total = 0
  for i = 0 to len(values) - 1
    total += values[i]
    if mode < 0 then
      total += 10
    else if values[i] > 1 then
      total += 1
    end if
  end for
  return total
end function

function case_value_index_loop(values as array, key as int) returns int
  total = 0
  for i = 0 to len(values) - 1
    total += values[i]
    switch key
      case values[i]
        total += 1
        break
      end case
      case default
        total += 2
        break
      end case
    end switch
  end for
  return total
end function

function case_lower_index_loop(values as array, key as int) returns int
  total = 0
  for i = 0 to len(values) - 1
    total += values[i]
    switch key
      case values[i] to 3
        total += 1
        break
      end case
      case default
        total += 2
        break
      end case
    end switch
  end for
  return total
end function

#if TARGET_OS == "windows"
extern function counter(output as bytes) from "kernel32.dll" symbol "QueryPerformanceCounter" returns i32
extern function frequency(output as bytes) from "kernel32.dll" symbol "QueryPerformanceFrequency" returns i32
#else
extern function counter(clockId as i32, output as bytes) from "libc.so.6" symbol "clock_gettime" returns i32
#endif

/// Decode nonnegative native timer fields using caller-owned storage.
function readCounter(buffer, offset as int) returns int
  value = 0
  for i = 0 to 7
    value = value | (buffer[offset + i] << (8 * i))
  end for
  return value
end function

/// Read a monotonic timer without allocating scratch buffers in the workload.
function ticks(buffer) returns int
#if TARGET_OS == "windows"
  counter(buffer)
  return readCounter(buffer, 0)
#else
  counter(1, buffer)
  return readCounter(buffer, 0) * 1000000000 + readCounter(buffer, 8)
#endif
end function

function main(args)
  mode = "array-elif"
  if len(args) > 0 then mode = args[0] end if
  values = array(512, 2)
  data = bytes(512, 2)
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
  if mode == "array-elif" then
    for round = 0 to 39999
      checksum += elif_index_loop(values, 0)
    end for
  else if mode == "bytes-elif" then
    for round = 0 to 39999
      checksum += byte_elif_index_loop(data, 0)
    end for
  else if mode == "case-value" then
    for round = 0 to 39999
      checksum += case_value_index_loop(values, 2)
    end for
  else if mode == "case-range" then
    for round = 0 to 39999
      checksum += case_lower_index_loop(values, 2)
    end for
  else if mode == "single-control" then
    for round = 0 to 39999
      checksum += single_use_dynamic_loop(values)
    end for
  else
    return 2
  end if
  finished = ticks(timer)
  allocated = heap_bytes_used() - before
  elapsed = ((finished - started) * 1000) / ticksPerSecond
  expected = 61440000
  if mode == "single-control" then expected = 40960000 end if
  if checksum != expected then return 3 end if
  print mode + " ms=" + elapsed + " bytes=" + allocated + " checksum=" + checksum
  return 0
end function
