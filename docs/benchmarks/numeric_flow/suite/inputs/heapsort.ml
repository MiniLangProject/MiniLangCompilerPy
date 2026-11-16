function dataHeapSift(values as array, startIndex as int, count as int) returns void
  root = startIndex
  while root * 2 + 1 < count
    child = root * 2 + 1
    if child + 1 < count and values[child] < values[child + 1] then
      child = child + 1
    end if
    if values[root] < values[child] then
      temporary = values[root]
      values[root] = values[child]
      values[child] = temporary
      root = child
    else
      return
    end if
  end while
end function

function bench(n as int, seed as int) returns int
  if n <= 0 then return 0 end if
  values = array(n, 0)
  state = seed & 4294967295
  for i = 0 to n - 1
    state = (state * 1664525 + 1013904223) & 4294967295
    values[i] = state & 2147483647
  end for
  startIndex = (n div 2) - 1
  while startIndex >= 0
    dataHeapSift(values, startIndex, n)
    startIndex = startIndex - 1
  end while
  last = n - 1
  while last > 0
    temporary = values[0]
    values[0] = values[last]
    values[last] = temporary
    dataHeapSift(values, 0, last)
    last = last - 1
  end while
  checksum = 0
  for i = 0 to n - 1
    checksum = (checksum * 257 + values[i]) & 1073741823
  end for
  return checksum
end function

// Appended to each independent MiniLang kernel. No gc_stat instrumentation.
extern function measurement_clock(clockId as i32, output as bytes) from "libc.so.6" symbol "clock_gettime" returns i32

function measurement_read64(data as bytes, offset as int) returns int
    value = 0
    for j = 0 to 7
        value = value | (data[offset + j] << (j * 8))
    end for
    return value
end function

function measurement_ns(stamp as bytes) returns int
    status = measurement_clock(1, stamp)
    if status != 0 then
        return error(9001, "clock_gettime failed")
    end if
    return measurement_read64(stamp, 0) * 1000000000 + measurement_read64(stamp, 8)
end function

function main(args) returns int
    if len(args) != 3 then return 90 end if
    n = toNumber(args[0])
    reps = toNumber(args[1])
    seed = toNumber(args[2])
    if n < 1 or reps < 1 or reps > 10000000 or seed < 0 or seed > 2147483647 then return 90 end if
    stamp = bytes(16, 0)
    warmup = bench(n, (seed + 65536) & 2147483647)
    checksum = 0
    start = measurement_ns(stamp)
    for r = 0 to reps - 1
        checksum = (checksum + bench(n, (seed + (r & 7)) & 2147483647)) & 2147483647
    end for
    elapsed = measurement_ns(stamp) - start
    print "RESULT " + checksum + " " + elapsed + " " + warmup
    return 0
end function
