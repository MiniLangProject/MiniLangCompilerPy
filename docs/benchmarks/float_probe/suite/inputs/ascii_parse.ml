// Setup is timed: generate six decimal digits plus a newline for every value.
function bench(n as int, seed as int) returns int
  data = bytes(n * 7, 0)
  state as int = seed & 2147483647
  i as int = 0
  while i < n
    state = (state * 1664525 + 1013904223) & 2147483647
    value as int = 100000 + state % 900000
    offset as int = i * 7
    digit as int = 5
    while digit >= 0
      data[offset + digit] = 48 + value % 10
      value = value div 10
      digit = digit - 1
    end while
    data[offset + 6] = 10
    i = i + 1
  end while

  current as int = 0
  checksum as int = 0
  pos as int = 0
  size as int = n * 7
  while pos < size
    byteValue as int = data[pos]
    if byteValue >= 48 and byteValue <= 57 then
      current = current * 10 + byteValue - 48
    else
      checksum = (checksum + current) & 2147483647
      current = 0
    end if
    pos = pos + 1
  end while
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
