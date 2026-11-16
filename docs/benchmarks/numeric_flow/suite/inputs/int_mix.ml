// Dependent integer arithmetic; all intermediates stay below 2^60.
function bench(n as int, seed as int) returns int
  x as int = seed & 2147483647
  y as int = (seed ^ 1103515245) & 2147483647
  checksum as int = 0
  i as int = 0
  while i < n
    x = (x * 1664525 + 1013904223) & 2147483647
    y = ((y ^ (x >> 7)) * 48271 + 17) & 2147483647
    checksum = (checksum + ((x ^ y) & 65535)) & 2147483647
    i = i + 1
  end while
  return (checksum ^ x ^ y) & 2147483647
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
