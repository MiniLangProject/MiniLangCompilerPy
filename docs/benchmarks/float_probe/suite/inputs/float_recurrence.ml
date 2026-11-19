import std.math as math

// Stable coupled binary64 recurrences with an accumulated observable result.
// Numeric locals permit MiniLang's exact-integral-result normalization to int.
// An `as float` annotation would assert a tag, rather than coerce every result.
function bench(n as int, seed as int) returns int
  x = 0.123456789012345 + toFloat(seed & 65535) * 0.00000123456789
  y = 0.987654321098765 + toFloat((seed >> 8) & 65535) * 0.00000034567891
  accumulated = 0.0
  i as int = 0
  while i < n
    nextX = x * 0.9999991 + y * 0.0000003 + 0.0000007
    nextY = y * 0.9999989 + x * 0.0000002 + 0.0000005
    x = nextX
    y = nextY
    accumulated = accumulated + x * 0.333333333333333 + y * 0.142857142857143
    i = i + 1
  end while
  return math.truncInt(accumulated * 1000.0) & 2147483647
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
