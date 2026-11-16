// Eight pseudo-random read/modify/write passes; modulo is part of the work.
function bench(n as int, seed as int) returns int
  if n <= 0 then return 0 end if
  values = array(n, 0)
  state = seed & 4294967295
  for i = 0 to n - 1
    state = (state * 1664525 + 1013904223) & 4294967295
    values[i] = state & 65535
  end for
  checksum = 0
  for roundIndex = 0 to 7
    for i = 0 to n - 1
      state = (state * 1664525 + 1013904223) & 4294967295
      index = state % n
      value = values[index]
      values[index] = (value + (state & 1023) + roundIndex) & 65535
      checksum = (checksum + value + (index & 255)) & 1073741823
    end for
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
