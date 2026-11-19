function fillChunk(data as bytes, value as int) returns void
  first as int = value
  second as int = (value ^ 1431655765) & 2147483647
  j as int = 0
  while j < 8
    digit as int = first & 15
    if digit < 10 then
      data[j] = 48 + digit
    else
      data[j] = 87 + digit
    end if
    digit = second & 15
    if digit < 10 then
      data[j + 8] = 48 + digit
    else
      data[j + 8] = 87 + digit
    end if
    first = first >> 4
    second = second >> 4
    j = j + 1
  end while
end function

function bench(n as int, seed as int) returns int
  chunkBytes = bytes(16, 0)
  text = ""
  state as int = seed & 2147483647
  i as int = 0
  while i < n
    state = (state * 1664525 + 1013904223) & 2147483647
    fillChunk(chunkBytes, state)
    chunk = decode(chunkBytes)
    text = text + chunk
    i = i + 1
  end while

  // Include a complete copy to bytes and read every resulting UTF-8 byte.
  encoded = bytes(text)
  checksum as int = 0
  pos as int = 0
  size as int = len(encoded)
  while pos < size
    checksum = (checksum * 131 + encoded[pos]) & 2147483647
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
