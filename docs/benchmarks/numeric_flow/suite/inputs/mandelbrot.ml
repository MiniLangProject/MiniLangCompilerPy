// n is the side length, so the raster contains n*n pixels.
// Arithmetic can normalize an exact floating result to an int value in MiniLang.
// These numeric locals therefore intentionally have no `as float` tag guard.
function bench(n as int, seed as int) returns int
  scale = 3.0 / toFloat(n)
  offset = toFloat(seed & 255) * 0.0000001
  checksum as int = 0
  py as int = 0
  while py < n
    cy = -1.5 + toFloat(py) * scale
    px as int = 0
    while px < n
      cx = -2.0 + toFloat(px) * scale + offset
      zr = 0.0
      zi = 0.0
      zr2 = 0.0
      zi2 = 0.0
      iteration as int = 0
      while iteration < 80 and zr2 + zi2 <= 4.0
        zi = 2.0 * zr * zi + cy
        zr = zr2 - zi2 + cx
        zr2 = zr * zr
        zi2 = zi * zi
        iteration = iteration + 1
      end while
      checksum = checksum + iteration
      px = px + 1
    end while
    py = py + 1
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
