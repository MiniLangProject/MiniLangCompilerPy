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


function main(args) returns int
    if len(args) != 3 then return 90 end if
    n = toNumber(args[0])
    reps = toNumber(args[1])
    seed = toNumber(args[2])
    checksum = 0
    beforeGC = gc_stat(0)
    beforeUsed = heap_bytes_used()
    beforeCount = heap_count()
    beforeFree = heap_free_bytes()
    beforeTLAB = gc_stat(7)
    for r = 0 to reps - 1
        checksum = (checksum + bench(n, (seed + (r & 7)) & 2147483647)) & 2147483647
    end for
    afterGC = gc_stat(0)
    afterUsed = heap_bytes_used()
    afterCount = heap_count()
    afterFree = heap_free_bytes()
    afterTLAB = gc_stat(7)
    thresholdAll = gc_stat(9)
    thresholdSmall = gc_stat(10)
    adaptive = gc_stat(11)
    gc_collect()
    postLive = gc_stat(1)
    postReclaimed = gc_stat(2)
    postCount = heap_count()
    postUsed = heap_bytes_used()
    postFree = heap_free_bytes()
    print "GC " + checksum + " " + beforeGC + " " + afterGC + " " + beforeUsed + " " + afterUsed + " " + beforeCount + " " + afterCount + " " + beforeFree + " " + afterFree + " " + beforeTLAB + " " + afterTLAB + " " + thresholdAll + " " + thresholdSmall + " " + adaptive + " " + postLive + " " + postReclaimed + " " + postCount + " " + postUsed + " " + postFree
    return 0
end function
