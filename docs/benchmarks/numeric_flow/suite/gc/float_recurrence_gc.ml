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
