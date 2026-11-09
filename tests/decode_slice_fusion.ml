import std.string_builder as sb

failures = 0
order = 0

function check(ok, message)
  global failures
  if not ok then
    failures += 1
    print "FAIL: " + message
  end if
end function

function reference(data, offset, count)
  part = slice(data, offset, count)
  return decode(part)
end function

function fused(data, offset, count)
  return decode(slice(data, offset, count))
end function

function source()
  global order
  order = order * 10 + 1
  return bytes("abcdef")
end function

function offset()
  global order
  order = order * 10 + 2
  gc_collect()
  return 1
end function

function count()
  global order
  order = order * 10 + 3
  gc_collect()
  return 3
end function

function main(args)
  if len(args) > 0 and args[0] == "bench" then
    data = bytes(4096, 65)
    gc_set_limit(33554432)
    checksum = 0
    for i = 1 to 150000
      text = decode(slice(data, 0, 4093))
      checksum += len(text)
    end for
    print checksum
    return 0
  end if
  values = [bytes("abcdef"), bytes("a\0b"), bytes("äö"), bytes(0), void, false, 1, "abc", [1, 2]]
  offsets = [-99, -6, -3, -1, 0, 1, 3, 6, 99, false, void, 1.5]
  counts = [-1, 0, 1, 2, 3, 6, 99, 2147483648, false, void, 1.5]
  for each data in values
    for each start in offsets
      for each size in counts
        check(fused(data, start, size) == reference(data, start, size), "slice/decode equivalence")
      end for
    end for
  end for
  gc_set_limit(1)
  result = decode(slice(source(), offset(), count()))
  check(order == 123, "left-to-right evaluation exactly once")
  check(result == "bcd", "source remains rooted across argument GC")
  gc_set_limit(0)
  builder = sb.StringBuilder.withCapacity(32)
  builder.appendString("first")
  snapshot = builder.toString()
  builder.appendString(" second")
  check(snapshot == "first", "materialized string is independent of mutable bytes")
  check(builder.toString() == "first second", "partially filled StringBuilder")
  sliceAlias = slice
  decodeAlias = decode
  check(decodeAlias(sliceAlias(bytes("abcdef"), 1, 3)) == "bcd", "first-class builtin calls")
  check(decode(slice(bytes("abcdef"), 1, 3), "utf-8") == "bcd", "explicit encoding remains valid")
  check(decode(slice(bytes("abcdef"), 1, 3), 42) == void, "invalid encoding is still rejected")
  data = bytes(8192, 65)
  gc_collect()
  before = heap_bytes_used()
  beforeRequests = gc_stat(5)
  result = decode(slice(data, 1, 8191))
  requests = gc_stat(5) - beforeRequests
  allocated = heap_bytes_used() - before
  check(len(result) == 8191, "large copied string")
  // One string plus its GC header/alignment; the old bytes slice doubled this.
  check(allocated < 8300, "no intermediate slice allocation")
  // These allocations exceed the TLAB small-object limit. Count central
  // requests too: reusing free blocks can hide allocations from heap growth.
  check(requests == 1, "exactly one large allocation")
  if failures != 0 then return 1 end if
  print "[OK] decode/slice fusion: bounds, types, order, roots and allocations"
  return 0
end function
