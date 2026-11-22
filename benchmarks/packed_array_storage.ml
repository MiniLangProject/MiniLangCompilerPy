// Measure the storage and access trade-off for a million signed 32-bit values.
#option PACKED: bool = false
// ACCESS: 0 reads and writes, 1 reads only, 2 writes only.
#option ACCESS: int = 0

#if PACKED
import std.ds.packed_array
#endif

function main(args)
  size = 1000000
  before = heap_bytes_used()
#if PACKED
  values = std.ds.packed_array.Int32Array(size)
#else
  values = array(size, 0)
#endif
  allocated = heap_bytes_used() - before
  total = 0
  for i = 0 to size - 1
#if ACCESS != 1
#if PACKED
    values.set(i, i)
#else
    values[i] = i
#endif
#endif
#if ACCESS != 2
#if PACKED
    total += values.get(i)
#else
    total += values[i]
#endif
#endif
  end for
#if ACCESS == 2
#if PACKED
  total = values.get(-1)
#else
  total = values[-1]
#endif
#endif
  print allocated
  print total
  return 0
end function
