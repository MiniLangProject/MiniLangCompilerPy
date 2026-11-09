// Focused copy/allocation workload. Keep GC diagnostic counters disabled so
// instrumentation does not alter the allocation hot path being measured.
function main(args)
  data = bytes(4096, 65)
  gc_set_limit(33554432)
  checksum = 0
  for i = 1 to 150000
    text = decode(slice(data, 0, 4093))
    checksum += len(text)
  end for
  print checksum
  return 0
end function
