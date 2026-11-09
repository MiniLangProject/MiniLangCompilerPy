// Fused string allocation must retain each worker's private source while a
// peer collects the shared heap. Publish results only through thread results.
function worker(seed)
  expected = stringRepeat("abcdef", 700)
  for i = 1 to 100
    source = bytes(expected)
    if i % 7 == 0 then gc_collect() end if
    text = decode(slice(source, 1, len(source) - 2))
    if text != stringSlice(expected, 1, len(expected) - 2) then
      return error(1950, "threaded decode/slice data corruption")
    end if
  end for
  return seed
end function

function main(args)
  gc_set_limit(65536)
  first = Thread(worker)
  second = Thread(worker)
  if not first.Start(41) or not second.Start(42) then return 1 end if
  for i = 1 to 10
    gc_collect()
    threadSleep(0)
  end for
  if not first.Join(10000) or not second.Join(10000) then return 2 end if
  if first.Result() != 41 or second.Result() != 42 then return 3 end if
  if not first.Close() or not second.Close() then return 4 end if
  print "[OK] decode/slice worker GC roots"
  return 0
end function
