function main(args)
  kept = [bytes(1024, 47)]
  before = gc_stat(0)
  gc_collect_async()
  collect = gc_collect_async
  collect()
  if gc_stat(0) != before + 2 or kept[0][1023] != 47 then return 1 end if
  print "GC ASYNC FALLBACK [OK]"
  return 0
end function
