// Read-only graph comparisons may allocate spill buffers while other workers
// trigger collection. Every comparison owns a thread-local precise root frame.
sharedLeft=void sharedRight=void
function chain(depth)
  value=[79,"shared graph"]
  for i=0 to depth-1
    value=[value,i]
  end for
  return value
end function
function worker(index)
  for i=0 to 31
    if sharedLeft!=sharedRight then return -1 end if
    temporary=bytes(4096,index+11)
    if temporary[4095]!=index+11 then return -2 end if
    if i%8==0 then gc_collect() end if
  end for
  return index+101
end function
function main(args)
  global sharedLeft,sharedRight
  sharedLeft=chain(192) sharedRight=chain(192)
  gc_set_limit(8192)
  workers=[Thread(worker),Thread(worker),Thread(worker),Thread(worker)]
  for i=0 to 3
    if not workers[i].Start(i) then return 1 end if
  end for
  for i=0 to 3
    if not workers[i].Join(30000) then return 2 end if
    if workers[i].Result()!=i+101 then return 3 end if
    if not workers[i].Close() then return 4 end if
  end for
  gc_collect()
  if sharedLeft!=sharedRight then return 5 end if
  print "ARRAY EQUALITY THREADS [OK] workers=4 comparisons=129"
  return 0
end function
