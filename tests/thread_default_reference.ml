// The only constructor reference is a default argument; allocation still needs TLS/locks.
function selectWorker(worker=Thread(allocateWorker))
  return worker
end function
ready=array(4,0) releaseWorkers=false
function allocateWorker(index)
  global ready,releaseWorkers
  ready[index]=1
  while not releaseWorkers
    threadSleep(0)
  end while
  value=void
  for i=0 to 19999
    value=bytes(1,index+11)
  end for
  return value
end function
function main(args)
  global releaseWorkers
  gc_set_limit(0)
  workers=[selectWorker(),selectWorker(),selectWorker(),selectWorker()]
  for i=0 to 3
    if not workers[i].Start(i) then return 1 end if
  end for
  while ready[0]+ready[1]+ready[2]+ready[3]<4
    threadSleep(0)
  end while
  requests=gc_stat(22) requested=gc_stat(23) refills=gc_stat(7)
  releaseWorkers=true
  for i=0 to 3
    if not workers[i].Join(30000) then return 2 end if
  end for
  if gc_stat(22)-requests!=80000 then
    print "FAIL requests="+(gc_stat(22)-requests)
    return 3
  end if
  if gc_stat(23)-requested!=1920000 then return 4 end if
  if gc_stat(7)<=refills then return 5 end if
  for i=0 to 3
    result=workers[i].Result()
    if result[0]!=i+11 or not workers[i].Close() then return 6 end if
  end for
  gc_collect()
  if gc_stat(26)<=0 or gc_stat(25)<gc_stat(26) then return 7 end if
  print "THREAD DEFAULT REFERENCE [OK] objects=80000 bytes=1920000"
  return 0
end function
