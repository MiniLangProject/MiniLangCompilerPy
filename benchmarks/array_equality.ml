// Linux-only isolated equality probe. Setup and output are outside the timer.
// Wide/deep results from the old bounded helper are correctness controls;
// their timings must not be advertised as valid before/after speedups.
extern function clockGettime(clockId as int, value as bytes) from "libc.so.6" symbol "clock_gettime" returns int
extern function getUsage(who as int, value as bytes) from "libc.so.6" symbol "getrusage" returns int
stamp=bytes(16,0)
usage=bytes(144,0)
function read64(data as bytes, at as int) returns int
  upperAt=at+4
  return asm unsafe x64(in data as bytes, in at as int, in upperAt as int, scratch high as int) returns int
    mov result,dword [data.data+at]
    mov high,dword [data.data+upperAt]
    shl high,32
    or result,high
  end asm
end function
function now()
  if clockGettime(1,stamp)!=0 then return error(1,"Monotonic clock failed") end if
  return read64(stamp,0)*1000000000+read64(stamp,8)
end function
function equal(left,right) return left==right end function
function probe(label,left,right,repeats)
  warm=0
  for i=0 to 9
    if equal(left,right) then warm=warm+1 end if
  end for
  getUsage(0,usage) faults=read64(usage,64)
  count=0 requests=gc_stat(22) requestedBytes=gc_stat(23)
  collections=gc_stat(0) pauses=gc_stat(24)
  started=now()
  for i=0 to repeats-1
    if equal(left,right) then count=count+1 end if
  end for
  elapsed=now()-started
  allocated=gc_stat(22)-requests
  requestedBytes=gc_stat(23)-requestedBytes collections=gc_stat(0)-collections pauses=gc_stat(24)-pauses
  getUsage(0,usage) faults=read64(usage,64)-faults
  print "ARRAY_EQ_BENCH "+label+" "+repeats+" "+count+" "+elapsed+" "+allocated+" "+requestedBytes+" "+collections+" "+pauses+" "+faults
end function
function chain(depth)
  value=[71,"leaf"]
  for i=0 to depth-1
    value=[value,i]
  end for
  return value
end function
function main(args)
  gc_set_limit(0)
  sizes=[5,13,81,256,1024,65536]
  repeats=[200000,200000,100000,50000,4000,64]
  for i=0 to len(sizes)-1
    probe("width_"+sizes[i],array(sizes[i],71),array(sizes[i],71),repeats[i])
  end for
  for each depth in [32,128,1024,4096]
    probe("depth_"+depth,chain(depth),chain(depth),20)
  end for
  return 0
end function
