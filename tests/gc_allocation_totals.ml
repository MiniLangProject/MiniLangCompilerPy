// Allocation totals include fast bump objects and escaped doubles.
checks=0 failures=0
function check(value,label)
  global checks,failures
  checks=checks+1
  if not value then failures=failures+1 print "FAIL "+label end if
end function
function reader() return gc_stat end function
function main(args)
  gc_set_limit(0)
  read=reader()
  check(typeof(read(22))=="int" and typeof(read(23))=="int","total counters available through first-class reader")
  check(typeof(read(16))=="void" and typeof(read(21))=="void","disabled concurrent slots remain reserved")
  check(typeof(read(27))=="void" and typeof(read(-1))=="void","invalid indices stay void")
  tiny=void
  requests=read(22) requested=read(23) central=read(5)
  for i=0 to 999
    tiny=bytes(1,37)
  end for
  check(read(22)-requests==1000,"small public request count")
  check(read(23)-requested==24000,"aligned one-byte payload blocks")
  check(read(5)==central,"single-thread bump bypasses central counter")
  check(tiny[0]==37,"allocation payload survives instrumentation")
  values=array(1000,0)
  requests=read(22) requested=read(23)
  for i=0 to 999
    values[i]=i+0.1
  end for
  check(read(22)-requests==1000,"escaped double allocation count")
  check(read(23)-requested==24000,"escaped double requested bytes")
  requests=read(22) requested=read(23)
  large=bytes(8193,91)
  check(read(22)-requests==1,"large direct request counted once")
  check(read(23)-requested==8216,"large direct allocation alignment")
  requests=read(22) requested=read(23)
  for i=0 to 99
    metric=read(22) other=read(23) paused=read(24)
  end for
  check(read(22)==requests and read(23)==requested,"diagnostic reads allocate nothing")
  total=read(24)
  gc_collect()
  last=read(26) longest=read(25)
  check(last>0 and read(24)==total+last and longest>=last,"full collection monotonic duration")
  total=read(24)
  gc_collect()
  check(read(24)==total+read(26) and read(25)>=longest and read(25)>=read(26),"cumulative and maximum duration")
  check(values[999]==999.1 and large[8192]==91,"collection preserves live roots")
  print "GC TOTALS checks="+checks+" failures="+failures
  return failures
end function
