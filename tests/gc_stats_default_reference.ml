// A default-only first-class reference must keep allocation diagnostics alive.
function selectReader(read=gc_stat)
  return read
end function
function main(args)
  gc_set_limit(0)
  read=selectReader()
  before=read(22) beforeBytes=read(23)
  payload=bytes(17,91)
  if read(22)-before!=1 or read(23)-beforeBytes!=40 then return 1 end if
  gc_collect()
  if payload[16]!=91 or read(26)<=0 then return 2 end if
  print "GC DEFAULT REFERENCE [OK]"
  return 0
end function
