#option FAIL: bool = false

#if FAIL
#error "requested compile failure"
#endif

function main(args)
  print "conditional error inactive [OK]"
  return 0
end function
