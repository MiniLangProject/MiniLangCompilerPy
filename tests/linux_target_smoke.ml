#if TARGET_OS != "linux" or TARGET_ARCH != "x64" or TARGET_ABI != "sysv" or TARGET_FORMAT != "elf"
#error "unexpected Linux target values"
#endif

function main(args)
  print "linux-target"
  print "linux " + len(args)
  src = [10, "linux", true]
  dst = array(4, 0)
  copyArray(dst, 1, src, 0, len(src))
  if dst != [0, 10, "linux", true] then return 1 end if
  print "copyArray linux [OK]"
  return 0
end function
