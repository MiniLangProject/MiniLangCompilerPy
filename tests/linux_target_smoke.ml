#if TARGET_OS != "linux" or TARGET_ARCH != "x64" or TARGET_ABI != "sysv" or TARGET_FORMAT != "elf"
#error "unexpected Linux target values"
#endif

function main(args)
  print "linux-target"
  print "linux " + len(args)
  return 0
end function
