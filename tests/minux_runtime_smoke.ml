#if TARGET_OS != "minux" or TARGET_ARCH != "x64" or TARGET_ABI != "sysv" or TARGET_FORMAT != "elf"
#error "MinUX target predefined values are inconsistent"
#endif

function main(args)
  print "minux-runtime"
  print "argc=" + len(args)
  for i = 0 to len(args) - 1
    print "arg=" + args[i]
  end for
  roots = ["retained", [1, 2, 3], bytes("MinUX")]
  for round = 0 to 23
    for i = 0 to 511
      transient = bytes(4096, i % 251)
    end for
    gc_collect()
  end for
  if roots[0] != "retained" or roots[1] != [1, 2, 3] or roots[2] != bytes("MinUX") then return 2 end if
  print "gc=ok"
  print "float=" + 1.25
  print "minux-runtime=ok"
  return 37
end function
