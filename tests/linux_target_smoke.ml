#if TARGET_OS != "linux" or TARGET_ARCH != "x64" or TARGET_ABI != "sysv" or TARGET_FORMAT != "elf"
#error "linux target predefined values are inconsistent"
#endif

import std.time as time
import std.threading as threading

function main(args)
  print "linux-target"
  print "linux " + len(args)
  src = [10, "linux", true]
  dst = array(4, 0)
  copyArray(dst, 1, src, 0, len(src))
  if dst != [0, 10, "linux", true] then return 1 end if
  print "copyArray linux [OK]"
  stamp = bytes(16, 0)
  time.linux._putI64(stamp, 0, -1)
  if time.linux._i64le(stamp, 0) != -1 then return 1 end if
  threading._putTimespecField(stamp, 8, 0x123456789ABCDEF)
  if hex(stamp) != "ffffffffffffffffefcdab8967452301" then return 1 end if
  print "time fields linux [OK]"
  return 0
end function
