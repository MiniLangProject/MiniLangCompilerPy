#if TARGET_OS != "linux"
#error "linux_float_format.ml requires the linux-x64 target"
#endif

function main(args)
  if "" + 1.9999999 != "2" then return 1 end if
  if "" + 9.9999999 != "10" then return 2 end if
  if "" + (-9.9999999) != "-10" then return 3 end if
  print "[OK] Linux float rounding carry"
  return 0
end function
