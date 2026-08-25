#if TARGET_OS != "linux" or TARGET_ABI != "sysv"
#error "linux_ffi.ml requires the linux-x64 target"
#endif

// Verify both ELF symbol relocation and SysV's first integer register (RDI).
extern function strlen(value as cstr) from "libc.so.6" returns u64
extern function cos(value as double) from "libm.so.6" returns double

function main(args)
  if strlen("MiniLang") != 8 then
    print "[FAIL] linux ffi strlen"
    return 1
  end if
  if cos(0.0) != 1.0 then
    print "[FAIL] linux ffi cos"
    return 2
  end if
  print "[OK] linux ffi strlen"
  print "[OK] linux ffi cos"
  return 0
end function
