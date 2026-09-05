#if TARGET_OS != "linux" or TARGET_ABI != "sysv"
#error "linux_ffi.ml requires the linux-x64 target"
#endif

// Verify both ELF symbol relocation and SysV's first integer register (RDI).
extern function strlen(value as cstr) from "libc.so.6" returns u64
extern function cos(value as double) from "libm.so.6" returns double

// C-string results must survive clobbered volatile registers during copying.
extern function strchr(value as cstr, ch as int) from "libc.so.6" returns cstr

function main(args)
  if strlen("MiniLang") != 8 then
    print "[FAIL] linux ffi strlen"
    return 1
  end if
  if cos(0.0) != 1.0 then
    print "[FAIL] linux ffi cos"
    return 2
  end if
  if strchr("prefix:Grüße 🚀", 58) != ":Grüße 🚀" then return 3 end if
  if strchr("text", 0) != "" then return 4 end if
  if strchr("text", 90) is void == false then return 5 end if
  print "[OK] linux ffi cstr return"
  print "[OK] linux ffi strlen"
  print "[OK] linux ffi cos"
  return 0
end function
