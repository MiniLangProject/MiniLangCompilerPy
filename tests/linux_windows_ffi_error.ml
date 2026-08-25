#if TARGET_OS != "linux"
#error "linux_windows_ffi_error.ml requires the linux-x64 target"
#endif

extern function GetTickCount64() from "kernel32.dll" returns u64

function main(args)
  return GetTickCount64()
end function
