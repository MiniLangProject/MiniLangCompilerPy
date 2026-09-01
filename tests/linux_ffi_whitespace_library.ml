#if TARGET_OS != "linux"
#error "linux_ffi_whitespace_library.ml requires the linux-x64 target"
#endif

// Boundary whitespace is part of Linux's exact dlopen identity. The compiler
// must build this consistently and surface the expected loader failure.
extern function spacedLabs(value as int) from " libc.so.6 " symbol "labs" returns int

function main(args)
  result = try(spacedLabs(-5))
  if typeof(result) != "error" then return 1 end if
  print "[OK] exact Linux library spelling"
  return 0
end function
