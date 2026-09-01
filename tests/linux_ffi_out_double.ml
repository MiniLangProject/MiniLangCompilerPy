#if TARGET_OS != "linux"
#error "linux_ffi_out_double.ml requires the linux-x64 target"
#endif

// modf stores the integral component through a double pointer and returns the
// fractional component. MiniLang's omitted out syntax returns the stored value.
extern function modfOut(value as double, out integral as double) from "libm.so.6" symbol "modf" returns double

function main(args)
  integral = modfOut(42.5)
  if integral != 42.0 then return 1 end if
  print "[OK] Linux FFI double out pointer"
  return 0
end function
