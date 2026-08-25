#option FEATURE: bool = false
#option LIMIT: int = 3
#option LABEL: string = "default"
#const DOUBLE_LIMIT = LIMIT * 2

#if -5 % 3 != 1 or "alpha" >= "beta"
#error "compile-time operator semantics failed"
#endif

#if TARGET_OS != "windows" or TARGET_ARCH != "x64" or POINTER_SIZE != 8
#error "unexpected MiniLang target"
#endif

#if false
import tests.this_module_must_not_be_resolved
#endif

function selectedLabel()
#if defined(FEATURE)
#if FEATURE and LABEL == "enabled"
  return "enabled"
#elif not FEATURE and LABEL == "default"
  return "default"
#else
  return "custom"
#endif
#else
  return "missing"
#endif
end function

function main(args)
#if DOUBLE_LIMIT != 6
#error "compile-time arithmetic failed"
#endif
  total = 0
  for index = 1 to 3
    total = total + index
  end for
  if total != 6 then return 2 end if
  label = selectedLabel()
#if FEATURE
  if label != "enabled" then return 3 end if
#else
  if label != "default" then return 4 end if
#endif
  print "conditional " + label + " " + total + " [OK]"
  return 0
end function
