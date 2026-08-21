/* Regression: fn_box_float must preserve XMM0 across an allocating GC safepoint. */

import std.math

function gcBoxFloatAssert(condition, message)
  if not condition then return error(1740, message) end if
  return true
end function

function main(args)
  // pi() cannot be represented exactly by MiniLang's immediate float32 tag,
  // so every call reaches fn_box_float.  Force its fn_alloc call to collect.
  gc_set_limit(1)

  // Start away from exact zero: MiniLang intentionally canonicalizes floating
  // zero to the immediate integer zero representation.
  iteration = 1
  while iteration < 2000
    p = std.math.pi()
    gcBoxFloatAssert(typeof(p) == "float", "pi remains a float")
    gcBoxFloatAssert(p > 3.14 and p < 3.15, "pi payload survives fn_alloc")

    wrapped = std.math._wrapPi(12.75 + iteration * 0.001)
    gcBoxFloatAssert(typeof(wrapped) == "float", "wrapped value remains a float")
    gcBoxFloatAssert(wrapped >= 0.0 - p and wrapped <= p, "wrapped value range")

    wave = std.math.sin(iteration * 0.01)
    gcBoxFloatAssert(typeof(wave) == "float", "sine remains a float")
    gcBoxFloatAssert(wave >= -1.01 and wave <= 1.01, "sine range")
    iteration = iteration + 1
  end while

  print "[OK] gc_box_float_safepoint: PASS"
  return 0
end function
