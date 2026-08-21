/* Regression coverage for boxed float values across nested calls and GC. */

import std.math as gcFloatMath

struct GcFloatHolder
  angle
  sine
  cosine
end struct

function gcFloatAssert(condition, message)
  if not condition then return error(1712, message) end if
  return true
end function

function gcFloatSample(degrees)
  radians = gcFloatMath.degToRad(degrees)
  sine = gcFloatMath.sin(radians)
  cosine = gcFloatMath.cos(radians)
  if typeof(radians) != "float" then return error(1713, "radians local type " + typeof(radians)) end if
  if typeof(sine) != "float" then return error(1714, "sine local type " + typeof(sine)) end if
  if typeof(cosine) != "float" then return error(1715, "cosine local type " + typeof(cosine)) end if
  return GcFloatHolder(radians, sine, cosine)
end function

function gcFloatReturnedHolder()
  return GcFloatHolder(gcFloatMath.pi(), gcFloatMath.pi(), gcFloatMath.pi())
end function

function gcFloatReturnedLocals()
  first = gcFloatMath.pi()
  second = gcFloatMath.pi()
  third = gcFloatMath.pi()
  return GcFloatHolder(first, second, third)
end function

function main(args)
  single = GcFloatHolder(gcFloatMath.pi(), gcFloatMath.pi(), gcFloatMath.pi())
  gcFloatAssert(typeof(single.angle) == "float", "single angle starts as a float")
  gc_collect()
  gcFloatAssert(typeof(single) == "struct", "single holder survives collection")
  gcFloatAssert(typeof(single.angle) == "float", "single angle survives collection")

  returned = gcFloatReturnedHolder()
  gcFloatAssert(typeof(returned.angle) == "float", "returned angle starts as a float")
  gc_collect()
  gcFloatAssert(typeof(returned.angle) == "float", "returned angle survives collection")

  returnedLocals = gcFloatReturnedLocals()
  gcFloatAssert(typeof(returnedLocals.angle) == "float", "returned local angle starts as a float")
  gc_collect()
  gcFloatAssert(typeof(returnedLocals.angle) == "float", "returned local angle survives collection")

  retained = array(32)
  iteration = 0
  while iteration < 12000
    degrees = (iteration % 720) - 359.75
    sample = gcFloatSample(degrees)

    gcFloatAssert(typeof(sample) == "struct", "sample remains a struct")
    gcFloatAssert(typeof(sample.angle) == "float", "angle remains a float")
    gcFloatAssert(typeof(sample.sine) == "float", "sine remains a float")
    gcFloatAssert(typeof(sample.cosine) == "float", "cosine remains a float")
    gcFloatAssert(sample.sine >= -1.01 and sample.sine <= 1.01, "sine remains bounded")
    gcFloatAssert(sample.cosine >= -1.01 and sample.cosine <= 1.01, "cosine remains bounded")

    slot = iteration % len(retained)
    retained[slot] = sample
    gc_collect()
    if typeof(sample) != "struct" then return error(1721, "local sample survives collection") end if
    if typeof(sample.angle) != "float" then return error(1719, "local angle survives collection") end if
    if typeof(retained[slot].angle) != "float" then return error(1720, "retained angle survives collection") end if
    iteration = iteration + 1
  end while

  print("[OK] gc_float_call_roots: PASS")
  return 0
end function
