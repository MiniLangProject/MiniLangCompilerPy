//! Regression: escaping variadic tails must remain heap-owned after MLO body release.

saved = void

/// This early-sorted function escapes its tail before later callers are emitted.
function aEscape(values...)
  global saved
  saved = values
  return len(values)
end function

/// Keep the non-escaping optimization covered alongside the escaping case.
function aSafe(values...)
  total = 0
  for each value in values
    total = total + value
  end for
  return total
end function

/// Consume another call frame before collecting and reading the saved array.
function overwriteFrame(a, b, c, d, e, f, g, h)
  scratch = array(64, "replacement")
  return a + b + c + d + e + f + g + h + len(scratch)
end function

/// Validate that a variadic array still exists after its creating call returns.
function main(args)
  // Eight live padding functions put aEscape in an earlier object batch.
  if bPad0() + bPad1() + bPad2() + bPad3() + bPad4() + bPad5() + bPad6() + bPad7() != 8 then return 6 end if
  if zMake() != 4 then return 1 end if
  if overwriteFrame(1, 2, 3, 4, 5, 6, 7, 8) != 100 then return 2 end if
  gc_collect()
  if saved[0] != "persistent" or saved[1][1] != 8 or saved[2] != 42 or saved[3] != "last" then return 3 end if
  if aSafe(1, 2, 3, 4) != 10 then return 4 end if
  if saved[0] != "persistent" then return 5 end if
  print "[OK] variadic escape lifetime"
  return 0
end function

/// Return from the caller that would incorrectly own the escaped stack view.
function zMake()
  return aEscape("persistent", [7, 8], 42, "last")
end function

/// Keep an early object-batch slot live.
function bPad0() value = 1; return value end function
/// Keep an early object-batch slot live.
function bPad1() value = 1; return value end function
/// Keep an early object-batch slot live.
function bPad2() value = 1; return value end function
/// Keep an early object-batch slot live.
function bPad3() value = 1; return value end function
/// Keep an early object-batch slot live.
function bPad4() value = 1; return value end function
/// Keep an early object-batch slot live.
function bPad5() value = 1; return value end function
/// Keep an early object-batch slot live.
function bPad6() value = 1; return value end function
/// Keep an early object-batch slot live.
function bPad7() value = 1; return value end function
