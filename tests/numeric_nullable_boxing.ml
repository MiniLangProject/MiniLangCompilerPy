// A numeric-or-void candidate is never a type guarantee. Only the guarded
// expression path may use it; every guard miss retains ordinary evaluation.
// Untyped reference helpers materialize their child and keep its normalization.

failures = 0
effects = 0
globalRight = 0.25
synchronized sharedRight = 0.25

struct NullableBox
  value
end struct

function check(condition, label)
  global failures
  if not condition then
    failures = failures + 1
    print "[FAIL] " + label
    return false
  end if
  return true
end function

function same(actual, expected, label)
  if typeof(actual) == "float" and actual != actual then
    return check(typeof(expected) == "float" and expected != expected, label + " NaN")
  end if
  check(typeof(actual) == typeof(expected), label + " tag")
  if typeof(actual) == "error" and typeof(expected) == "error" then
    check(actual.code == expected.code, label + " code")
    check(actual.message == expected.message, label + " message")
  else
    check(actual == expected, label + " value")
  end if
  return true
end function

function expectError(actual, code, label)
  if not check(typeof(actual) == "error", label + " type") then return false end if
  return check(actual.code == code, label + " code")
end function

function referenceAdd(a, b, right)
  child = a + b
  return child + right
end function

function referenceMul(a, b, right)
  child = a * b
  return child * right
end function

function referenceSub(a, b, right)
  child = a - b
  return child - right
end function

function referenceCaught(a, b, right)
  return try((a + b) + right)
end function

function referenceDivision(divisor, right)
  quotient = 3.0 / divisor
  child = quotient + 0.125
  return child + right
end function

function variableFloatRight(a as float, b as float, right as float)
  return (a + b) + right
end function

function variableFloatMulRight(a as float, b as float, right as float)
  return (a * b) * right
end function

function variableFloatSubRight(a as float, b as float, right as float)
  return (a - b) - right
end function

// All three locals have a number fact, but the false branch runs only ints.
// An integer RHS must select the complete old expression, before child work.
function variableNumberRight(a as int, b as int, right as int, fractions)
  if fractions then
    a = 0.5
    b = 0.25
    right = 0.25
  end if
  return (a + b) + right
end function

function nullableAdd(n as int, right as float)
  quotient = 3.0 / toFloat(n)
  return (quotient + 0.125) + right
end function

function nullableMultiply(n as int, right as float)
  quotient = 3.0 / toFloat(n)
  return (quotient * 0.125) * right
end function

function nullableSubtract(n as int, right as float)
  quotient = 3.0 / toFloat(n)
  return (quotient - 0.125) - right
end function

function nullableFloatDivisor(divisor as float, right as float)
  quotient = 3.0 / divisor
  return (quotient + 0.125) + right
end function

function nullableRight(a as float, b as float, n as int)
  right = 3.0 / toFloat(n)
  return (a + b) + right
end function

function caughtNullableRight(a as float, b as float, n as int)
  right = 3.0 / toFloat(n)
  return try((a + b) + right)
end function

function caughtNullableAdd(n as int, right as float)
  quotient = 3.0 / toFloat(n)
  return try((quotient + 0.125) + right)
end function

function caughtNullableChild(n as int)
  quotient = 3.0 / toFloat(n)
  return try(quotient + 0.125)
end function

function nullableAliasJoin(n as int, right as float, replace)
  quotient = 0.5
  if replace then quotient = 3.0 / toFloat(n) end if
  alias = quotient
  return (alias + 0.125) + right
end function

function nullableLoopJoin(n as int, count as int, right as float)
  quotient = 0.5
  i as int = 0
  while i < count
    quotient = 3.0 / toFloat(n)
    i = i + 1
  end while
  return (quotient + 0.125) + right
end function

function nullableChain(n as int, right as float)
  quotient = 3.0 / toFloat(n)
  product = quotient * 0.5
  difference = product - 0.25
  shifted = difference + 0.125
  return (shifted + 0.1) + right
end function

function nullableConversionTag(n as int)
  quotient = 3.0 / toFloat(n)
  return typeof(toFloat(quotient))
end function

function unusedScale(n as int)
  scale = 3.0 / toFloat(n)
  total as int = 0
  i as int = 0
  while i < n
    total = total + 1
    i = i + 1
  end while
  return total
end function

function readBeforeNumericInit(a as float, b as float)
  right = void
  result = (a + b) + right
  right = 0.25
  return result
end function

function zeroTripRight(a as float, b as float, count as int)
  right = void
  i as int = 0
  while i < count
    right = 0.25
    i = i + 1
  end while
  return (a + b) + right
end function

function recordedRight(value)
  global effects
  effects = effects * 10 + 2
  return value
end function

function recordedChild(value)
  global effects
  effects = effects * 10 + 1
  return value
end function

function noFuseRightCall(a as float, b as float)
  return (a + b) + recordedRight(0.25)
end function

function noFuseBothCalls()
  return (recordedChild(0.1) + 0.2) + recordedRight(0.25)
end function

function noFuseErrorOrder(n as int)
  quotient = 3.0 / toFloat(n)
  return (quotient + 0.125) + recordedRight(0.25)
end function

function noFuseRightMember(a as float, b as float, box)
  return (a + b) + box.value
end function

function noFuseRightIndex(a as float, b as float, values)
  return (a + b) + values[0]
end function

function noFuseRightGlobal(a as float, b as float)
  global globalRight
  return (a + b) + globalRight
end function

function noFuseRightSynchronized(a as float, b as float)
  global sharedRight
  return (a + b) + sharedRight
end function

function noFuseRightCapture(a as float, b as float, right as float)
  function change()
    right = right + 0.125
    return right
  end function
  change()
  return (a + b) + right
end function

function noFuseMixedRight(a as float, b as float, text)
  right = 0.25
  if text then right = "tail" end if
  return (a + b) + right
end function

function optionalRight(a as float, b as float, right as float?)
  return (a + b) + right
end function

function declaredFloat(enabled) returns float
  if enabled then return 0.25 end if
end function

function noFuseOpaqueRight(a as float, b as float, enabled)
  right = declaredFloat(enabled)
  return (a + b) + right
end function

function requireInt(value) returns int
  return value
end function

function noFuseErrorRight(a as float, b as float)
  right = try(requireInt("wrong"))
  return try((a + b) + right)
end function

// Small copy of the original recurrence. The earlier division is still
// evaluated for n=0; the unused loop must not turn that void into an error.
function smallMandelbrot(n as int)
  scale = 3.0 / toFloat(n)
  checksum as int = 0
  py as int = 0
  while py < n
    cy = -1.5 + toFloat(py) * scale
    px as int = 0
    while px < n
      cx = -2.0 + toFloat(px) * scale
      zr = 0.0
      zi = 0.0
      zr2 = 0.0
      zi2 = 0.0
      iteration as int = 0
      while iteration < 80 and zr2 + zi2 <= 4.0
        zi = 2.0 * zr * zi + cy
        zr = zr2 - zi2 + cx
        zr2 = zr * zr
        zi2 = zi * zi
        iteration = iteration + 1
      end while
      checksum = checksum + iteration
      px = px + 1
    end while
    py = py + 1
  end while
  return checksum
end function

// Indexed state prevents numeric local facts in this reference recurrence.
function referenceMandelbrot(n)
  scale = 3.0 / toFloat(n)
  checksum = 0
  py = 0
  while py < n
    cy = -1.5 + toFloat(py) * scale
    px = 0
    while px < n
      cx = -2.0 + toFloat(px) * scale
      state = [0.0, 0.0, 0.0, 0.0]
      iteration = 0
      while iteration < 80 and state[2] + state[3] <= 4.0
        state[1] = 2.0 * state[0] * state[1] + cy
        state[0] = state[2] - state[3] + cx
        state[2] = state[0] * state[0]
        state[3] = state[1] * state[1]
        iteration = iteration + 1
      end while
      checksum = checksum + iteration
      px = px + 1
    end while
    py = py + 1
  end while
  return checksum
end function

function nullableGc(n as int, right as float)
  value = 1.0 / toFloat(n)
  return ((value * 0.1) + (value * 0.1)) + right
end function

function main(args)
  global failures, effects
  same(variableFloatRight(0.1, 0.2, 0.25), referenceAdd(0.1, 0.2, 0.25), "boxed RHS and child")
  same(variableFloatMulRight(0.25, 0.5, 0.5), 0.0625, "immediate float RHS")
  same(variableFloatSubRight(0.3, 0.2, 0.1), referenceSub(0.3, 0.2, 0.1), "subtraction RHS")
  same(variableNumberRight(9007199254740993, 0, 1, false), 9007199254740994, "int RHS keeps exact child above 2^53")
  same(variableNumberRight(9007199254740993, -9007199254740992, 9007199254740993, false), 9007199254740994, "large cancellation and int RHS")
  same(variableNumberRight(1152921504606846975, 1, 1, false), -1152921504606846975, "int RHS after int61 wrap")
  same(variableNumberRight(1, 2, 3, true), 1, "number RHS takes actual float path")
  same(variableFloatMulRight(toFloat(576460752303423488), 2.0, 0.5), -576460752303423488, "float child retains int61 intermediate wrap")
  expectError(try(variableFloatRight(1, 0.2, 0.25)), 1308, "entry guard remains")

  for each n in [-3, -2, -1, 1, 2, 3, 7]
    quotient = 3.0 / toFloat(n)
    same(nullableAdd(n, 0.25), referenceAdd(quotient, 0.125, 0.25), "nullable addition valid branch")
    same(nullableMultiply(n, 0.25), referenceMul(quotient, 0.125, 0.25), "nullable multiplication valid branch")
    same(nullableSubtract(n, 0.25), referenceSub(quotient, 0.125, 0.25), "nullable subtraction valid branch")
  end for
  expectError(try(nullableAdd(0, 0.25)), 1200, "nullable child fallback retains strict plus error")
  same(nullableMultiply(0, 0.25), void, "nullable multiplication remains void")
  same(nullableSubtract(0, 0.25), void, "nullable subtraction remains void")
  same(nullableConversionTag(0), "void", "nullable candidate cannot prove toFloat succeeds")
  same(nullableConversionTag(2), "float", "valid nullable conversion")
  same(unusedScale(0), 0, "unused zero divisor retains zero-trip behavior")
  same(unusedScale(-1), 0, "unused negative-size loop")
  same(nullableRight(0.1, 0.2, 2), referenceAdd(0.1, 0.2, 1.5), "nullable RHS actual float")
  same(nullableRight(0.1, 0.2, 1), referenceAdd(0.1, 0.2, 3), "nullable RHS actual int fallback")
  expectError(try(nullableRight(0.1, 0.2, 0)), 1200, "nullable RHS void fallback")
  same(caughtNullableRight(0.1, 0.2, 2), referenceCaught(0.1, 0.2, 1.5), "try with actual float RHS")
  same(caughtNullableRight(0.1, 0.2, 1), referenceCaught(0.1, 0.2, 3), "try with actual int RHS")
  expectError(try(caughtNullableRight(0.1, 0.2, 0)), 1200, "try with void RHS")
  same(try(caughtNullableAdd(0, 0.25)), try(referenceCaught(void, 0.125, 0.25)), "try retains intermediate Error continuation")
  same(caughtNullableAdd(2, 0.25), referenceCaught(1.5, 0.125, 0.25), "try valid nullable child")
  expectError(try(caughtNullableChild(0)), 1200, "try preserves child Error code")
  same(nullableAliasJoin(0, 0.25, false), 0.875, "unselected nullable assignment")
  same(nullableAliasJoin(2, 0.25, true), 1.875, "nullable mixed write and alias")
  expectError(try(nullableAliasJoin(0, 0.25, true)), 1200, "nullable join never becomes nonnullable")
  same(nullableLoopJoin(0, 0, 0.25), 0.875, "zero loop retains initialized number")
  same(nullableLoopJoin(2, 2, 0.25), 1.875, "nullable loop backedge valid value")
  expectError(try(nullableLoopJoin(0, 1, 0.25)), 1200, "nullable loop backedge void value")
  same(nullableChain(2, 0.25), referenceAdd(1.5 * 0.5 - 0.25 + 0.125, 0.1, 0.25), "nullable arithmetic chain")
  expectError(try(nullableChain(0, 0.25)), 1200, "nullable chain retains first strict plus error")
  expectError(try(readBeforeNumericInit(0.1, 0.2)), 1200, "read before numeric initialization")
  expectError(try(zeroTripRight(0.1, 0.2, 0)), 1200, "zero-trip loop cannot initialize RHS")
  same(zeroTripRight(0.1, 0.2, 1), referenceAdd(0.1, 0.2, 0.25), "executed loop initializes RHS dynamically")

  effects = 0
  same(noFuseRightCall(0.1, 0.2), referenceAdd(0.1, 0.2, 0.25), "effectful RHS")
  same(effects, 2, "effectful RHS executes once")
  effects = 0
  same(noFuseBothCalls(), referenceAdd(0.1, 0.2, 0.25), "effectful operands")
  same(effects, 12, "left-to-right call order")
  effects = 0
  expectError(try(noFuseErrorOrder(0)), 1200, "left error precedes RHS effect")
  same(effects, 0, "RHS not evaluated after propagated child error")
  same(noFuseRightMember(0.1, 0.2, NullableBox(0.25)), referenceAdd(0.1, 0.2, 0.25), "member RHS")
  same(noFuseRightIndex(0.1, 0.2, [0.25]), referenceAdd(0.1, 0.2, 0.25), "indexed RHS")
  same(noFuseRightGlobal(0.1, 0.2), referenceAdd(0.1, 0.2, 0.25), "global RHS")
  same(noFuseRightSynchronized(0.1, 0.2), referenceAdd(0.1, 0.2, 0.25), "synchronized RHS")
  same(noFuseRightCapture(0.1, 0.2, 0.25), referenceAdd(0.1, 0.2, 0.375), "captured RHS survives mutation")
  same(noFuseMixedRight(0.1, 0.2, true), referenceAdd(0.1, 0.2, "tail"), "string join remains dynamic")
  same(optionalRight(0.1, 0.2, 0.25), referenceAdd(0.1, 0.2, 0.25), "optional RHS present")
  expectError(try(optionalRight(0.1, 0.2, void)), 1200, "optional RHS void")
  same(noFuseOpaqueRight(0.1, 0.2, true), referenceAdd(0.1, 0.2, 0.25), "typed call normal return")
  expectError(try(noFuseOpaqueRight(0.1, 0.2, false)), 1200, "typed call implicit void return")
  errorRight = try(requireInt("wrong"))
  same(try(noFuseErrorRight(0.1, 0.2)), try(referenceCaught(0.1, 0.2, errorRight)), "Error-valued RHS remains dynamic")

  // Only valid immediate float bit patterns; special values never stringify.
  for each bits in [0, 2147483648, 2139095040, 4286578688, 2143289344, 1, 8388608]
    special = nativeValueFromRaw((bits << 3) | 5)
    same(variableFloatRight(0.1, 0.2, special), referenceAdd(0.1, 0.2, special), "special float RHS")
    same(variableFloatMulRight(special, 1.0, 0.5), referenceMul(special, 1.0, 0.5), "special float child")
    same(try(nullableFloatDivisor(special, 0.25)), try(referenceDivision(special, 0.25)), "zero unordered infinite or tiny divisor")
  end for
  infinity = nativeValueFromRaw((2139095040 << 3) | 5)
  same(variableFloatSubRight(infinity, infinity, 0.25), referenceSub(infinity, infinity, 0.25), "NaN child normalization")
  tiny = nativeValueFromRaw(13) / 2.0
  same(variableFloatRight(0.0, 0.0, tiny), referenceAdd(0.0, 0.0, tiny), "boxed subnormal RHS")
  same(try(nullableFloatDivisor(tiny, 0.25)), try(referenceDivision(tiny, 0.25)), "overflowing quotient remains normalized")
  for each n in [-1, 0, 1, 2, 3, 7]
    same(smallMandelbrot(n), referenceMandelbrot(n), "small original Mandelbrot recurrence")
  end for

  // Deeper child boxes can collect before the boxed RHS is loaded again.
  // The final materialized Value must remain rooted at the next allocation.
  expected = referenceAdd(0.1 * 0.1, 0.1 * 0.1, 0.2)
  check((nativeRawValue(expected) & 7) == 0, "GC result requires a boxed double")
  retained = array(8)
  collectionsBefore = gc_stat(0)
  gc_set_limit(1)
  i as int = 0
  while i < 64
    result = nullableGc(10, 0.2)
    same(result, expected, "nullable child and RHS survive GC safepoints")
    retained[i % 8] = result
    i = i + 1
  end while
  gc_set_limit(0)
  check(gc_stat(0) > collectionsBefore, "nullable GC path actually collects")
  gc_collect()
  for each value in retained
    same(value, expected, "retained nullable result survives collection")
  end for

  if failures != 0 then return 1 end if
  print "NUMERIC NULLABLE BOXING [OK]"
  return 0
end function
