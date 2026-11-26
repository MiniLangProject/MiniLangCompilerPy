// Shared by the Python and self-hosted compiler regression suites.
// Keep the reference helpers dynamically typed and materialize each child:
// they deliberately retain the ordinary per-operation Value normalization.

failures = 0
effects = 0
globalNumber = 0.1
synchronized synchronizedNumber = 0.2

struct NumericBox
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
    check(actual.code == expected.code, label + " error code")
    check(actual.message == expected.message, label + " error message")
  else
    check(actual == expected, label + " value")
  end if
  return true
end function

function expectError(actual, code, label)
  if not check(typeof(actual) == "error", label + " type") then return false end if
  return check(actual.code == code, label + " code")
end function

function genericAddParent(a, b, right)
  child = a + b
  return child + right
end function

function genericMulParent(a, b, right)
  child = a * b
  return child * right
end function

function genericSubParent(a, b, right)
  child = a - b
  return child - right
end function

// The branch gives the locals a number fact. At runtime the false branch
// exercises the exact int/int child, including values not exact in a double.
function fusedAddInts(left as int, right as int, useFractions)
  a = left
  b = right
  if useFractions then
    a = 0.5
    b = 0.25
  end if
  return (a + b) + 0.25
end function

function fusedAddFloats(a as float, b as float)
  return (a + b) + 0.25
end function

function fusedMulFloats(a as float, b as float)
  return (a * b) * 0.5
end function

function fusedSubFloats(a as float, b as float)
  return (a - b) - 0.1
end function

function fusedDepthTwo(a as float, b as float, c as float, d as float)
  return ((a * b) + (c * d)) + 0.25
end function

function builtinConverted(value as int)
  converted = toFloat(value)
  return (converted + 0.1) + 0.25
end function

function branchTemporary(value as float, first)
  if first then
    left = value + 0.125
    return (left + 0.25) + 0.5
  else
    right = value * 0.5
    return (right + 0.25) + 0.5
  end if
end function

function loopTemporary(value as float, count as int)
  result = 0.0
  i as int = 0
  while i < count
    temporary = value + 0.125
    result = (temporary + 0.25) + 0.5
    i = i + 1
  end while
  return result
end function

// Declarations check entry, while later ordinary assignments stay dynamic.
function parameterIntToFloat(value as int)
  before = value + 1
  value = 0.5
  after = (value + 1.0) + 0.25
  return [before, after]
end function

function parameterFloatToInt(value as float)
  before = (value + 1.0) + 0.25
  value = 9007199254740993
  after = value + 1
  return [before, after]
end function

function optionalParameter(value as float?)
  return (value + 1.0) + 0.25
end function

function noFuseSibling(first)
  temporary = void
  if first then
    temporary = 0.5
    return 7
  else
    return (temporary + 1.0) + 0.25
  end if
end function

function noFuseZeroLoop(count as int)
  temporary = void
  i as int = 0
  while i < count
    temporary = 0.5
    i = i + 1
  end while
  return (temporary + 1.0) + 0.25
end function

function noFuseLoopBack(count as int)
  value = 0.5
  i as int = 0
  while i < count
    value = void
    i = i + 1
  end while
  return (value + 1.0) + 0.25
end function

function produce(value)
  global effects
  effects = effects + 1
  return value
end function

function noFuseCall(value as float)
  return (produce(value) + 1.0) + 0.25
end function

function noFuseMember(box)
  return (box.value + 1.0) + 0.25
end function

function noFuseIndex(values)
  return (values[0] + 1.0) + 0.25
end function

function noFuseGlobal()
  global globalNumber
  return (globalNumber + 1.0) + 0.25
end function

function noFuseSynchronized()
  global synchronizedNumber
  return (synchronizedNumber + 1.0) + 0.25
end function

function noFuseCapture(value as float)
  function change()
    value = value + 0.1
    return value
  end function
  change()
  return (value + 1.0) + 0.25
end function

function noFuseConstantChild()
  return (0.1 + 0.2) + 0.25
end function

function noFuseIntRight(a as float, b as float)
  return (a + b) + 1
end function

function noFusePlainIntChild(a as int, b as int)
  return (a + b) + 0.25
end function

function fallibleConverted(value)
  converted = toFloat(value)
  return (converted + 0.1) + 0.25
end function

function requireInt(value) returns int
  return value
end function

function capturedConversionError(value)
  return try((toFloat(requireInt(value)) + 0.1) + 0.25)
end function

// A normal-path numeric fact does not exclude Error/void captured by try().
function capturedVoid(value)
  checked as int = 7
  return try(((requireInt(value) / 1) + checked) + 0.25)
end function

function capturedError(value)
  checked as int = 7
  return try((((requireInt(value) / 1) / 1) + checked) + 0.25)
end function

// Return annotations guard explicit returns. Falling off the end still yields
// void, so an alias of this call is not proof that toFloat always succeeds.
function fallthroughInt(enabled) returns int
  if enabled then return 1 end if
end function

function fallthroughConversionTag(enabled)
  first = fallthroughInt(enabled)
  alias = first
  converted = toFloat(alias)
  return typeof(converted)
end function

function fallthroughConversionValue(enabled)
  first = fallthroughInt(enabled)
  alias = first
  return try(toFloat(alias) + 0.25)
end function

function reassignedCall(value as float)
  value = fallthroughInt(false)
  return value + 0.25
end function

function unorderedDivisorTag(value as int)
  // The decimal overflow literals produce infinity. Keep them directly in the
  // expression: a global const is not available to every early inference pass.
  quotient = value / (1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.0 - 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.0)
  converted = toFloat(quotient)
  return typeof(converted)
end function

// New optimization facts must not turn catchable index failures into compile
// diagnostics. Both cases compiled and failed at runtime before this change.
function parameterIndex(items, index as float)
  return items[index]
end function

function nestedIndex(items, enabled)
  if enabled then
    index = 0.0
    return items[index]
  end if
  return 7
end function

namespace NumericConversionScope
  function toFloat(value, replacement = 9007199254740993)
    return replacement
  end function

  function converted(value as int)
    number = toFloat(value)
    return number + 1
  end function

  function qualifiedConverted(value as int)
    number = NumericConversionScope.toFloat(value)
    return number + 1
  end function
end namespace

function main(args)
  global failures, effects
  same(fusedAddInts(9007199254740993, -9007199254740992, false), 1.25, "exact int child above 2^53")
  same(fusedAddInts(1152921504606846975, 1, false), -1152921504606846976, "positive int61 child wrap")
  same(fusedAddInts(-1152921504606846976, -1, false), genericAddParent(-1152921504606846976, -1, 0.25), "negative int61 child wrap")
  same(fusedAddInts(7, 9, true), 1, "number facts allow fractional branch")
  same(fusedAddFloats(0.1, 0.2), genericAddParent(0.1, 0.2, 0.25), "boxed float child")
  same(fusedAddFloats(0.5, 0.5), 1.25, "integral float child normalizes")
  same(fusedMulFloats(0.25, 0.5), 0.0625, "exact immediate floats")
  same(fusedSubFloats(0.3, 0.2), genericSubParent(0.3, 0.2, 0.1), "subtraction rounding")
  same(fusedDepthTwo(0.1, 0.2, 0.3, 0.4), genericAddParent(0.1 * 0.2, 0.3 * 0.4, 0.25), "bounded deeper tree")
  wrapped = toFloat(576460752303423488)
  same(fusedMulFloats(wrapped, 2.0), -576460752303423488, "float child normalizes through int61 wrap")
  expectError(try(fusedAddFloats("wrong", 0.2)), 1308, "float entry contract retained")
  expectError(try(fusedAddInts(1.0, 2, false)), 1308, "int entry contract retained")

  same(builtinConverted(3), genericAddParent(toFloat(3), 0.1, 0.25), "builtin numeric toFloat")
  same(branchTemporary(0.1, true), genericAddParent(0.1 + 0.125, 0.25, 0.5), "nested first branch initialization")
  same(branchTemporary(0.1, false), genericAddParent(0.1 * 0.5, 0.25, 0.5), "nested second branch initialization")
  same(loopTemporary(0.1, 3), genericAddParent(0.1 + 0.125, 0.25, 0.5), "nested loop initialization")
  same(loopTemporary(0.1, 0), 0.0, "zero loop keeps prior initialized value")
  reboundInt = parameterIntToFloat(9007199254740993)
  same(reboundInt[0], 9007199254740994, "int parameter before reassignment")
  same(reboundInt[1], 1.75, "int parameter after float reassignment")
  reboundFloat = parameterFloatToInt(0.1)
  same(reboundFloat[0], genericAddParent(0.1, 1.0, 0.25), "float parameter before reassignment")
  same(reboundFloat[1], 9007199254740994, "float parameter after int reassignment")
  same(optionalParameter(0.5), 1.75, "optional present parameter")
  expectError(try(optionalParameter(void)), 1200, "optional void remains dynamic")
  expectError(try(noFuseSibling(false)), 1200, "sibling branch does not initialize")
  same(noFuseSibling(true), 7, "initialized sibling branch")
  expectError(try(noFuseZeroLoop(0)), 1200, "zero loop does not initialize outside")
  same(noFuseZeroLoop(1), 1.75, "executed loop initializes dynamically")
  expectError(try(noFuseLoopBack(1)), 1200, "loop backedge may change representation")
  same(noFuseLoopBack(0), 1.75, "zero loop retains original float")

  effects = 0
  same(noFuseCall(0.1), genericAddParent(0.1, 1.0, 0.25), "call operand")
  same(effects, 1, "call operand executes once")
  same(noFuseMember(NumericBox(0.1)), genericAddParent(0.1, 1.0, 0.25), "member operand")
  same(noFuseIndex([0.1]), genericAddParent(0.1, 1.0, 0.25), "indexed operand")
  same(noFuseGlobal(), genericAddParent(0.1, 1.0, 0.25), "global operand")
  same(noFuseSynchronized(), genericAddParent(0.2, 1.0, 0.25), "synchronized operand")
  same(noFuseCapture(0.1), genericAddParent(0.1 + 0.1, 1.0, 0.25), "mutated captured operand")
  same(noFuseConstantChild(), genericAddParent(0.1, 0.2, 0.25), "constant child")
  same(noFuseIntRight(0.1, 0.2), genericAddParent(0.1, 0.2, 1), "integer parent operand")
  same(noFusePlainIntChild(9007199254740993, -9007199254740992), 1.25, "already unboxed int child")
  same(fallibleConverted("0.1"), genericAddParent(0.1, 0.1, 0.25), "fallible string conversion")
  expectError(try(fallibleConverted("invalid")), 1200, "failed conversion keeps void")
  expectError(try(capturedConversionError("wrong")), 1303, "caught conversion error remains dynamic")
  same(try(capturedVoid("wrong")), void, "caught void keeps the existing numeric continuation")
  same(try(capturedError("wrong")), void, "caught Error keeps the existing numeric continuation")
  same(capturedVoid(1), 8.25, "captured numeric normal path")
  same(capturedError(1), 8.25, "captured chained numeric normal path")
  same(fallthroughConversionTag(false), "void", "typed call alias may contain implicit void")
  same(fallthroughConversionTag(true), "float", "typed call alias converts its valid result")
  expectError(try(fallthroughConversionValue(false)), 1200, "aliased fallthrough under try")
  same(fallthroughConversionValue(true), 1.25, "aliased typed return normal path")
  expectError(try(reassignedCall(0.1)), 1200, "parameter rebound to implicit void keeps its error")
  same(unorderedDivisorTag(1), "void", "NaN divisor is not a nonzero numeric proof")
  expectError(try(parameterIndex([1], 0.0)), 1301, "typed float index remains catchable")
  expectError(try(nestedIndex([1], true)), 1301, "nested float index remains catchable")
  same(nestedIndex([1], false), 7, "unused invalid index is not evaluated")
  same(NumericConversionScope.converted(1), 2, "unqualified toFloat retains builtin lookup")
  same(NumericConversionScope.qualifiedConverted(1), 9007199254740994, "qualified toFloat is a user function")

  // Construct only valid float32-immediate Values. This avoids target-specific
  // FFI and parser overflow cases; no NaN/Inf is sent to the string formatter.
  for each bits in [0, 2147483648, 2139095040, 4286578688, 2143289344, 1, 8388608]
    special = nativeValueFromRaw((bits << 3) | 5)
    check(typeof(special) == "float", "special value has a float tag")
    same(fusedAddFloats(special, 0.0), genericAddParent(special, 0.0, 0.25), "special float addition")
    same(fusedMulFloats(special, 1.0), genericMulParent(special, 1.0, 0.5), "special float multiplication")
    same(fusedSubFloats(special, 0.0), genericSubParent(special, 0.0, 0.1), "special float subtraction")
  end for
  infinity = nativeValueFromRaw((2139095040 << 3) | 5)
  same(fusedSubFloats(infinity, infinity), genericSubParent(infinity, infinity, 0.1), "NaN intermediate normalization")
  same(fusedMulFloats(infinity, 0.0), genericMulParent(infinity, 0.0, 0.5), "unordered multiplication normalization")
  small = nativeValueFromRaw(13) / 2.0
  same(fusedMulFloats(small, 1.0), genericMulParent(small, 1.0, 0.5), "non-immediate small double")

  // Each call follows the fused path after the patch and must materialize a
  // boxed final double. Keep prior boxes reachable while collections occur.
  expected = genericAddParent(0.1, 0.2, 0.25)
  deepExpected = genericAddParent(0.1 * 0.2, 0.3 * 0.4, 0.25)
  check((nativeRawValue(expected) & 7) == 0, "stress result requires a boxed double")
  retained = array(8)
  deepRetained = array(8)
  collectionsBefore = gc_stat(0)
  gc_set_limit(1)
  i as int = 0
  while i < 96
    value = fusedAddFloats(0.1, 0.2)
    same(value, expected, "fused result across allocation safepoint")
    retained[i % 8] = value
    deep = fusedDepthTwo(0.1, 0.2, 0.3, 0.4)
    same(deep, deepExpected, "rooted subtree survives sibling allocation")
    deepRetained[i % 8] = deep
    same(retained[i % 8], expected, "prior fused result survives next allocation")
    i = i + 1
  end while
  gc_set_limit(0)
  check(gc_stat(0) > collectionsBefore, "fused allocation stress actually collects")
  gc_collect()
  for each value in retained
    same(value, expected, "retained fused result survives collection")
  end for
  for each value in deepRetained
    same(value, deepExpected, "retained deeper result survives collection")
  end for

  if failures != 0 then return 1 end if
  print "NUMERIC TYPEFLOW BOXING [OK]"
  return 0
end function
