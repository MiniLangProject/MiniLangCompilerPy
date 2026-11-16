// The same regression source is kept in both compiler repositories.
// Checks may disappear only when the result is independently proven.
// Error codes/messages, operand order, effects and value tags remain observable.

failures = 0
trace = 0
entered = 0

function expectEq(actual, expected, label)
  global failures
  if actual != expected then
    failures = failures + 1
    print "[FAIL] " + label
    print actual
    print expected
    return false
  end if
  return true
end function

function expectError(actual, code, message, label)
  if typeof(actual) != "error" then
    expectEq(typeof(actual), "error", label + " type")
    return false
  end if
  expectEq(actual.code, code, label + " code")
  expectEq(actual.message, message, label + " message")
  return true
end function

function markTarget(value)
  global trace
  trace = trace * 10 + 1
  return value
end function

function markIndex(value)
  global trace
  trace = trace * 10 + 2
  return value
end function

function markValue(value)
  global trace
  trace = trace * 10 + 3
  return value
end function

// Unknown receiver/index: exercise the generic store with a literal RHS.
function storeZero(target, index)
  target[index] = 0
  return 0
end function

function storeOne(target, index)
  target[index] = 1
  return 0
end function

function store255(target, index)
  target[index] = 255
  return 0
end function

function store256(target, index)
  target[index] = 256
  return 0
end function

function storeFloat(target, index)
  target[index] = 1.0
  return 0
end function

function storeBool(target, index)
  target[index] = true
  return 0
end function

function dynamicStore(target, index, value)
  markTarget(target)[markIndex(index)] = markValue(value)
  return 0
end function

function effectfulLiteralStore(target, index)
  markTarget(target)[markIndex(index)] = 255
  return 0
end function

// Proven bytes and fixed/bounded indices exercise the specialized stores.
function localLiteralStores()
  result = bytes(3, 99)
  result[0] = 0
  result[1] = 1
  result[-1] = 255
  return result
end function

function loopLiteralStores()
  result = bytes(3)
  for i = 0 to 2
    result[i] = 0
    result[i] = 1
    result[i] = 255
  end for
  return result
end function

function localRejectedByte(which)
  result = bytes(1, 77)
  if which == 0 then result[0] = -1 end if
  if which == 1 then result[0] = 256 end if
  if which == 2 then result[0] = 1.0 end if
  if which == 3 then result[0] = 255.0 end if
  if which == 4 then result[0] = true end if
  if which == 5 then result[0] = "1" end if
  return result[0]
end function

// bytes(source) can return void. Its checked-bytes target guard must remain.
function checkedBytesStore(source, index as int)
  result = bytes(source)
  result[index] = 255
  return result
end function

function incrementByte(target, index)
  target[index] = target[index] + 1
  return target[index]
end function

// Literal-only proofs are useful, but declarations alone prove nothing.
function literalContracts()
  zero as int = 0
  answer as integer = 20 + 22
  yes as boolean = 3 < 4
  text as str = "literal"
  fraction as float = 0.5
  normalized as int = 0.5 + 0.5
  return [zero, answer, yes, text, fraction, normalized]
end function

function literalFloatIsNotInt()
  checked as int = 1.0
  return checked
end function

function normalizedLiteralIsNotFloat()
  checked as float = 0.5 + 0.5
  return checked
end function

function localContract(value)
  global entered
  checked as int = markValue(value)
  entered = entered + 1
  return checked
end function

function localReassignment(value)
  global entered
  checked as int = 1
  checked = markValue(value)
  entered = entered + 1
  return checked
end function

function optionalContract(value)
  checked as int? = value
  return checked
end function

function parameterContracts(first as int, second as string)
  global entered
  entered = entered + 1
  return first
end function

function parameterReassignment(value as int, replacement)
  value = replacement
  return value
end function

function returnContract(value) returns int
  return markValue(value)
end function

function normalizedFloatContract(value as float)
  checked as float = value + 0.0
  return checked
end function

function typedFailure() returns int
  global trace
  trace = trace * 10 + 4
  return error(1774, "typed call failure")
end function

function localFromTypedFailure()
  global entered
  checked as int = typedFailure()
  entered = entered + 1
  return checked
end function

// Guards currently resolve this namespaced spelling to the builtin typeof.
// Preserve that existing lookup behavior as well as the result value.
namespace GuardQuery
  calls = 0
  function typeof(value, label = "string")
    global calls
    calls = calls + 1
    return label
  end function
  function literalContract()
    checked as int = 1
    return checked
  end function
end namespace

// Division by a nonzero constant gives an internal number fact. The result
// can still be an exact tagged int. Never round int/int addition through f64.
function inferredNumberInts(left as int, right as int)
  checkedLeft as int = left
  checkedRight as int = right
  a = checkedLeft / 1
  b = checkedRight / 1
  return a + b
end function

function inferredNumberFloats(left as float, right as float)
  checkedLeft as float = left
  checkedRight as float = right
  a = checkedLeft + 0.0
  b = checkedRight + 0.0
  return a + b
end function

function inferredNumberMixed(left as int, right as float)
  checkedLeft as int = left
  checkedRight as float = right
  a = checkedLeft / 1
  b = checkedRight + 0.0
  return a + b
end function

function numberInput(value) returns int
  return value
end function

// try() captures the failed return contract inside this whole expression.
// Dividing that Error by 1 yields void, despite the inferred number fact.
function inferredVoidFallback(value)
  checked as int = 7
  return try((numberInput(value) / 1) + checked)
end function

// A second division instead leaves a captured Error at the addition. Both
// operand orders must reach the existing generic concatenation error path.
function inferredErrorFallback(value, reverse)
  checked as int = 7
  if reverse then
    return try(checked + ((numberInput(value) / 1) / 1))
  end if
  return try(((numberInput(value) / 1) / 1) + checked)
end function

function effectfulNumericSum(left as int, right as int)
  a = markTarget(left) / 1
  b = markIndex(right) / 1
  return a + b
end function

function main(args)
  global failures, trace, entered

  b = bytes(3, 77)
  expectEq(storeZero(b, 0), 0, "generic literal zero store")
  expectEq(storeOne(b, 1), 0, "generic literal one store")
  expectEq(store255(b, -1), 0, "generic literal 255 and negative index")
  expectEq(b[0], 0, "zero byte")
  expectEq(b[1], 1, "one byte")
  expectEq(b[2], 255, "maximum byte")
  expectEq(store255(b, -3), 0, "negative first index")
  expectEq(b[0], 255, "negative first index normalized")

  local = localLiteralStores()
  expectEq(local[0], 0, "known bytes zero")
  expectEq(local[1], 1, "known bytes one")
  expectEq(local[2], 255, "known bytes 255")
  looped = loopLiteralStores()
  expectEq(looped[0] + looped[1] + looped[2], 765, "bounded loop byte stores")

  byteMessage = "Byte value must be an int in range 0..255"
  for which = 0 to 5
    expectError(try(localRejectedByte(which)), 1200, byteMessage, "known invalid byte")
  end for

  unchanged = bytes(2, 77)
  expectError(try(dynamicStore(unchanged, 0, -1)), 1200, byteMessage, "negative byte")
  expectError(try(store256(unchanged, 0)), 1200, byteMessage, "literal 256")
  expectError(try(storeFloat(unchanged, 0)), 1200, byteMessage, "whole float is not byte int")
  expectError(try(storeBool(unchanged, 0)), 1200, byteMessage, "bool is not byte int")
  expectError(try(dynamicStore(unchanged, 0, "1")), 1200, byteMessage, "string is not byte int")
  expectEq(unchanged[0], 77, "failed byte values preserve slot")
  expectEq(unchanged[1], 77, "failed byte values preserve neighbor")

  expectError(try(storeZero(b, 3)), 1300, "Array index out of bounds", "positive bound")
  expectError(try(storeOne(b, -4)), 1300, "Array index out of bounds", "negative bound")
  expectError(try(store255(bytes(0), 0)), 1300, "Array index out of bounds", "empty bytes")
  expectError(try(storeOne(b, "0")), 1301, "Index must be an int", "string index")
  expectError(try(storeOne(b, 0.0)), 1301, "Index must be an int", "float index")
  expectError(try(storeOne(b, true)), 1301, "Index must be an int", "bool index")
  expectError(try(store255(7, 0)), 1302, "Index assignment requires array or bytes", "int target")
  expectError(try(store255("abc", 0)), 1302, "Index assignment requires array or bytes", "string target")
  expectError(try(checkedBytesStore(-1, 0)), 1302, "Index assignment requires array or bytes", "checked constructor target")
  expectError(try(checkedBytesStore("ab", 2)), 1300, "Array index out of bounds", "checked bytes bound")
  checked = checkedBytesStore("ab", -1)
  expectEq(checked[1], 255, "checked bytes negative index")

  overflow = bytes(1, 255)
  expectError(try(incrementByte(overflow, 0)), 1200, byteMessage, "computed byte overflow")
  expectEq(overflow[0], 255, "computed overflow preserves byte")

  // The same generic functions must still allow wider and non-int array data.
  values = [0]
  expectEq(store256(values, 0), 0, "array 256 store")
  expectEq(values[0], 256, "array is not restricted to byte range")
  expectEq(storeFloat(values, 0), 0, "array float store")
  expectEq(typeof(values[0]), "float", "array float tag retained")

  trace = 0
  expectEq(effectfulLiteralStore(unchanged, -1), 0, "literal store effects")
  expectEq(trace, 12, "literal target and index evaluated once in order")
  expectEq(unchanged[1], 255, "literal effectful store result")

  trace = 0
  expectError(try(dynamicStore(7, "bad", 256)), 1302, "Index assignment requires array or bytes", "target error before index/value")
  expectEq(trace, 123, "all store operands evaluated before target check")
  trace = 0
  expectError(try(dynamicStore(unchanged, "bad", 256)), 1301, "Index must be an int", "index error before bounds/value")
  expectEq(trace, 123, "all store operands evaluated before index check")
  trace = 0
  expectError(try(dynamicStore(unchanged, 2, 256)), 1300, "Array index out of bounds", "bounds error before value")
  expectEq(trace, 123, "all store operands evaluated before bounds check")
  trace = 0
  expectError(try(dynamicStore(unchanged, 0, 256)), 1200, byteMessage, "value error after valid address")
  expectEq(trace, 123, "RHS evaluated exactly once")
  expectEq(unchanged[0], 77, "ordered failures preserve target")
  expectEq(unchanged[1], 255, "ordered failures preserve neighbor")

  // Errors during operand evaluation propagate before later operands/checks.
  targetError = try(error(1771, "target evaluation"))
  indexError = try(error(1772, "index evaluation"))
  valueError = try(error(1773, "value evaluation"))
  trace = 0
  expectError(try(dynamicStore(targetError, 0, 1)), 1771, "target evaluation", "target evaluation error")
  expectEq(trace, 1, "target error skips index and RHS")
  trace = 0
  expectError(try(dynamicStore(unchanged, indexError, 1)), 1772, "index evaluation", "index evaluation error")
  expectEq(trace, 12, "index error skips RHS")
  trace = 0
  expectError(try(dynamicStore(7, "bad", valueError)), 1773, "value evaluation", "RHS error before deferred target check")
  expectEq(trace, 123, "RHS error keeps evaluation order")

  literals = literalContracts()
  expectEq(literals[0], 0, "literal int contract")
  expectEq(literals[1], 42, "folded int and alias contract")
  expectEq(literals[2], true, "folded bool and alias contract")
  expectEq(literals[3], "literal", "literal string alias contract")
  expectEq(typeof(literals[4]), "float", "literal float contract")
  expectEq(literals[4], 0.5, "literal float value")
  expectEq(typeof(literals[5]), "int", "folded exact sum normalizes to int")
  expectEq(literals[5], 1, "folded exact sum value")
  expectError(try(literalFloatIsNotInt()), 1308, "Expected value of type int", "float literal cannot prove int")
  expectError(try(normalizedLiteralIsNotFloat()), 1308, "Expected value of type float", "normalized literal cannot prove float")

  trace = 0
  entered = 0
  expectError(try(localContract("wrong")), 1308, "Expected value of type int", "local declaration is not its own proof")
  expectEq(trace, 3, "local initializer evaluated once")
  expectEq(entered, 0, "failed local contract stops body")
  trace = 0
  // An annotation checks its declaration; ordinary later writes remain dynamic.
  expectEq(localReassignment("wrong"), "wrong", "local reassignment remains dynamic")
  expectEq(trace, 3, "reassignment RHS evaluated once")
  expectEq(entered, 1, "dynamic reassignment continues body")
  trace = 0
  expectEq(localContract(9), 9, "valid local contract")
  expectEq(trace, 3, "valid local initializer evaluated once")
  expectEq(entered, 2, "valid local continuation")
  expectEq(typeof(optionalContract(void)), "void", "optional void accepted")
  expectEq(optionalContract(7), 7, "optional int accepted")
  expectError(try(optionalContract("wrong")), 1308, "Expected value of type int?", "optional contract still checked")

  trace = 0
  entered = 0
  expectError(try(parameterContracts(markTarget("wrong"), markIndex(7))), 1308, "Expected value of type int", "first parameter contract precedes second")
  expectEq(trace, 12, "all call arguments evaluated before parameter guards")
  expectEq(entered, 0, "invalid parameter does not enter body")
  expectError(try(parameterContracts(7, 8)), 1308, "Expected value of type string", "second parameter still checked")
  expectEq(entered, 0, "second failed parameter stops body")
  expectEq(parameterContracts(7, "ok"), 7, "valid parameter contracts")
  expectEq(parameterReassignment(1, "wrong"), "wrong", "parameter reassignment remains dynamic")
  expectError(try(parameterReassignment("wrong", 1)), 1308, "Expected value of type int", "parameter annotation cannot prove entry")
  trace = 0
  expectError(try(returnContract("wrong")), 1308, "Expected value of type int", "dynamic return contract")
  expectEq(trace, 3, "return operand evaluated once")
  expectError(try(normalizedFloatContract(1.0)), 1308, "Expected value of type float", "number fact does not prove float")
  expectEq(normalizedFloatContract(1.5), 1.5, "fractional result satisfies float")

  trace = 0
  entered = 0
  // An explicit Error return violates returns int; its contract error propagates.
  expectError(try(localFromTypedFailure()), 1308, "Expected value of type int", "typed call propagates its return-contract error")
  expectEq(trace, 4, "fallible typed call evaluated once")
  expectEq(entered, 0, "propagated call error stops continuation")
  expectEq(GuardQuery.literalContract(), 1, "guard keeps existing builtin lookup")
  expectEq(GuardQuery.calls, 0, "namespace typeof is not called by the guard")

  exact = inferredNumberInts(9007199254740992, 1)
  expectEq(typeof(exact), "int", "number int/int result tag")
  expectEq(exact, 9007199254740993, "number int/int preserves bit above 2^53")
  expectEq(inferredNumberInts(1152921504606846848, 127), 1152921504606846975, "number int/int reaches maximum signed61 exactly")
  expectEq(inferredNumberInts(1152921504606846848, 128), -1152921504606846976, "number int/int preserves positive signed61 wrap")
  expectEq(inferredNumberInts(-1152921504606846976, -1), 1152921504606846975, "number int/int preserves negative signed61 wrap")
  expectEq(inferredNumberInts(-576460752303423488, -1), -576460752303423489, "negative large int addition stays exact")
  expectEq(inferredNumberInts(-1152921504606846976, 1), -1152921504606846975, "minimum signed61 plus one stays exact")
  expectEq(inferredNumberFloats(0.25, 0.5), 0.75, "fractional number plus number")
  expectEq(typeof(inferredNumberFloats(0.25, 0.5)), "float", "fractional result tag")
  boxed = inferredNumberFloats(0.1, 0.2)
  expectEq(boxed, 0.30000000000000004, "boxed double addition result")
  expectEq(typeof(boxed), "float", "boxed double result retains float tag")
  expectEq(inferredNumberFloats(0.25, 0.75), 1, "float sum exact integer value")
  expectEq(typeof(inferredNumberFloats(0.25, 0.75)), "int", "float sum exact integer normalization")
  expectEq(inferredNumberFloats(1.0, 0.25), 1.25, "normalized int plus float")
  expectEq(inferredNumberFloats(0.25, 1.0), 1.25, "float plus normalized int")
  expectEq(inferredNumberFloats(1.25, -1.25), 0, "cancellation result")
  expectEq(typeof(inferredNumberFloats(1.25, -1.25)), "int", "cancellation normalizes to int")
  expectEq(inferredNumberMixed(7, 0.5), 7.5, "int and fractional number")
  expectEq(inferredNumberMixed(7, 1.0), 8, "int and normalized whole float")
  expectError(try(inferredVoidFallback("wrong")), 1200, "Cannot apply '+' to void", "number fallback retains strict void error")
  expectError(try(inferredErrorFallback("wrong", false)), 1303, "Cannot stringify unsupported value for string concatenation", "number fallback retains captured left Error")
  expectError(try(inferredErrorFallback("wrong", true)), 1303, "Cannot stringify unsupported value for string concatenation", "number fallback retains captured right Error")
  trace = 0
  expectEq(effectfulNumericSum(20, 22), 42, "effectful numeric inputs")
  expectEq(trace, 12, "numeric operands evaluated once in order")

  // Exercise the proven-number plus/boxed-double safepoint under real GC.
  collectionsBefore = gc_stat(0)
  gc_set_limit(1)
  for gcRound = 0 to 63
    boxed = inferredNumberFloats(0.1, 0.2)
    expectEq(boxed, 0.30000000000000004, "boxed addition survives GC")
    expectEq(typeof(boxed), "float", "boxed addition tag survives GC")
  end for
  gc_set_limit(0)
  expectEq(gc_stat(0) > collectionsBefore, true, "boxed number loop actually collected")

  if failures != 0 then return 1 end if
  print "PROVEN CHECK ELISION [OK]"
  return 0
end function
