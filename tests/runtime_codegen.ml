/// Differential coverage for floor division and allocation-free string identities.
import std.cpu as cpu

failures = 0

/// Keep successful differential checks silent; fail the process on any mismatch.
function checkEq(actual, expected, label)
  global failures
  if actual != expected then
    failures += 1
    print label + " [FAIL]"
  end if
end function

function checkTrue(value, label)
  checkEq(value, true, label)
end function

function dynamicDiv(x, divisor)
  result = x div divisor
  return result
end function

function checkDivision(x as int)
  checkEq(x div 3, dynamicDiv(x, 3), "div three")
  checkEq(x div 10, dynamicDiv(x, 10), "div ten")
  checkEq(x div 31, dynamicDiv(x, 31), "div 31")
  checkEq(x div 2147483647, dynamicDiv(x, 2147483647), "div large prime")
  checkEq(x div 1152921504606846975, dynamicDiv(x, 1152921504606846975), "div maximum")
  checkEq(x div 1, dynamicDiv(x, 1), "div one")
  checkEq(x div 2, dynamicDiv(x, 2), "div two")
  checkEq(x div 8, dynamicDiv(x, 8), "div eight")
  checkEq(x div 1024, dynamicDiv(x, 1024), "div 1024")
  checkEq(x div 1073741824, dynamicDiv(x, 1073741824), "div 2^30")
  checkEq(x div 576460752303423488, dynamicDiv(x, 576460752303423488), "div 2^59")
  checkEq(x div 1152921504606846976, dynamicDiv(x, 1152921504606846976), "wrapped negative divisor")
  checkEq(x div 2305843009213693952, void, "wrapped zero divisor")
  checkEq(x div -8, dynamicDiv(x, -8), "negative divisor")
  checkEq(x div 7, dynamicDiv(x, 7), "non-power divisor")
  checkEq(x div 0, void, "zero divisor")
end function

visits = 0
function observed(value)
  global visits
  visits += 1
  return value
end function

function concatVoid(value)
  return "" + value
end function

/// Allocate in a worker and publish an identity result beyond its stack lifetime.
function worker(value)
  source = stringRepeat(value, 1000)
  return stringJoin([stringRepeat(source + "", 1)], ",")
end function

function main(args)
  global visits
  checkAdvancedCodegen()
  for sample = -2048 to 2048
    checkDivision(sample)
  end for
  // Tagged wraparound deliberately produces both signs and large magnitudes.
  seed = 20260930
  for sample = 0 to 1023
    seed = seed * 1103515245 + 12345
    checkDivision(seed)
    checkEq(toNumber(str(seed)), seed, "decimal roundtrip")
  end for
  checkEq(str(-1152921504606846976), "-1152921504606846976", "decimal minimum")
  checkEq(str(1152921504606846975), "1152921504606846975", "decimal maximum")
  checkEq(str(0), "0", "decimal zero")
  checkEq(localRepeated(11, 7), 324, "pure local CSE")
  visits = 0
  checkEq(observed(2) + observed(2), 4, "calls must not merge")
  checkEq(visits, 2, "both calls executed")
  values = [-1152921504606846976, -1152921504606846975, -1025, -1024, -1023, -9, -8, -7, -1, 0, 1, 7, 8, 9, 1023, 1024, 1025, 1152921504606846975]
  for each value in values
    checkDivision(value)
  end for
  for i = -4097 to 4097
    checkDivision(i)
  end for
  // Scalar-array classification must agree even when encoded values need 64 bits.
  // Storing a pointer later must promote it back to a GC-scanned array.
  values[0] = stringRepeat("promoted", 100)
  gc_collect()
  checkEq(values[0], stringRepeat("promoted", 100), "large-int array promotion")
  checkEq(dynamicDiv(8.5, 2), void, "float dividend is not int")
  checkEq(dynamicDiv(8, 2.5), void, "float divisor is not int")
  checkEq(dynamicDiv(void, 2), void, "void dividend")
  checkEq(dynamicDiv(-9, 8), -2, "floor rather than truncation")

  // Include tails not equal to a power of two and embedded NUL/UTF-8 bytes.
  sources = ["", "a", "\0", "abc", "ab\0cd", "Grüße", stringRepeat("z", 257)]
  counts = [0, 1, 2, 3, 7, 16, 17, 63, 255]
  for each source in sources
    for each count in counts
      expected = ""
      if count > 0 then
        for i = 0 to count - 1
          expected = expected + source
        end for
      end if
      actual = stringRepeat(source, count)
      checkEq(actual, expected, "repeat doubling content")
      checkEq(len(actual), len(source) * count, "repeat length")
    end for
  end for
  checkEq(stringRepeat("x", -1), "", "negative repeat")
  checkEq(stringRepeat("x", 2147483648), void, "count overflow")
  checkEq(stringRepeat("xx", 2147483647), void, "length overflow")
  checkEq(stringRepeat("x", true), void, "invalid count")
  checkEq(stringRepeat(1, 1), void, "invalid source")
  checkEq(stringRepeat("", true), "", "existing empty-source validation order")
  previousMask = cpu.activeFeatures()
  cpu.setDispatchMaskForTesting(0)
  scalarFill = stringRepeat("x", 4097)
  checkEq(stringRepeat("abc", 257), stringRepeat(stringRepeat("abc", 1), 257), "scalar copy fallback")
  fallback = stringRepeat("abc", 257)
  cpu.setDispatchMaskForTesting(previousMask)
  checkEq(scalarFill, stringRepeat("x", 4097), "scalar and SIMD fill agree")
  checkEq(fallback, stringRepeat("abc", 257), "scalar and SIMD repeat agree")
  gc_set_limit(1)
  retained = stringRepeat(stringRepeat("gc", 257), 17)
  gc_collect()
  checkEq(len(retained), 8738, "repeat survives allocation safepoint")
  gc_set_limit(0)
  checkEq(stringJoin(["x"], true), void, "singleton separator validated")
  checkEq(stringJoin([1], ","), void, "singleton element validated")
  checkEq(stringJoin(["a", "b", "c"], ","), "a,b,c", "general join")
  checkEq(stringJoin([], ","), "", "empty join")
  checkEq(stringJoin([""], ","), "", "empty singleton")
  checkEq("" + 42, "42", "conversion still runs")
  checkEq(true + "", "true", "left conversion still runs")
  problem = try(concatVoid(void))
  checkEq(typeof(problem), "error", "void conversion still fails")
  visits = 0
  checkEq(observed("") + observed("ok"), "ok", "left empty")
  checkEq(observed("ok") + observed(""), "ok", "right empty")
  checkEq(visits, 4, "both operands evaluated")

  source = stringRepeat("abcd", 1024)
  singleton = [source]
  a = void
  b = void
  c = void
  d = void
  gc_collect()
  before = heap_bytes_used()
  for i = 0 to 99
    a = stringRepeat(source, 1)
    b = stringJoin(singleton, ",")
    c = source + ""
    d = "" + source
  end for
  allocated = heap_bytes_used() - before
  checkEq(allocated, 0, "identity operations allocate no heap bytes")
  source = void
  singleton = void
  gc_collect()
  checkEq(len(a), 4096, "repeat identity survives GC")
  checkEq(a, b, "join identity survives GC")
  checkEq(c, d, "concat identity survives GC")

  thread = Thread(worker)
  checkTrue(thread.Start("xyz"), "worker starts")
  checkTrue(thread.Join(30000), "worker joins")
  published = thread.Result()
  checkTrue(thread.Close(), "worker closes")
  gc_collect()
  checkEq(published, stringRepeat("xyz", 1000), "identity survives worker exit")
  if failures != 0 then return 1 end if
  print "RUNTIME CODEGEN [OK]"
  return 0
end function

/// Repeated primitive trees may be reused, but remain tagged wraparound ints.
function localRepeated(x as int, y as int) returns int
  return (x + y) * (x + y)
end function

/// Constructor projections may disappear only when discarded arguments are pure.
struct CodegenPair
  first as int
  second as int
end struct

function projectedPair(x as int, y as int) returns int
  return CodegenPair(x + 1, y * 3).second
end function

function effectfulPair()
  return CodegenPair(observed(7), observed(9)).second
end function

function invalidPair(value)
  return CodegenPair(1, value).first
end function

function dynamicSum(values as array) returns int
  total = 0
  for i = 0 to len(values) - 1
    total += values[i]
    values[i] = values[i] + 1
  end for
  return total
end function

function emptyLoop(values as array)
  global visits
  for i = 0 to len(values) - 1
    visits += 1
    value = values[i]
  end for
end function

function reboundLoop(values as array)
  total = 0
  for i = 0 to len(values) - 1
    values = [10, 20]
    total += values[i]
  end for
  return total
end function

function collectedLoop(values as array)
  total = 0
  for i = 0 to len(values) - 1
    gc_collect()
    total += values[i]
  end for
  return total
end function

function changedIndex(values as array)
  total = 0
  for i = 0 to len(values) - 1
    i += 1
    total += values[i]
  end for
  return total
end function

function dynamicBytes(values as bytes)
  total = 0
  for i = 0 to len(values) - 1
    total += values[i]
    values[i] = 255
  end for
  return total
end function

function inline specializedInteger(x)
  return (x + 3) * (x - 2)
end function

function literalEntry()
  result = specializedInteger(11)
  return result
end function

function inline reassignedInteger(x)
  x = "changed"
  return x + x
end function

/// Preserve captures, argument effects, allocation roots and error provenance.
function checkAdvancedCodegen()
  global visits
  checkEq(projectedPair(4, 7), 21, "temporary struct projection")
  visits = 0
  checkEq(effectfulPair(), 9, "effectful struct projection")
  checkEq(visits, 2, "discarded fields still execute effects")
  bad = try(invalidPair("wrong"))
  checkEq(typeof(bad), "error", "discarded field contract remains checked")
  checkEq(specializedInteger(11), 126, "literal inline specialization")
  checkEq(literalEntry(), 126, "specialized native entry")
  checkEq(specializedInteger("a"), void, "noninteger inline fallback")
  checkEq(reassignedInteger(11), "changedchanged", "inline type changes")
  data = [1, 2, 3, 4]
  checkEq(dynamicSum(data), 10, "dynamic-length loop")
  checkEq(data[3], 5, "dynamic-length stores")
  checkEq(dynamicSum([9]), 9, "singleton loop")
  checkEq(reboundLoop([1, 2]), 30, "mutated container is not hoisted")
  checkEq(collectedLoop([3, 5, 7]), 15, "hoisted root survives GC")
  checkEq(changedIndex([1, 2, 3, 4]), 6, "mutated index retains checks")
  byteData = bytes([1, 2, 3])
  checkEq(dynamicBytes(byteData), 6, "dynamic bytes read and store")
  checkEq(byteData[2], 255, "dynamic byte store result")
  guardError = try(dynamicSum("wrong"))
  checkEq(typeof(guardError), "error", "container contract is still checked")
  visits = 0
  problem = try(emptyLoop([]))
  checkEq(typeof(problem), "error", "empty descending loop retains error")
  checkEq(visits, 1, "empty loop preserves effects before failing")
  checkEq(problem.code, 1300, "cold error code")
  checkEq(problem.func, "emptyLoop", "cold error function")
  checkTrue(problem.line > 0, "cold error line")
  checkTrue(len(problem.script) > 0, "cold error script")
  captured = 3
  function changeCaptured()
    return 1
  end function
  checkEq(changeCaptured() + captured, 4, "RHS local loaded after call")
  visits = 3
  checkEq(observed(1) + visits, 5, "RHS global loaded after call")
  gc_collect()
  checkEq(problem.code, 1300, "error survives collection")
  beforeProjection = heap_bytes_used()
  result = 0
  for i = 0 to 99
    result += projectedPair(i, i)
  end for
  projectionBytes = heap_bytes_used() - beforeProjection
  checkEq(result, 14850, "projection checksum")
  checkEq(projectionBytes, 0, "projected structs allocate no heap")
end function
