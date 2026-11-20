// Counted float loops may delay materialization only across complete, pure
// iterations. References call untyped arithmetic helpers so they retain the
// ordinary statement path, including every integer/NaN normalization boundary.
failures = 0
effects = 0
globalLoopValue = 0.125
synchronized synchronizedLoopValue = 0.125

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
  if not check(typeof(actual) == typeof(expected), label + " tag") then return false end if
  if typeof(actual) == "void" then return true end if
  if typeof(actual) == "error" then
    check(actual.code == expected.code, label + " code")
    check(actual.message == expected.message, label + " message")
  else
    check(actual == expected, label + " value")
  end if
  return true
end function

function sameState(actual, expected, label)
  if not check(len(actual) == len(expected), label + " length") then return false end if
  for index = 0 to len(expected) - 1
    same(actual[index], expected[index], label + " slot " + index)
  end for
  return true
end function

function expectError(actual, code, label)
  if not check(typeof(actual) == "error", label + " type") then return false end if
  return check(actual.code == code, label + " code")
end function

function referenceAdd(left, right)
  return left + right
end function

function referenceSub(left, right)
  return left - right
end function

function referenceMul(left, right)
  return left * right
end function

function loopRecurrence(n as int, x as float, y as float, accumulated as float)
  i as int = 0
  while i < n
    nextX = x * 0.9999991 + y * 0.0000003 + 0.0000007
    nextY = y * 0.9999989 + x * 0.0000002 + 0.0000005
    x = nextX
    y = nextY
    accumulated = accumulated + x * 0.333333333333333 + y * 0.142857142857143
    i = i + 1
  end while
  return [x, y, accumulated, i]
end function

function referenceRecurrence(n, x, y, accumulated)
  i = 0
  while i < n
    nextX = referenceAdd(referenceAdd(referenceMul(x, 0.9999991), referenceMul(y, 0.0000003)), 0.0000007)
    nextY = referenceAdd(referenceAdd(referenceMul(y, 0.9999989), referenceMul(x, 0.0000002)), 0.0000005)
    x = nextX
    y = nextY
    accumulated = referenceAdd(referenceAdd(accumulated, referenceMul(x, 0.333333333333333)), referenceMul(y, 0.142857142857143))
    i = i + 1
  end while
  return [x, y, accumulated, i]
end function

// Both outer targets denote the same new Value after a successful iteration.
// Independently boxing x and copy would preserve numbers but break this alias.
function loopAlias(n as int, seed as float)
  x = seed
  copy = seed
  old = seed
  i as int = 0
  while i < n
    next = x * 0.9999991 + 0.0000007
    x = next
    copy = x
    i = i + 1
  end while
  return [x, copy, old, i, nativeRawValue(x) == nativeRawValue(copy), nativeRawValue(old) == nativeRawValue(seed)]
end function

function referenceAlias(n, seed)
  x = seed
  copy = seed
  old = seed
  i = 0
  while i < n
    next = referenceAdd(referenceMul(x, 0.9999991), 0.0000007)
    x = next
    copy = x
    i = i + 1
  end while
  return [x, copy, old, i, nativeRawValue(x) == nativeRawValue(copy), nativeRawValue(old) == nativeRawValue(seed)]
end function

// output is written before it is read in the loop. Its old void/String value
// is not an entry float requirement, and zero trips must preserve it exactly.
function loopWriteOnly(n as int, initial as float, oldOutput)
  x = initial
  output = oldOutput
  i as int = 0
  while i < n
    next = x * 0.9999991 + 0.0000007
    x = next
    output = next
    i = i + 1
  end while
  return [x, output, i, nativeRawValue(x) == nativeRawValue(initial)]
end function

function referenceWriteOnly(n, initial, oldOutput)
  x = initial
  output = oldOutput
  i = 0
  while i < n
    next = referenceAdd(referenceMul(x, 0.9999991), 0.0000007)
    x = next
    output = next
    i = i + 1
  end while
  return [x, output, i, nativeRawValue(x) == nativeRawValue(initial)]
end function

// z reaches integer 1 on the third iteration from 0.25. x and y already have
// tentative next values when that happens; replay must not update them twice.
function loopLate(n as int, x as float, y as float, z as float)
  i as int = 0
  while i < n
    x = x + 0.125
    y = y + 0.0625
    z = z + 0.25
    i = i + 1
  end while
  return [x, y, z, i]
end function

function referenceLate(n, x, y, z)
  i = 0
  while i < n
    x = referenceAdd(x, 0.125)
    y = referenceAdd(y, 0.0625)
    z = referenceAdd(z, 0.25)
    i = i + 1
  end while
  return [x, y, z, i]
end function

// Parameters can become number candidates without proving their runtime tag.
// Integer entry must keep exact >2^53 arithmetic and signed61 wrapping.
function loopNumericEntry(n as int, first as int, second as int, useFloats)
  x = first
  y = second
  if useFloats then
    x = toFloat(first)
    y = toFloat(second)
  end if
  i as int = 0
  while i < n
    x = x + y
    y = y + 0.25
    i = i + 1
  end while
  return [x, y, i]
end function

function referenceNumericEntry(n, first, second, useFloats)
  x = first
  y = second
  if useFloats then
    x = toFloat(first)
    y = toFloat(second)
  end if
  i = 0
  while i < n
    x = referenceAdd(x, y)
    y = referenceAdd(y, 0.25)
    i = i + 1
  end while
  return [x, y, i]
end function

function loopCounter(start as int, limit as int, x as float)
  i as int = start
  while i < limit
    x = x * 0.5 + 0.125
    i as int = i + 1
  end while
  return [x, i]
end function

function loopSpecial(n as int, x as float, other as float)
  i as int = 0
  while i < n
    x = (x - other + 1.0) * 0.5
    i = i + 1
  end while
  return [x, i]
end function

function referenceSpecial(n, x, other)
  i = 0
  while i < n
    x = referenceMul(referenceAdd(referenceSub(x, other), 1.0), 0.5)
    i = i + 1
  end while
  return [x, i]
end function

function calledStep(value)
  global effects
  effects = effects + 1
  return value + 0.125
end function

function calledFailure(value)
  global effects
  effects = effects + 1
  return error(1775, "float loop call failure")
end function

function noLoopCall(n as int, x as float)
  i as int = 0
  while i < n
    x = calledStep(x)
    i = i + 1
  end while
  return [x, i]
end function

function noLoopError(n as int, x as float)
  i as int = 0
  while i < n
    x = x + 0.125
    x = calledFailure(x)
    i = i + 1
  end while
  return [x, i]
end function

function noLoopGlobal(n as int)
  global globalLoopValue
  i as int = 0
  while i < n
    globalLoopValue = globalLoopValue + 0.125
    i = i + 1
  end while
  return globalLoopValue
end function

function noLoopSynchronized(n as int)
  global synchronizedLoopValue
  i as int = 0
  while i < n
    synchronizedLoopValue = synchronizedLoopValue + 0.125
    i = i + 1
  end while
  return synchronizedLoopValue
end function

function noLoopCapture(n as int, x as float)
  function read()
    return x
  end function
  i as int = 0
  while i < n
    x = x + 0.125
    i = i + 1
  end while
  return read()
end function

function noLoopContract(n as int, x as float)
  i as int = 0
  while i < n
    checked as float = x + 0.25
    x = checked
    i = i + 1
  end while
  return x
end function

function noLoopControl(n as int, x as float)
  i as int = 0
  while i < n
    i = i + 1
    if i == 2 then continue end if
    x = x + 0.125
    if i == 4 then break end if
  end while
  return [x, i]
end function

function noLoopReturn(n as int, x as float)
  i as int = 0
  while i < n
    x = x + 0.125
    if i == 1 then return [x, i] end if
    i = i + 1
  end while
  return [x, i]
end function

function noLoopChangingBound(n as int, x as float)
  i as int = 0
  while i < n
    x = x + 0.125
    n = n - 1
    i = i + 1
  end while
  return [x, i, n]
end function

function noLoopStep(n as int, x as float)
  i as int = 0
  while i < n
    x = x + 0.125
    i = i + 2
  end while
  return [x, i]
end function

// copy deliberately preserves the previous iteration's existing Value. This
// is not an alias of a fresh definition and must retain ordinary lowering.
function noLoopOldAlias(n as int, seed as float)
  x = seed
  copy = seed
  i as int = 0
  while i < n
    copy = x
    x = x * 0.9999991 + 0.0000007
    i = i + 1
  end while
  return [x, copy, i, nativeRawValue(copy) == nativeRawValue(seed)]
end function

function referenceOldAlias(n, seed)
  x = seed
  copy = seed
  i = 0
  while i < n
    copy = x
    x = referenceAdd(referenceMul(x, 0.9999991), 0.0000007)
    i = i + 1
  end while
  return [x, copy, i, nativeRawValue(copy) == nativeRawValue(seed)]
end function

// Leave a body-local builtin name and the following typed counter update on
// ordinary lowering. The existing compiler accepts this local numeric value;
// the conservative loop boundary must preserve those observed values/tags.
function noLoopBodyTypeof(n as int, x as float)
  i as int = 0
  while i < n
    typeof = x * 0.5 + 0.125
    x = typeof
    i as int = i + 1
  end while
  return [x, i]
end function

// Thirteen statements exercise the extended bounded raw loop, including
// chained definitions, aliases, zero trips and transaction replay.
function loopLong(n as int, x as float, y as float, accumulated as float)
  i as int = 0
  copy = accumulated
  while i < n
    a = x * 0.9999991 + y * 0.0000003 + 0.0000007
    b = y * 0.9999989 + x * 0.0000002 + 0.0000005
    c = a * 0.9 + b * 0.1
    d = b * 0.8 + c * 0.2
    e = c * 0.7 + d * 0.3
    f = d * 0.6 + e * 0.4
    g = e * 0.5 + f * 0.5
    h = f * 0.4 + g * 0.6
    x = a
    y = b
    accumulated = h
    copy = accumulated
    i = i + 1
  end while
  return [x, y, accumulated, copy, i, nativeRawValue(copy) == nativeRawValue(accumulated)]
end function

function referenceLong(n, x, y, accumulated)
  i = 0
  copy = accumulated
  while i < n
    a = referenceAdd(referenceAdd(referenceMul(x, 0.9999991), referenceMul(y, 0.0000003)), 0.0000007)
    b = referenceAdd(referenceAdd(referenceMul(y, 0.9999989), referenceMul(x, 0.0000002)), 0.0000005)
    c = referenceAdd(referenceMul(a, 0.9), referenceMul(b, 0.1))
    d = referenceAdd(referenceMul(b, 0.8), referenceMul(c, 0.2))
    e = referenceAdd(referenceMul(c, 0.7), referenceMul(d, 0.3))
    f = referenceAdd(referenceMul(d, 0.6), referenceMul(e, 0.4))
    g = referenceAdd(referenceMul(e, 0.5), referenceMul(f, 0.5))
    h = referenceAdd(referenceMul(f, 0.4), referenceMul(g, 0.6))
    x = a
    y = b
    accumulated = h
    copy = accumulated
    i = i + 1
  end while
  return [x, y, accumulated, copy, i, nativeRawValue(copy) == nativeRawValue(accumulated)]
end function
function main(args)
  global failures, effects
  for each n in [0, 1, 2, 7]
    sameState(loopLong(n, 0.173, 0.291, 0.037), referenceLong(n, 0.173, 0.291, 0.037), "thirteen-statement float loop " + n)
  end for
  sameState(loopLong(2, 0.0, 0.0, 0.0), referenceLong(2, 0.0, 0.0, 0.0), "thirteen-statement normalization fallback")
  for each n in [0, 1, 2, 7]
    sameState(loopRecurrence(n, 0.123456789012345, 0.987654321098765, 0.0), referenceRecurrence(n, 0.123456789012345, 0.987654321098765, 0.0), "recurrence " + n)
    sameState(loopAlias(n, 0.123456789012345), referenceAlias(n, 0.123456789012345), "outer aliases " + n)
  end for
  for each n in [-1, 0, 1, 3]
    sameState(loopWriteOnly(n, 0.123456789012345, void), referenceWriteOnly(n, 0.123456789012345, void), "write-only void " + n)
    sameState(loopWriteOnly(n, 0.123456789012345, "untouched"), referenceWriteOnly(n, 0.123456789012345, "untouched"), "write-only string " + n)
  end for
  sameState(loopNumericEntry(0, 2, 0, true), [2.0, 0.0, 0], "zero trips preserve integral float tags")
  for each n in [1, 2, 3, 4]
    sameState(loopLate(n, 0.125, 0.0625, 0.25), referenceLate(n, 0.125, 0.0625, 0.25), "late third-write bailout " + n)
  end for
  sameState(loopLate(3, 0.125, 0.0625, 0.25), [0.5, 0.25, 1, 3], "third-write bailout commits once")
  sameState(loopLate(1, 0.125, 0.0625, 0.75), [0.25, 0.125, 1, 1], "first-iteration bailout commits once")
  sameState(loopLate(3, 0.75, 0.0625, 0.125), referenceLate(3, 0.75, 0.0625, 0.125), "late first-write bailout")
  sameState(loopNumericEntry(1, 9007199254740993, 1, false), [9007199254740994, 1.25, 1], "integer entry above 2^53")
  sameState(loopNumericEntry(1, 1152921504606846975, 1, false), [-1152921504606846976, 1.25, 1], "positive signed61 wrap")
  sameState(loopNumericEntry(1, -1152921504606846976, -1, false), [1152921504606846975, -0.75, 1], "negative signed61 wrap")
  sameState(loopNumericEntry(2, 1152921504606846975, 1, true), referenceNumericEntry(2, 1152921504606846975, 1, true), "integral float first bailout retains original operands")
  sameState(loopCounter(1152921504606846973, 1152921504606846975, 0.125), [0.21875, 1152921504606846975], "maximum signed61 counter")
  sameState(loopCounter(-1152921504606846976, -1152921504606846974, 0.125), [0.21875, -1152921504606846974], "minimum signed61 counter")
  sameState(loopCounter(1152921504606846975, 1152921504606846975, 0.125), [0.125, 1152921504606846975], "counter at maximum is zero-trip")

  // Valid immediate encodings: both zeros, both infinities, NaN, and the
  // smallest binary32 subnormal. No special float is string-formatted.
  for each bits in [0, 2147483648, 2139095040, 4286578688, 2143289344, 1]
    special = nativeValueFromRaw((bits << 3) | 5)
    sameState(loopSpecial(2, special, 0.25), referenceSpecial(2, special, 0.25), "special float loop")
  end for
  infinity = nativeValueFromRaw((2139095040 << 3) | 5)
  sameState(loopSpecial(1, infinity, infinity), [0.5, 1], "NaN normalizes before remaining arithmetic")
  expectError(try(loopRecurrence(1, "wrong", 0.2, 0.0)), 1308, "entry contract retained")

  effects = 0
  sameState(noLoopCall(3, 0.125), [0.5, 3], "call path")
  same(effects, 3, "call executes once per iteration")
  effects = 0
  expectError(try(noLoopError(3, 0.125)), 1775, "error after a partial assignment")
  same(effects, 1, "failing call is not repeated")
  same(noLoopGlobal(3), 0.5, "global mutation")
  same(noLoopSynchronized(2), 0.375, "synchronized mutation")
  same(noLoopCapture(3, 0.125), 0.5, "captured local mutation")
  same(noLoopContract(2, 0.125), 0.625, "successful body type guard")
  expectError(try(noLoopContract(1, 0.75)), 1308, "normalized integer fails body float guard")
  sameState(noLoopControl(8, 0.125), [0.5, 4], "break and continue")
  sameState(noLoopReturn(8, 0.125), [0.375, 1], "early return")
  sameState(noLoopChangingBound(5, 0.125), [0.5, 3, 2], "changing bound")
  sameState(noLoopStep(5, 0.125), [0.5, 6], "nonunit counter")
  for each n in [0, 1, 3]
    sameState(noLoopOldAlias(n, 0.123456789012345), referenceOldAlias(n, 0.123456789012345), "old Value alias " + n)
  end for
  firstAlias = noLoopOldAlias(1, 0.123456789012345)
  same(firstAlias[3], true, "old Value keeps its original pointer")
  sameState(noLoopBodyTypeof(0, 0.125), [0.125, 0], "body-local typeof zero trips")
  sameState(noLoopBodyTypeof(3, 0.125), [0.234375, 3], "body-local typeof typed counter")

  // Every recurrence exit needs three real boxes. A collection caused by the
  // first materialization must leave the remaining raw bank and prior roots
  // intact; later materializations must retain each already-published result.
  input = referenceAdd(0.123456789012345, 0.000000000000321)
  right = referenceMul(0.987654321098765, 0.777777777777777)
  initialTotal = referenceAdd(0.111111111111111, 0.000000000000321)
  expected = referenceRecurrence(7, input, right, initialTotal)
  aliasExpected = referenceAlias(7, input)
  check((nativeRawValue(input) & 7) == 0, "GC input is heap-backed")
  for index = 0 to 2
    check((nativeRawValue(expected[index]) & 7) == 0, "GC exit needs boxed state " + index)
  end for
  retained = array(8)
  collectionsBefore = gc_stat(0)
  concurrentBefore = gc_stat(16)
  gc_set_limit(1)
  iteration as int = 0
  while iteration < 24
    result = loopRecurrence(7, input, right, initialTotal)
    aliases = loopAlias(7, input)
    sameState(result, expected, "GC final state")
    sameState(aliases, aliasExpected, "GC aliases")
    retained[iteration % 8] = [result, aliases, input, right]
    iteration = iteration + 1
  end while
  gc_set_limit(0)
  if typeof(concurrentBefore) == "int" then
    gc_collect()
    check(gc_stat(16) > concurrentBefore or gc_stat(0) > collectionsBefore, "concurrent collection completed")
  else
    check(gc_stat(0) > collectionsBefore, "stress actually collected")
    gc_collect()
  end if
  for each record in retained
    sameState(record[0], expected, "retained state survives collection")
    sameState(record[1], aliasExpected, "retained aliases survive collection")
    same(record[2], input, "old input survives exit boxes")
    same(record[3], right, "sibling root survives exit boxes")
  end for
  if failures != 0 then return 1 end if
  print "NUMERIC FLOAT LOOP [OK]"
  return 0
end function
