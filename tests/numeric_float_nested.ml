// Nested float loops and compound-condition reentry must preserve every Value
// normalization boundary. The untyped helpers keep reference loops ordinary.
failures = 0
effects = 0
globalNestedValue = 0.125

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
  else if typeof(actual) == "float" and actual != actual then
    check(expected != expected, label + " NaN")
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

function referenceAdd(a, b) return a + b end function
function referenceMul(a, b) return a * b end function
function referenceSub(a, b) return a - b end function

function nestedCounted(rounds as int, n as int, x as float)
  round as int = 0
  while round < rounds
    i as int = 0
    while i < n
      x = x * 0.9999991 + 0.0000007
      i = i + 1
    end while
    round = round + 1
  end while
  return [x, round]
end function

function referenceCounted(rounds, n, x)
  round = 0
  while round < rounds
    i = 0
    while i < n
      x = referenceAdd(referenceMul(x, 0.9999991), 0.0000007)
      i = i + 1
    end while
    round = round + 1
  end while
  return [x, round]
end function

// Candidate sites in mutually exclusive arms have different local counters.
function nestedBranches(first, n as int, x as float)
  if first then
    left as int = 0
    while left < n
      x = x * 0.9999991 + 0.0000007
      left = left + 1
    end while
  else
    right as int = 0
    while right < n
      x = x * 0.9999991 + 0.0000007
      right = right + 1
    end while
  end if
  return x
end function

// Sibling sites have different state/definition maps but share the private
// frame reservation. A later site must reload the newly materialized homes.
function nestedSiblings(rounds as int, n as int, x as float, y as float, z as float)
  round as int = 0
  while round < rounds
    left as int = 0
    while left < n and x + y <= 4.0
      x = x * 0.5 + 0.123456789012345
      y = y * 0.5 + 0.234567890123456
      left = left + 1
    end while
    right as int = 0
    while right < n and y + z <= 4.0
      y = y * 0.5 + 0.234567890123456
      z = z * 0.5 + 0.345678901234567
      right = right + 1
    end while
    round = round + 1
  end while
  return [x, y, z, round]
end function

function referenceSiblings(rounds, n, x, y, z)
  round = 0
  while round < rounds
    left = 0
    while left < n and referenceAdd(x, y) <= 4.0
      x = referenceAdd(referenceMul(x, 0.5), 0.123456789012345)
      y = referenceAdd(referenceMul(y, 0.5), 0.234567890123456)
      left = left + 1
    end while
    right = 0
    while right < n and referenceAdd(y, z) <= 4.0
      y = referenceAdd(referenceMul(y, 0.5), 0.234567890123456)
      z = referenceAdd(referenceMul(z, 0.5), 0.345678901234567)
      right = right + 1
    end while
    round = round + 1
  end while
  return [x, y, z, round]
end function

// The third store crosses an int boundary repeatedly. Earlier tentative
// writes must roll back, and each ordinary retry must make exactly one step.
function compoundReentry(n as int, x as float, y as float, z as float)
  i as int = 0
  while i < n and x + y <= 20.0
    x = x + 0.125
    y = y + 0.0625
    z = z + 0.25
    i = i + 1
  end while
  return [x, y, z, i]
end function

function referenceReentry(n, x, y, z)
  i = 0
  while i < n and referenceAdd(x, y) <= 20.0
    x = referenceAdd(x, 0.125)
    y = referenceAdd(y, 0.0625)
    z = referenceAdd(z, 0.25)
    i = i + 1
  end while
  return [x, y, z, i]
end function

// Escape after committed iterations must use the current raw state, and
// materialize one shared Value for the two final aliases.
function compoundEscape(n as int, x as float, y as float)
  copy = x
  old = x
  i as int = 0
  while i < n and x + y <= 1.0
    next = x + 0.13
    x = next
    copy = next
    y = y * 0.75 + 0.017
    i = i + 1
  end while
  return [x, y, copy, old, i, nativeRawValue(x) == nativeRawValue(copy)]
end function

function referenceEscape(n, x, y)
  copy = x
  old = x
  i = 0
  while i < n and referenceAdd(x, y) <= 1.0
    next = referenceAdd(x, 0.13)
    x = next
    copy = next
    y = referenceAdd(referenceMul(y, 0.75), 0.017)
    i = i + 1
  end while
  return [x, y, copy, old, i, nativeRawValue(x) == nativeRawValue(copy)]
end function

function compoundCounter(start as int, limit as int, x as float)
  i as int = start
  while i < limit and x <= 4.0
    x = x * 0.5 + 0.125
    i as int = i + 1
  end while
  return [x, i]
end function

function compoundIntegerEntry(n as int, first as int, second as int, floats)
  x = first
  y = second
  if floats then
    x = toFloat(first)
    y = toFloat(second)
  end if
  i as int = 0
  while i < n and x * 0.000000000000000001 + y * 0.000000000000000001 <= 4.0
    x = x + y
    y = y + 0.25
    i = i + 1
  end while
  return [x, y, i]
end function

function referenceIntegerEntry(n, first, second, floats)
  x = first
  y = second
  if floats then
    x = toFloat(first)
    y = toFloat(second)
  end if
  i = 0
  while i < n and referenceAdd(referenceMul(x, 0.000000000000000001), referenceMul(y, 0.000000000000000001)) <= 4.0
    x = referenceAdd(x, y)
    y = referenceAdd(y, 0.25)
    i = i + 1
  end while
  return [x, y, i]
end function

// With .25/.75 the sum stays integer 1 on every condition evaluation.
// Repeated condition misses must execute the scalar body instead of spinning.
function compoundNormalizeCondition(n as int, x as float, y as float)
  i as int = 0
  while i < n and x + y <= 4.0
    x = x * 0.5 + 0.125
    y = y * 0.5 + 0.375
    i = i + 1
  end while
  return [x, y, i]
end function

function referenceNormalizeCondition(n, x, y)
  i = 0
  while i < n and referenceAdd(x, y) <= 4.0
    x = referenceAdd(referenceMul(x, 0.5), 0.125)
    y = referenceAdd(referenceMul(y, 0.5), 0.375)
    i = i + 1
  end while
  return [x, y, i]
end function

function compoundShortCircuit(n as int, divisor as int)
  x = 3.0 / toFloat(divisor)
  i as int = 0
  while i < n and x + 0.125 <= 4.0
    x = x * 0.5 + 0.125
    i = i + 1
  end while
  return [x, i]
end function

function compoundAliases(n as int, seed as float)
  x = seed
  copy = seed
  old = seed
  i as int = 0
  while i < n and x <= 4.0
    next = x * 0.9999991 + 0.0000007
    x = next
    copy = x
    i = i + 1
  end while
  return [x, copy, old, i, nativeRawValue(x) == nativeRawValue(copy), nativeRawValue(old) == nativeRawValue(seed)]
end function

function referenceAliases(n, seed)
  x = seed
  copy = seed
  old = seed
  i = 0
  while i < n and x <= 4.0
    next = referenceAdd(referenceMul(x, 0.9999991), 0.0000007)
    x = next
    copy = x
    i = i + 1
  end while
  return [x, copy, old, i, nativeRawValue(x) == nativeRawValue(copy), nativeRawValue(old) == nativeRawValue(seed)]
end function

function compoundWriteOnly(n as int, initial as float, oldOutput)
  x = initial
  output = oldOutput
  i as int = 0
  while i < n and x <= 4.0
    next = x * 0.9999991 + 0.0000007
    x = next
    output = next
    i = i + 1
  end while
  return [x, output, i, nativeRawValue(x) == nativeRawValue(initial)]
end function

function compoundBothTrees(n as int, a as float, b as float, c as float, d as float, x as float)
  i as int = 0
  while i < n and (a * b + c * d) <= (a * c + b * d)
    x = x * 0.5 + 0.125
    i = i + 1
  end while
  return [x, i]
end function

function referenceBothTrees(n, a, b, c, d, x)
  i = 0
  while i < n and referenceAdd(referenceMul(a, b), referenceMul(c, d)) <= referenceAdd(referenceMul(a, c), referenceMul(b, d))
    x = referenceAdd(referenceMul(x, 0.5), 0.125)
    i = i + 1
  end while
  return [x, i]
end function

function compareEqual(n as int, left as float, right as float, x as float)
  i as int = 0
  while i < n and left == right
    x = x * 0.5 + 0.125
    i = i + 1
  end while
  return [x, i]
end function

function compareUnequal(n as int, left as float, right as float, x as float)
  i as int = 0
  while i < n and left != right
    x = x * 0.5 + 0.125
    i = i + 1
  end while
  return [x, i]
end function

function compareLess(n as int, left as float, right as float, x as float)
  i as int = 0
  while i < n and left < right
    x = x * 0.5 + 0.125
    i = i + 1
  end while
  return [x, i]
end function

function compareLessEqual(n as int, left as float, right as float, x as float)
  i as int = 0
  while i < n and left <= right
    x = x * 0.5 + 0.125
    i = i + 1
  end while
  return [x, i]
end function

function compareGreater(n as int, left as float, right as float, x as float)
  i as int = 0
  while i < n and left > right
    x = x * 0.5 + 0.125
    i = i + 1
  end while
  return [x, i]
end function

function compareGreaterEqual(n as int, left as float, right as float, x as float)
  i as int = 0
  while i < n and left >= right
    x = x * 0.5 + 0.125
    i = i + 1
  end while
  return [x, i]
end function

function referencePredicate(left, right, op)
  if op == 0 then return left == right end if
  if op == 1 then return left != right end if
  if op == 2 then return left < right end if
  if op == 3 then return left <= right end if
  if op == 4 then return left > right end if
  return left >= right
end function

function referenceCompare(n, left, right, x, op)
  i = 0
  while i < n and referencePredicate(left, right, op)
    x = referenceAdd(referenceMul(x, 0.5), 0.125)
    i = i + 1
  end while
  return [x, i]
end function

// This is the original three-level Mandelbrot shape, including float zeros,
// unannotated numeric state and the source operation order.
function nestedMandel(n as int, seed as int)
  scale = 3.0 / toFloat(n)
  offset = toFloat(seed & 255) * 0.0000001
  checksum as int = 0
  py as int = 0
  while py < n
    cy = -1.5 + toFloat(py) * scale
    px as int = 0
    while px < n
      cx = -2.0 + toFloat(px) * scale + offset
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

function referenceMandel(n, seed)
  scale = 3.0 / toFloat(n)
  offset = toFloat(seed & 255) * 0.0000001
  checksum = 0
  py = 0
  while py < n
    cy = -1.5 + toFloat(py) * scale
    px = 0
    while px < n
      cx = -2.0 + toFloat(px) * scale + offset
      zr = 0.0
      zi = 0.0
      zr2 = 0.0
      zi2 = 0.0
      iteration = 0
      while iteration < 80 and referenceAdd(zr2, zi2) <= 4.0
        zi = referenceAdd(referenceMul(referenceMul(2.0, zr), zi), cy)
        zr = referenceAdd(referenceSub(zr2, zi2), cx)
        zr2 = referenceMul(zr, zr)
        zi2 = referenceMul(zi, zi)
        iteration = iteration + 1
      end while
      checksum = checksum + iteration
      px = px + 1
    end while
    py = py + 1
  end while
  return checksum
end function

function calledCondition(value)
  global effects
  effects = effects + 1
  return value <= 4.0
end function

function noNestedCall(n as int, x as float)
  i as int = 0
  while i < n and calledCondition(x)
    x = x + 0.125
    i = i + 1
  end while
  return [x, i]
end function

function noNestedGlobal(n as int)
  global globalNestedValue
  i as int = 0
  while i < n and globalNestedValue <= 4.0
    globalNestedValue = globalNestedValue + 0.125
    i = i + 1
  end while
  return globalNestedValue
end function

function noNestedCapture(n as int, x as float)
  function read() return x end function
  i as int = 0
  while i < n and x <= 4.0
    x = x + 0.125
    i = i + 1
  end while
  return read()
end function

function noNestedOldAlias(n as int, seed as float)
  x = seed
  old = seed
  i as int = 0
  while i < n and x <= 4.0
    old = x
    x = x * 0.5 + 0.125
    i = i + 1
  end while
  return [x, old, i, nativeRawValue(old) == nativeRawValue(seed)]
end function

function noNestedChangingBound(n as int, x as float)
  i as int = 0
  while i < n and x <= 4.0
    x = x + 0.125
    n = n - 1
    i = i + 1
  end while
  return [x, i, n]
end function

function noNestedOr(n as int, x as float)
  i as int = 0
  while i < n or x < 0.5
    x = x + 0.125
    i = i + 1
  end while
  return [x, i]
end function

// Separate declarations with the same spelling must not share a raw slot.
function noNestedDuplicate(first, n as int, left as float, right as float)
  result = 0.0
  if first then
    x = left
    i as int = 0
    while i < n and x <= 4.0
      x = x * 0.5 + 0.125
      i = i + 1
    end while
    result = x
  else
    x = right
    j as int = 0
    while j < n and x <= 4.0
      x = x * 0.5 + 0.125
      j = j + 1
    end while
    result = x
  end if
  return result
end function

function inline inlineLoop(n as int, x as float)
  i as int = 0
  while i < n and x <= 4.0
    x = x * 0.5 + 0.125
    i = i + 1
  end while
  return x
end function

function noNestedInline(n as int, x as float)
  return inlineLoop(n, x)
end function

function main(args)
  global failures, effects
  for each n in [0, 1, 7]
    sameState(nestedCounted(3, n, 0.123456789012345), referenceCounted(3, n, 0.123456789012345), "nested counted " + n)
    expected = referenceCounted(1, n, 0.123456789012345)
    same(nestedBranches(true, n, 0.123456789012345), expected[0], "if branch " + n)
    same(nestedBranches(false, n, 0.123456789012345), expected[0], "else branch " + n)
    sameState(nestedSiblings(3, n, 0.123456789012345, 0.234567890123456, 0.345678901234567), referenceSiblings(3, n, 0.123456789012345, 0.234567890123456, 0.345678901234567), "sibling arenas " + n)
    sameState(compoundAliases(n, 0.123456789012345), referenceAliases(n, 0.123456789012345), "new Value aliases " + n)
  end for
  for each n in [1, 3, 4, 13, 40]
    sameState(compoundReentry(n, 0.125, 0.0625, 0.25), referenceReentry(n, 0.125, 0.0625, 0.25), "repeated late rollback " + n)
  end for
  sameState(compoundReentry(3, 0.125, 0.0625, 0.25), [0.5, 0.25, 1, 3], "third write commits once")
  sameState(compoundReentry(9, 0.125, 0.5, 0.125), referenceReentry(9, 0.125, 0.5, 0.125), "later condition normalization rolls back once")
  sameState(compoundEscape(100, 0.123456789012345, 0.234567890123456), referenceEscape(100, 0.123456789012345, 0.234567890123456), "escape sees latest committed state")
  escaped = compoundEscape(100, 0.123456789012345, 0.234567890123456)
  check(escaped[4] > 1 and escaped[4] < 100, "escape follows multiple committed iterations")
  sameState(compoundCounter(1152921504606846973, 1152921504606846975, 0.125), [0.21875, 1152921504606846975], "compound maximum signed61 counter")
  sameState(compoundCounter(-1152921504606846976, -1152921504606846974, 0.125), [0.21875, -1152921504606846974], "compound minimum signed61 counter")
  sameState(compoundCounter(1152921504606846975, 1152921504606846975, 0.125), [0.125, 1152921504606846975], "compound maximum zero trip")
  sameState(compoundNormalizeCondition(13, 0.25, 0.75), [0.25, 0.75, 13], "integer condition makes progress")
  sameState(compoundNormalizeCondition(13, 0.0, 0.0), referenceNormalizeCondition(13, 0.0, 0.0), "initial zero normalization and reentry")
  sameState(compoundNormalizeCondition(2, 3.75, 0.25), referenceNormalizeCondition(2, 3.75, 0.25), "exact escape boundary")
  sameState(compoundNormalizeCondition(8, 4.25, 0.25), [4.25, 0.25, 0], "false escape before first iteration")
  sameState(compoundIntegerEntry(1, 9007199254740993, 1, false), [9007199254740994, 1.25, 1], "integer precision above 2^53")
  sameState(compoundIntegerEntry(1, 1152921504606846975, 1, false), [-1152921504606846976, 1.25, 1], "positive signed61 wrap")
  sameState(compoundIntegerEntry(1, -1152921504606846976, -1, false), [1152921504606846975, -0.75, 1], "negative signed61 wrap")
  sameState(compoundIntegerEntry(6, 2, 1, false), referenceIntegerEntry(6, 2, 1, false), "integer entry then float reentry")
  sameState(compoundIntegerEntry(6, 2, 1, true), referenceIntegerEntry(6, 2, 1, true), "integral float entry")
  sameState(compoundShortCircuit(0, 0), [void, 0], "false counter does not inspect void condition")
  shortError = try(compoundShortCircuit(1, 0))
  check(typeof(shortError) == "error", "live invalid condition still fails")
  sameState(compoundWriteOnly(0, 0.123456789012345, "old"), [0.123456789012345, "old", 0, true], "zero counter preserves write-only output")
  sameState(compoundWriteOnly(7, 4.25, "old"), [4.25, "old", 0, true], "false condition preserves write-only output")
  aliases = compoundAliases(7, 4.25)
  sameState(aliases, [4.25, 4.25, 4.25, 0, true, true], "false condition preserves aliases")
  for each n in [0, 1, 7]
    sameState(compoundBothTrees(n, 0.123456789, 0.876543219, 0.246813579, 0.975318642, 0.123456789), referenceBothTrees(n, 0.123456789, 0.876543219, 0.246813579, 0.975318642, 0.123456789), "two condition trees " + n)
  end for

  nan = nativeValueFromRaw((2143289344 << 3) | 5)
  positiveInfinity = nativeValueFromRaw((2139095040 << 3) | 5)
  negativeInfinity = nativeValueFromRaw((4286578688 << 3) | 5)
  negativeZero = nativeValueFromRaw((2147483648 << 3) | 5)
  tiny = nativeValueFromRaw((1 << 3) | 5)
  comparators = [compareEqual, compareUnequal, compareLess, compareLessEqual, compareGreater, compareGreaterEqual]
  pairs = [[0.25, 0.25], [0.25, 0.75], [0.75, 0.25], [nan, 0.25], [0.25, nan], [positiveInfinity, positiveInfinity], [negativeZero, 0.0], [tiny, 0.0]]
  for op = 0 to 5
    for each pair in pairs
      sameState(comparators[op](3, pair[0], pair[1], 0.123456789012345), referenceCompare(3, pair[0], pair[1], 0.123456789012345, op), "comparison " + op)
    end for
  end for
  sameState(compoundNormalizeCondition(3, positiveInfinity, negativeInfinity), referenceNormalizeCondition(3, positiveInfinity, negativeInfinity), "condition NaN remains unordered before comparison")
  sameState(compoundAliases(3, nan), referenceAliases(3, nan), "leaf NaN is unordered and preserves zero-trip Value")
  for each n in [1, 3, 5, 17]
    same(nestedMandel(n, 12345), referenceMandel(n, 12345), "original Mandelbrot shape " + n)
  end for

  effects = 0
  sameState(noNestedCall(3, 0.125), [0.5, 3], "effectful condition")
  same(effects, 3, "short-circuit condition calls once per live iteration")
  same(noNestedGlobal(3), 0.5, "global state")
  same(noNestedCapture(3, 0.125), 0.5, "captured state")
  sameState(noNestedOldAlias(1, 0.123456789012345), [referenceAdd(referenceMul(0.123456789012345, 0.5), 0.125), 0.123456789012345, 1, true], "old Value identity")
  sameState(noNestedChangingBound(5, 0.125), [0.5, 3, 2], "changing counter bound")
  sameState(noNestedOr(3, 0.125), [0.5, 3], "unsupported or condition")
  same(noNestedDuplicate(true, 2, 0.125, 0.375), 0.21875, "first distinct binding")
  same(noNestedDuplicate(false, 2, 0.125, 0.375), 0.28125, "second distinct binding")
  same(noNestedInline(2, 0.125), 0.21875, "inlined loop uses ordinary homes")

  // Collection during an inner exit or reentry materialization must preserve
  // outer roots, earlier result groups and raw values still awaiting boxes.
  input = referenceAdd(0.123456789012345, 0.000000000000321)
  right = referenceMul(0.987654321098765, 0.777777777777777)
  tail = referenceAdd(0.111111111111111, 0.000000000000321)
  expectedSiblings = referenceSiblings(3, 7, input, right, tail)
  expectedAliases = referenceAliases(7, input)
  check((nativeRawValue(input) & 7) == 0, "retained input is boxed")
  for slot = 0 to 2
    check((nativeRawValue(expectedSiblings[slot]) & 7) == 0, "nested output is boxed " + slot)
  end for
  retained = array(8)
  before = gc_stat(0)
  gc_set_limit(1)
  repeat as int = 0
  while repeat < 24
    siblingResult = nestedSiblings(3, 7, input, right, tail)
    aliasResult = compoundAliases(7, input)
    rollbackResult = compoundReentry(13, input, right, 0.25)
    sameState(siblingResult, expectedSiblings, "GC nested results")
    sameState(aliasResult, expectedAliases, "GC grouped aliases")
    sameState(rollbackResult, referenceReentry(13, input, right, 0.25), "GC reentry materialization")
    retained[repeat % 8] = [siblingResult, aliasResult, input, right]
    repeat = repeat + 1
  end while
  gc_set_limit(0)
  check(gc_stat(0) > before, "stress actually collected")
  gc_collect()
  for each record in retained
    sameState(record[0], expectedSiblings, "retained nested results")
    sameState(record[1], expectedAliases, "retained nested aliases")
    same(record[2], input, "outer input survives inner materialization")
    same(record[3], right, "outer sibling survives inner materialization")
  end for
  if failures != 0 then return 1 end if
  print "NUMERIC FLOAT NESTED [OK]"
  return 0
end function
