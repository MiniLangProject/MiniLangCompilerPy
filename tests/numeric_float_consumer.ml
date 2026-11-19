// Float consumers must receive the canonical numeric result of a child,
// including signed61 wrap and the ordinary NaN-to-integer normalization.
// Untyped helper calls keep the references on the preceding scalar path.
failures = 0

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
  if typeof(actual) == "float" and actual != actual then
    return check(expected != expected, label + " NaN")
  end if
  return check(actual == expected, label + " value")
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

// An integer/NaN child has an actual-float sibling. Its canonical wrapped
// numeric value can be consumed without abandoning the current raw iteration.
function consumerLeft(n as int, x as float, y as float, scale as float)
  i as int = 0
  while i < n
    x = (x + y) * scale
    i = i + 1
  end while
  return [x, i]
end function

function referenceLeft(n, x, y, scale)
  i = 0
  while i < n
    x = referenceMul(referenceAdd(x, y), scale)
    i = i + 1
  end while
  return [x, i]
end function

// The left value is saved while the right child enters its normalization
// continuation. That continuation must preserve the saved XMM register.
function consumerRight(n as int, x as float, y as float, scale as float)
  i as int = 0
  while i < n
    x = scale * (x + y)
    i = i + 1
  end while
  return [x, i]
end function

function referenceRight(n, x, y, scale)
  i = 0
  while i < n
    x = referenceMul(scale, referenceAdd(x, y))
    i = i + 1
  end while
  return [x, i]
end function

// Both internal nodes can normalize to int in one iteration. The assignment
// root still must remain a float before it may enter the committed bank.
function consumerChain(n as int, x as float, y as float, scale as float, offset as float)
  i as int = 0
  while i < n
    x = ((x + y) * scale) + offset
    i = i + 1
  end while
  return [x, i]
end function

function referenceChain(n, x, y, scale, offset)
  i = 0
  while i < n
    x = referenceAdd(referenceMul(referenceAdd(x, y), scale), offset)
    i = i + 1
  end while
  return [x, i]
end function

// A cached fresh definition is also a proven float sibling. The second tree
// needs a saved left value and fans its result out to two observable aliases.
function consumerFresh(n as int, seed as float, y as float, z as float)
  x = seed
  copy = seed
  tail = seed
  old = seed
  i as int = 0
  while i < n
    first = x * 0.75 + 0.012345678901234
    second = first * (y + z)
    x = first
    copy = second
    tail = second
    i = i + 1
  end while
  return [x, copy, tail, old, i, nativeRawValue(copy) == nativeRawValue(tail), nativeRawValue(old) == nativeRawValue(seed)]
end function

function referenceFresh(n, seed, y, z)
  x = seed
  copy = seed
  tail = seed
  old = seed
  i = 0
  while i < n
    first = referenceAdd(referenceMul(x, 0.75), 0.012345678901234)
    second = referenceMul(first, referenceAdd(y, z))
    x = first
    copy = second
    tail = second
    i = i + 1
  end while
  return [x, copy, tail, old, i, nativeRawValue(copy) == nativeRawValue(tail), nativeRawValue(old) == nativeRawValue(seed)]
end function

// Neither arithmetic sibling is proven to remain float. Integer/integer
// arithmetic can produce an odd result above 2^53 and must retain rollback.
function consumerBoth(n as int, a as float, b as float, c as float, d as float, seed as float)
  result = seed
  i as int = 0
  while i < n
    result = (a * b) + (c * d)
    i = i + 1
  end while
  return [result, i]
end function

function referenceBoth(n, a, b, c, d, seed)
  result = seed
  i = 0
  while i < n
    result = referenceAdd(referenceMul(a, b), referenceMul(c, d))
    i = i + 1
  end while
  return [result, i]
end function

// Comparison roots with two arithmetic sides remain outside this bounded
// consumer rule. Only the existing body's float-sibling child is eligible.
function consumerBothCondition(n as int, a as float, b as float, c as float, d as float, seed as float)
  x = seed
  i as int = 0
  while i < n and (a + b) <= (c + d)
    x = x * 0.5 + 0.123456789012345
    i = i + 1
  end while
  return [x, i]
end function

function referenceBothCondition(n, a, b, c, d, seed)
  x = seed
  i = 0
  while i < n and referenceAdd(a, b) <= referenceAdd(c, d)
    x = referenceAdd(referenceMul(x, 0.5), 0.123456789012345)
    i = i + 1
  end while
  return [x, i]
end function

// A final integer assignment root must still roll back earlier cached values.
// Repeated ordinary retries and guarded reentry must advance the counter once.
function consumerLate(n as int, x as float, y as float, z as float)
  copy = x
  i as int = 0
  while i < n and x + y <= 20.0
    first = (x + y) * 0.375 + 0.012345678901234
    second = first * 0.25 + 0.023456789012345
    x = first
    y = second
    z = z + 0.25
    copy = first
    i = i + 1
  end while
  return [x, y, z, copy, i, nativeRawValue(x) == nativeRawValue(copy)]
end function

function referenceLate(n, x, y, z)
  copy = x
  i = 0
  while i < n and referenceAdd(x, y) <= 20.0
    first = referenceAdd(referenceMul(referenceAdd(x, y), 0.375), 0.012345678901234)
    second = referenceAdd(referenceMul(first, 0.25), 0.023456789012345)
    x = first
    y = second
    z = referenceAdd(z, 0.25)
    copy = first
    i = i + 1
  end while
  return [x, y, z, copy, i, nativeRawValue(x) == nativeRawValue(copy)]
end function

function consumerEqual(n as int, a as float, b as float, bound as float, seed as float)
  x = seed
  i as int = 0
  while i < n and a + b == bound
    x = x * 0.5 + 0.123456789012345
    i = i + 1
  end while
  return [x, i, nativeRawValue(x) == nativeRawValue(seed)]
end function

function consumerUnequal(n as int, a as float, b as float, bound as float, seed as float)
  x = seed
  i as int = 0
  while i < n and a + b != bound
    x = x * 0.5 + 0.123456789012345
    i = i + 1
  end while
  return [x, i, nativeRawValue(x) == nativeRawValue(seed)]
end function

function consumerLess(n as int, a as float, b as float, bound as float, seed as float)
  x = seed
  i as int = 0
  while i < n and a + b < bound
    x = x * 0.5 + 0.123456789012345
    i = i + 1
  end while
  return [x, i, nativeRawValue(x) == nativeRawValue(seed)]
end function

function consumerLessEqual(n as int, a as float, b as float, bound as float, seed as float)
  x = seed
  i as int = 0
  while i < n and a + b <= bound
    x = x * 0.5 + 0.123456789012345
    i = i + 1
  end while
  return [x, i, nativeRawValue(x) == nativeRawValue(seed)]
end function

function consumerGreater(n as int, a as float, b as float, bound as float, seed as float)
  x = seed
  i as int = 0
  while i < n and a + b > bound
    x = x * 0.5 + 0.123456789012345
    i = i + 1
  end while
  return [x, i, nativeRawValue(x) == nativeRawValue(seed)]
end function

function consumerGreaterEqual(n as int, a as float, b as float, bound as float, seed as float)
  x = seed
  i as int = 0
  while i < n and a + b >= bound
    x = x * 0.5 + 0.123456789012345
    i = i + 1
  end while
  return [x, i, nativeRawValue(x) == nativeRawValue(seed)]
end function

// A right comparison tree must preserve its already evaluated left operand.
function consumerConditionRight(n as int, a as float, b as float, bound as float, seed as float)
  x = seed
  i as int = 0
  while i < n and bound <= a + b
    x = x * 0.5 + 0.123456789012345
    i = i + 1
  end while
  return [x, i, nativeRawValue(x) == nativeRawValue(seed)]
end function

function referencePredicate(left, right, op)
  if op == 0 then return left == right end if
  if op == 1 then return left != right end if
  if op == 2 then return left < right end if
  if op == 3 then return left <= right end if
  if op == 4 then return left > right end if
  return left >= right
end function

function referenceCompare(n, a, b, bound, seed, op)
  x = seed
  i = 0
  while i < n and referencePredicate(referenceAdd(a, b), bound, op)
    x = referenceAdd(referenceMul(x, 0.5), 0.123456789012345)
    i = i + 1
  end while
  return [x, i, nativeRawValue(x) == nativeRawValue(seed)]
end function

function referenceConditionRight(n, a, b, bound, seed)
  x = seed
  i = 0
  while i < n and bound <= referenceAdd(a, b)
    x = referenceAdd(referenceMul(x, 0.5), 0.123456789012345)
    i = i + 1
  end while
  return [x, i, nativeRawValue(x) == nativeRawValue(seed)]
end function

// A mixture of exactly encoded binary32 and boxed binary64 literals must
// decode the same values. Normalization probes retain their original order.
function consumerLiterals(n as int, x as float)
  i as int = 0
  while i < n
    first = x * 0.125 + 0.123456789012345
    second = first + 0.25 * x
    x = second
    i = i + 1
  end while
  return [x, i]
end function

function referenceLiterals(n, x)
  i = 0
  while i < n
    first = referenceAdd(referenceMul(x, 0.125), 0.123456789012345)
    second = referenceAdd(first, referenceMul(0.25, x))
    x = second
    i = i + 1
  end while
  return [x, i]
end function

function main(args)
  global failures
  seed = 0.123456789012345
  nan = nativeValueFromRaw((2143289344 << 3) | 5)
  infinity = nativeValueFromRaw((2139095040 << 3) | 5)
  negativeInfinity = nativeValueFromRaw((4286578688 << 3) | 5)
  negativeZero = nativeValueFromRaw((2147483648 << 3) | 5)
  tiny = nativeValueFromRaw((1 << 3) | 5)
  largestSubnormal = nativeValueFromRaw((8388607 << 3) | 5)
  smallestNormal = nativeValueFromRaw((8388608 << 3) | 5)
  positive60 = nativeValueFromRaw((1568669696 << 3) | 5)
  negative60 = nativeValueFromRaw((3716153344 << 3) | 5)
  positive61 = nativeValueFromRaw((1577058304 << 3) | 5)
  negative61 = nativeValueFromRaw((3724541952 << 3) | 5)
  negative63 = nativeValueFromRaw((3741319168 << 3) | 5)

  for each n in [0, 1, 3, 9]
    sameState(consumerLeft(n, 0.25, 0.75, 0.375), referenceLeft(n, 0.25, 0.75, 0.375), "integer left child " + n)
    sameState(consumerRight(n, 0.25, 0.75, 0.375), referenceRight(n, 0.25, 0.75, 0.375), "integer right child " + n)
    sameState(consumerChain(n, 0.25, 0.75, 0.0, 0.125), referenceChain(n, 0.25, 0.75, 0.0, 0.125), "successive integer children " + n)
    sameState(consumerFresh(n, seed, 0.25, 0.75), referenceFresh(n, seed, 0.25, 0.75), "fresh cached float sibling " + n)
    sameState(consumerBoth(n, 0.125, 0.375, 0.25, 0.625, seed), referenceBoth(n, 0.125, 0.375, 0.25, 0.625, seed), "two arithmetic children " + n)
    sameState(consumerBothCondition(n, 0.25, 0.75, 0.5, 0.5, seed), referenceBothCondition(n, 0.25, 0.75, 0.5, 0.5, seed), "two comparison roots " + n)
    sameState(consumerLiterals(n, seed), referenceLiterals(n, seed), "immediate and boxed literals " + n)
  end for
  sameState(consumerLeft(1, 0.25, 0.75, 0.375), [0.375, 1], "canonical child remains usable")
  sameState(consumerRight(1, 0.25, 0.75, 0.375), [0.375, 1], "right canonical child remains usable")
  sameState(consumerChain(3, 0.25, 0.75, 0.0, 0.125), [0.125, 3], "integer continuations make raw progress")

  for each large in [positive60, negative60, positive61, negative61, negative63]
    sameState(consumerChain(1, large, 0.0, 0.000000000000000001, 0.125), referenceChain(1, large, 0.0, 0.000000000000000001, 0.125), "signed61 child canonicalization")
    sameState(consumerRight(1, large, 0.0, 0.000000000000000001), referenceRight(1, large, 0.0, 0.000000000000000001), "right signed61 child canonicalization")
  end for
  sameState(consumerChain(1, positive61, 0.0, 0.000000000000000001, 0.125), [0.125, 1], "positive61 wraps to zero before float parent")
  sameState(consumerChain(1, negative63, 0.0, 0.000000000000000001, 0.125), [0.125, 1], "negative63 wraps to zero before float parent")
  sameState(consumerChain(1, infinity, negativeInfinity, 0.5, 0.125), [0.125, 1], "NaN child normalizes to zero")
  sameState(consumerChain(1, nan, 0.25, 0.5, 0.125), [0.125, 1], "NaN leaf produces canonical child")
  exact = consumerBoth(1, 9007199254740992.0, 1.0, 1.0, 1.0, seed)
  sameState(exact, [9007199254740993, 1], "two integer children keep precision above 2^53")

  for each special in [nan, infinity, negativeInfinity, negativeZero, tiny, largestSubnormal, smallestNormal]
    sameState(consumerLeft(3, special, 0.25, 0.5), referenceLeft(3, special, 0.25, 0.5), "special left child")
    sameState(consumerRight(3, special, 0.25, 0.5), referenceRight(3, special, 0.25, 0.5), "special right child")
    sameState(consumerLiterals(3, special), referenceLiterals(3, special), "special literal arithmetic")
    sameState(consumerFresh(0, special, 0.25, 0.75), referenceFresh(0, special, 0.25, 0.75), "zero trips retain original aliases")
  end for
  sameState(consumerLeft(1, negativeZero, 0.0, 1.0), [0, 1], "integer assignment root still normalizes")
  sameState(consumerBothCondition(3, infinity, negativeInfinity, 0.0, 0.0, seed), referenceBothCondition(3, infinity, negativeInfinity, 0.0, 0.0, seed), "two-root condition retains scalar normalization")

  for each n in [1, 2, 3, 4, 9, 13]
    sameState(consumerLate(n, 0.25, 0.75, 0.25), referenceLate(n, 0.25, 0.75, 0.25), "late assignment-root rollback " + n)
  end for
  sameState(consumerLate(1, 0.25, 0.75, 0.75), referenceLate(1, 0.25, 0.75, 0.75), "first-iteration assignment-root rollback")
  late = consumerLate(3, 0.25, 0.75, 0.25)
  same(late[2], 1, "late assignment normalizes to integer")
  same(late[4], 3, "rollback advances exactly once")
  same(late[5], true, "rollback preserves alias fanout")

  comparators = [consumerEqual, consumerUnequal, consumerLess, consumerLessEqual, consumerGreater, consumerGreaterEqual]
  cases = [[0.25, 0.75, 1.0], [0.25, 0.75, 0.5], [0.25, 0.75, 1.5], [infinity, negativeInfinity, 0.0], [nan, 0.25, 0.0], [0.25, 0.75, nan], [positive60, 0.0, 0.0], [negative60, 0.0, 0.0], [positive61, 0.0, 0.0], [negative63, 0.0, 0.0], [negativeZero, 0.0, 0.0], [tiny, 0.0, 0.0]]
  for op = 0 to 5
    for each values in cases
      sameState(comparators[op](3, values[0], values[1], values[2], seed), referenceCompare(3, values[0], values[1], values[2], seed, op), "canonical comparison " + op)
    end for
  end for
  for each values in cases
    sameState(consumerConditionRight(3, values[0], values[1], values[2], seed), referenceConditionRight(3, values[0], values[1], values[2], seed), "right comparison continuation")
  end for
  sameState(consumerEqual(0, nan, infinity, negativeInfinity, seed), [seed, 0, true], "false counter skips canonical condition")
  sameState(consumerEqual(3, 0.25, 0.75, 0.5, seed), [seed, 0, true], "false first canonical condition retains original Value")

  if failures != 0 then return 1 end if
  print "NUMERIC FLOAT CONSUMER [OK]"
  return 0
end function
