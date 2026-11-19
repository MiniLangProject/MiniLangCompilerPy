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


function consumerLiteralTiny(n as int, x as float)
  i as int = 0
  while i < n
    x = x + 0.000000000000000000000000000000000000000000001401298464324817
    i = i + 1
  end while
  return [x, i]
end function

extern function phase8_mxcsr_read() from "libphase8_mxcsr.so" returns u32
extern function phase8_mxcsr_write(value as u32) from "libphase8_mxcsr.so" returns void

function main(args)
  saved = phase8_mxcsr_read()
  seed = 0.123456789012345
  nan = nativeValueFromRaw((2143289344 << 3) | 5)
  signalingNan = nativeValueFromRaw((2139095041 << 3) | 5)
  infinity = nativeValueFromRaw((2139095040 << 3) | 5)
  negativeInfinity = nativeValueFromRaw((4286578688 << 3) | 5)
  negativeZero = nativeValueFromRaw((2147483648 << 3) | 5)
  tiny = nativeValueFromRaw((1 << 3) | 5)
  largestSubnormal = nativeValueFromRaw((8388607 << 3) | 5)
  positive60 = nativeValueFromRaw((1568669696 << 3) | 5)
  negative60 = nativeValueFromRaw((3716153344 << 3) | 5)
  positive61 = nativeValueFromRaw((1577058304 << 3) | 5)
  phase8_mxcsr_write(8064)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8064)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8064:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(8128)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "8128:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40832)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40832:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(40896)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "40896:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16256)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16256:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(16320)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "16320:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49024)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49024:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(49088)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "49088:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24448)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24448:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(24512)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "24512:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57216)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57216:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(57280)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "57280:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32640)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32640:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(32704)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "32704:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65408)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65408:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerChain(1, seed, 0.125, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:fractional:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerLeft(1, 0.25, 0.75, 0.375)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:integer-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerChain(1, 0.25, 0.75, 0.0, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:integer-chain:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerChain(1, positive60, 0.0, 0.000000000000000001, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:positive-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerRight(1, negative60, 0.0, 0.000000000000000001)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:negative-wrap:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerChain(1, positive61, 0.0, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:wrap-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerChain(1, infinity, negativeInfinity, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:nan-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerChain(1, nan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:quiet-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerChain(1, signalingNan, 0.25, 0.5, 0.125)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:signaling-nan-source:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerLeft(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:subnormal-left:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerRight(1, tiny, 0.0, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:subnormal-right:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerLeft(1, largestSubnormal, tiny, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:f32-boundary:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerLeft(1, infinity, 0.25, 0.5)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:infinity-child:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerLeft(1, negativeZero, 0.0, 1.0)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:negative-zero:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerLessEqual(1, 0.25, 0.75, 1.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:condition-int:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerEqual(1, infinity, negativeInfinity, 0.0, seed)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:condition-nan:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(65472)
  observed = consumerLiteralTiny(1, largestSubnormal)
  flags = phase8_mxcsr_read()
  phase8_mxcsr_write(saved)
  print "65472:literal-subnormal:" + flags + ":" + typeof(observed[0]) + ":" + observed[1]
  phase8_mxcsr_write(saved)
  return 0
end function
