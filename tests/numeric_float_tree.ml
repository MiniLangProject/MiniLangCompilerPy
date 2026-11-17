// Every reference materializes each operation with untyped operands. The
// guarded tree may skip boxes only while every inner result remains a float.
// Integer, unordered and invalid intermediate cases retain the old expression.

failures = 0
effects = 0
globalTreeValue = 0.1
synchronized synchronizedTreeValue = 0.1

struct TreeBox
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
  check(typeof(actual) == typeof(expected), label + " tag")
  if typeof(actual) == "error" and typeof(expected) == "error" then
    check(actual.code == expected.code, label + " code")
    check(actual.message == expected.message, label + " message")
  else
    check(actual == expected, label + " value")
  end if
  return true
end function

function sameComparisons(actual, expected, label)
  for i = 0 to 5
    same(actual[i], expected[i], label + " comparison " + i)
  end for
  return true
end function

function expectError(actual, code, label)
  if not check(typeof(actual) == "error", label + " type") then return false end if
  return check(actual.code == code, label + " code")
end function

function referenceBalanced(a, b, c, d)
  left = a * b
  right = c * d
  return left + right
end function

function referenceDeep(a, b, c, d)
  first = a * b
  second = first + c
  return second * d
end function

function referenceEight(a, b, c, d, e, f, g, h)
  first = a * b
  second = c * d
  left = first + second
  third = e * f
  fourth = g * h
  right = third + fourth
  return left * right
end function

function referenceRightNested(a, b, c, d)
  first = c + d
  second = b * first
  return a + second
end function

function referenceCancellation(a, b, c)
  first = a + b
  second = first - c
  return second + 0.25
end function

function referenceTwoCancellation(a, b, c, d)
  left = a + b
  right = c + d
  difference = left - right
  return difference + 0.25
end function

function referenceWrap(a, b)
  first = a * b
  second = first * 0.5
  return second + 0.25
end function

function referenceNaN(a, b)
  first = a - b
  second = first + 1.0
  return second * 0.5
end function

function referenceProbe(a)
  first = a + 0.0
  second = first - 1.0
  return second * 16777216.0
end function

function referenceSubnormal(a)
  left = a * 0.5
  right = a * 0.25
  sum = left + right
  return sum * 4.0
end function

function referenceOrder(large, small, tail)
  first = large + small
  second = first - large
  return second + tail
end function

function referenceComparisons(a, b, c, d)
  left = a * b
  right = c * d
  return [left == right, left != right, left < right, left <= right, left > right, left >= right]
end function

function referenceCompareRight(a, b, right)
  left = a * b
  return [left == right, left != right, left < right, left <= right, left > right, left >= right]
end function

function referenceCompareLeft(left, a, b)
  right = a * b
  return [left == right, left != right, left < right, left <= right, left > right, left >= right]
end function

function referenceNullable(n, right)
  quotient = 3.0 / toFloat(n)
  left = quotient * 0.1
  other = right * 0.2
  return left + other
end function

function referenceNullableComparison(n, right)
  quotient = 3.0 / toFloat(n)
  left = quotient * 0.1
  other = right * 0.2
  return left < other
end function

function treeBalanced(a as float, b as float, c as float, d as float)
  return (a * b) + (c * d)
end function

function treeDeep(a as float, b as float, c as float, d as float)
  return ((a * b) + c) * d
end function

// Seven arithmetic nodes, three levels, and two pending nonleaf right trees.
function treeEight(a as float, b as float, c as float, d as float, e as float, f as float, g as float, h as float)
  return ((a * b) + (c * d)) * ((e * f) + (g * h))
end function

function treeRightNested(a as float, b as float, c as float, d as float)
  return a + (b * (c + d))
end function

// A number fact allows actual ints, which must miss the all-float leaf guards.
function treeNumberCancellation(a as int, b as int, c as int, fractions)
  if fractions then
    a = 0.1
    b = 0.2
    c = 0.4
  end if
  return ((a + b) - c) + 0.25
end function

function treeTwoCancellation(a as int, b as int, c as int, d as int, fractions)
  if fractions then
    a = 0.1
    b = 0.2
    c = 0.3
    d = 0.4
  end if
  return ((a + b) - (c + d)) + 0.25
end function

function treeWrap(a as float, b as float)
  return ((a * b) * 0.5) + 0.25
end function

function treeNaN(a as float, b as float)
  return ((a - b) + 1.0) * 0.5
end function

function treeProbe(a as float)
  return ((a + 0.0) - 1.0) * 16777216.0
end function

function treeSubnormal(a as float)
  return ((a * 0.5) + (a * 0.25)) * 4.0
end function

function treeOrder(large as float, small as float, tail as float)
  return ((large + small) - large) + tail
end function

function treeComparisons(a as float, b as float, c as float, d as float)
  return [a * b == c * d, a * b != c * d, a * b < c * d, a * b <= c * d, a * b > c * d, a * b >= c * d]
end function

// NaN at a comparison leaf must retain the unordered comparison behavior;
// it has not passed through an arithmetic normalizer yet.
function treeCompareRight(a as float, b as float, right as float)
  return [a * b == right, a * b != right, a * b < right, a * b <= right, a * b > right, a * b >= right]
end function

function treeCompareLeft(left as float, a as float, b as float)
  return [left == a * b, left != a * b, left < a * b, left <= a * b, left > a * b, left >= a * b]
end function

function treeCompareLiteral(a as float, b as float)
  return a * b <= 4.0
end function

function treeNullable(n as int, right as float)
  quotient = 3.0 / toFloat(n)
  return (quotient * 0.1) + (right * 0.2)
end function

function treeCaughtNullable(n as int, right as float)
  quotient = 3.0 / toFloat(n)
  return try((quotient * 0.1) + (right * 0.2))
end function

function treeNullableComparison(n as int, right as float)
  quotient = 3.0 / toFloat(n)
  return (quotient * 0.1) < (right * 0.2)
end function

function treeBuiltinConverted(value as int, right as float)
  converted = toFloat(value)
  return (converted * 0.1) + (right * 0.2)
end function

function record(value)
  global effects
  effects = effects * 10 + 1
  return value
end function

function noTreeCall(a as float, b as float, c as float, d as float)
  return (record(a) * b) + (c * d)
end function

function noTreeErrorOrder(n as int, right as float)
  quotient = 3.0 / toFloat(n)
  return (quotient + 0.125) + (record(right) * 0.2)
end function

function noTreeMember(a as float, b as float, c as float, box)
  return (a * b) + (c * box.value)
end function

function noTreeIndex(a as float, b as float, c as float, values)
  return (a * b) + (c * values[0])
end function

function noTreeGlobal(b as float, c as float, d as float)
  global globalTreeValue
  return (globalTreeValue * b) + (c * d)
end function

function noTreeSynchronized(b as float, c as float, d as float)
  global synchronizedTreeValue
  return (synchronizedTreeValue * b) + (c * d)
end function

function noTreeCapture(a as float, b as float, c as float, d as float)
  function change()
    a = a + 0.125
    return a
  end function
  change()
  return (a * b) + (c * d)
end function

function noTreeOptional(a as float, b as float, right as float?)
  return (a * b) + (right * 0.2)
end function

function noTreeIntegerLeaf(a as float, b as float, value as int)
  return (a + b) * value
end function

function noTreeIntegerLiteral(a as float, b as float)
  return (a + b) * 2
end function

function noTreeConstantSubtree(a as float, b as float)
  return (a * b) + (0.1 * 0.2)
end function

function noTreeDivision(a as float, b as float, c as float)
  return (a / b) + (c * 0.2)
end function

// The whole four-level tree is outside the budget. An eligible descendant
// may still use the new path while the outer operation keeps normal emission.
function outsideDepthBudget(a as float, b as float, c as float, d as float, e as float)
  return (((a * b) + c) * d) + e
end function

function main(args)
  global failures, effects
  same(treeBalanced(0.1, 0.2, 0.3, 0.4), referenceBalanced(0.1, 0.2, 0.3, 0.4), "both child boxes")
  same(treeDeep(0.1, 0.2, 0.3, 0.4), referenceDeep(0.1, 0.2, 0.3, 0.4), "three arithmetic levels")
  same(treeEight(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8), referenceEight(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8), "seven nodes and two pending right trees")
  same(treeRightNested(0.1, 0.2, 0.3, 0.4), referenceRightNested(0.1, 0.2, 0.3, 0.4), "right nested arithmetic")
  same(treeNumberCancellation(9007199254740992, 1, 9007199254740992, false), 1.25, "exact int grandchild above 2^53")
  same(treeTwoCancellation(9007199254740992, 1, 9007199254740992, 0, false), 1.25, "exact two int grandchildren above 2^53")
  same(treeNumberCancellation(0, 0, 0, true), referenceCancellation(0.1, 0.2, 0.4), "number facts with actual float leaves")
  same(treeTwoCancellation(0, 0, 0, 0, true), referenceTwoCancellation(0.1, 0.2, 0.3, 0.4), "number facts in both float branches")
  same(treeNumberCancellation(1152921504606846975, 1, 1, false), referenceCancellation(1152921504606846975, 1, 1), "int61 positive wrap fallback")
  same(treeNumberCancellation(-1152921504606846976, -1, -1, false), referenceCancellation(-1152921504606846976, -1, -1), "int61 negative wrap fallback")
  wrapped = toFloat(576460752303423488)
  same(treeWrap(wrapped, 2.0), -576460752303423488, "float grandchild normalizes through signed61 wrap")
  same(treeWrap(wrapped, 2.0), referenceWrap(wrapped, 2.0), "wrapped grandchild matches materialized reference")
  same(treeDeep(0.5, 2.0, 0.1, 0.2), referenceDeep(0.5, 2.0, 0.1, 0.2), "integral first product uses original expression")
  same(treeBalanced(0.5, 2.0, 0.25, 4.0), 2, "both products normalize to int")
  same(treeProbe(1.0000000596046448), 1, "inexact float32 probe cannot change binary64 value")
  same(treeProbe(1.0000000596046448), referenceProbe(1.0000000596046448), "float32 midpoint probe reference")
  same(treeOrder(toFloat(9007199254740992), 0.25, 0.5), 0.5, "source association retained")
  same(treeOrder(toFloat(9007199254740992), 0.25, 0.5), referenceOrder(toFloat(9007199254740992), 0.25, 0.5), "association matches materialized reference")
  expectError(try(treeBalanced("wrong", 0.2, 0.3, 0.4)), 1308, "entry contract retained")
  expectError(try(treeNumberCancellation(1.0, 1, 1, false)), 1308, "int entry contract retained")

  for each n in [-1, 0, 1, 2, 3, 7, 10]
    same(try(treeNullable(n, 0.25)), try(referenceNullable(n, 0.25)), "nullable float tree")
    same(try(treeCaughtNullable(n, 0.25)), try(referenceNullable(n, 0.25)), "nullable float tree under try")
    same(try(treeNullableComparison(n, 0.25)), try(referenceNullableComparison(n, 0.25)), "nullable comparison tree")
  end for
  same(treeBuiltinConverted(3, 0.25), referenceBalanced(toFloat(3), 0.1, 0.25, 0.2), "trusted conversion before tree")

  sameComparisons(treeComparisons(0.1, 0.2, 0.3, 0.4), referenceComparisons(0.1, 0.2, 0.3, 0.4), "ordered comparison roots")
  sameComparisons(treeComparisons(0.1, 0.2, 0.1, 0.2), referenceComparisons(0.1, 0.2, 0.1, 0.2), "equal nonintegral comparison roots")
  sameComparisons(treeComparisons(0.5, 2.0, 0.25, 4.0), referenceComparisons(0.5, 2.0, 0.25, 4.0), "integral comparison children use fallback")
  same(treeCompareLiteral(0.1, 0.2), true, "single arithmetic comparison child")
  same(treeCompareLiteral(2.0, 2.0), true, "exact integral comparison child")

  // Valid immediate encodings for both zeros, both infinities, NaN, the
  // smallest binary32 subnormal, and the smallest normal binary32 value.
  for each bits in [0, 2147483648, 2139095040, 4286578688, 2143289344, 1, 8388608]
    special = nativeValueFromRaw((bits << 3) | 5)
    same(treeBalanced(special, 0.5, 0.1, 0.2), referenceBalanced(special, 0.5, 0.1, 0.2), "special left child")
    same(treeRightNested(0.1, 0.2, special, 0.3), referenceRightNested(0.1, 0.2, special, 0.3), "special deep right child")
    sameComparisons(treeCompareRight(0.1, 0.2, special), referenceCompareRight(0.1, 0.2, special), "unordered or special right comparison leaf")
    sameComparisons(treeCompareLeft(special, 0.1, 0.2), referenceCompareLeft(special, 0.1, 0.2), "unordered or special left comparison leaf")
  end for
  infinity = nativeValueFromRaw((2139095040 << 3) | 5)
  negativeInfinity = nativeValueFromRaw((4286578688 << 3) | 5)
  same(treeNaN(infinity, infinity), 0.5, "inner NaN normalizes before remaining arithmetic")
  same(treeNaN(infinity, infinity), referenceNaN(infinity, infinity), "inner NaN reference")
  same(treeBalanced(infinity, 0.5, negativeInfinity, 0.5), 0, "root NaN retains ordinary normalization")
  tiny = nativeValueFromRaw(13)
  same(treeSubnormal(tiny), referenceSubnormal(tiny), "two binary64 subnormal intermediates")
  same(treeSubnormal(tiny), tiny * 3.0, "subnormal intermediates are not rounded to float32")
  small = tiny / 2.0
  same(treeDeep(small, 0.5, small, 0.25), referenceDeep(small, 0.5, small, 0.25), "boxed subnormal leaves and intermediates")

  effects = 0
  same(noTreeCall(0.1, 0.2, 0.3, 0.4), referenceBalanced(0.1, 0.2, 0.3, 0.4), "call leaf stays ordinary")
  same(effects, 1, "call leaf executes once")
  effects = 0
  expectError(try(noTreeErrorOrder(0, 0.25)), 1200, "left failure retained")
  same(effects, 0, "left failure precedes right call")
  same(noTreeErrorOrder(10, 0.25), (3.0 / 10.0 + 0.125) + (0.25 * 0.2), "valid left before right call")
  same(effects, 1, "right call executes once")
  same(noTreeMember(0.1, 0.2, 0.3, TreeBox(0.4)), referenceBalanced(0.1, 0.2, 0.3, 0.4), "member leaf exclusion")
  same(noTreeIndex(0.1, 0.2, 0.3, [0.4]), referenceBalanced(0.1, 0.2, 0.3, 0.4), "index leaf exclusion")
  same(noTreeGlobal(0.2, 0.3, 0.4), referenceBalanced(0.1, 0.2, 0.3, 0.4), "global leaf exclusion")
  same(noTreeSynchronized(0.2, 0.3, 0.4), referenceBalanced(0.1, 0.2, 0.3, 0.4), "synchronized leaf exclusion")
  same(noTreeCapture(0.1, 0.2, 0.3, 0.4), referenceBalanced(0.1 + 0.125, 0.2, 0.3, 0.4), "captured leaf exclusion")
  same(noTreeOptional(0.1, 0.2, 0.25), referenceBalanced(0.1, 0.2, 0.25, 0.2), "optional leaf present")
  same(try(noTreeOptional(0.1, 0.2, void)), try(referenceBalanced(0.1, 0.2, void, 0.2)), "optional leaf void")
  same(noTreeIntegerLeaf(0.1, 0.2, 2), referenceDeep(0.1, 1.0, 0.2, 2), "known integer leaf exclusion")
  same(noTreeIntegerLiteral(0.1, 0.2), referenceDeep(0.1, 1.0, 0.2, 2), "integer literal exclusion")
  same(noTreeConstantSubtree(0.1, 0.2), referenceBalanced(0.1, 0.2, 0.1, 0.2), "constant subtree retained")
  same(noTreeDivision(0.1, 0.2, 0.3), 0.1 / 0.2 + 0.3 * 0.2, "division subtree exclusion")
  same(outsideDepthBudget(0.1, 0.2, 0.3, 0.4, 0.5), referenceDeep(0.1, 0.2, 0.3, 0.4) + 0.5, "outer depth budget preserves eligible descendants")

  // Final boxing must still protect XMM0 at an allocating safepoint. Keep
  // heap-backed input Values and earlier array operands live across it.
  expected = referenceEight(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8)
  right = referenceBalanced(0.1, 0.2, 0.3, 0.4)
  nestedExpected = referenceRightNested(0.1, 0.2, right, 0.4)
  check((nativeRawValue(expected) & 7) == 0, "tree stress result requires a boxed double")
  check((nativeRawValue(right) & 7) == 0, "tree stress input is heap-backed")
  retained = array(8)
  collectionsBefore = gc_stat(0)
  gc_set_limit(1)
  i as int = 0
  while i < 64
    result = treeEight(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8)
    same(result, expected, "tree final boxing survives forced collection")
    retained[i % 8] = [result, right, treeRightNested(0.1, 0.2, right, 0.4)]
    i = i + 1
  end while
  gc_set_limit(0)
  check(gc_stat(0) > collectionsBefore, "tree stress actually collected")
  gc_collect()
  for each values in retained
    same(values[0], expected, "retained tree result survives collection")
    same(values[1], right, "heap-backed input survives final boxing")
    same(values[2], nestedExpected, "outer expression roots survive sibling allocation")
  end for

  if failures != 0 then return 1 end if
  print "NUMERIC FLOAT TREE [OK]"
  return 0
end function
