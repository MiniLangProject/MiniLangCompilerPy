// A cached fresh definition must survive all its consumers without replacing
// the last committed loop state. Untyped helper calls keep the reference
// arithmetic on the ordinary path and preserve its normalization boundaries.
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

// The same local spelling has two different definitions. Consumers of the
// earlier value must not observe the later write, including on the next trip.
function cacheRepeated(n as int, seed as float)
  x = seed
  copy = seed
  i as int = 0
  while i < n
    first = x * 0.75 + 0.012345678901234
    second = first * 0.625 + 0.023456789012345
    first = second * 0.5 + 0.034567890123456
    x = first * 0.375 + second
    copy = second
    i = i + 1
  end while
  return [x, copy, i]
end function

function referenceRepeated(n, seed)
  x = seed
  copy = seed
  i = 0
  while i < n
    first = referenceAdd(referenceMul(x, 0.75), 0.012345678901234)
    second = referenceAdd(referenceMul(first, 0.625), 0.023456789012345)
    first = referenceAdd(referenceMul(second, 0.5), 0.034567890123456)
    x = referenceAdd(referenceMul(first, 0.375), second)
    copy = second
    i = i + 1
  end while
  return [x, copy, i]
end function

// A cached result fans out to three observable homes. All three must receive
// one shared Value, while the second arithmetic result remains independent.
function cacheFanout(n as int, seed as float)
  x = seed
  left = seed
  right = seed
  tail = seed
  old = seed
  i as int = 0
  while i < n
    first = x * 0.8125 + 0.012345678901234
    second = first * 0.3125 + 0.034567890123456
    x = first
    left = first
    right = first
    tail = second
    i = i + 1
  end while
  return [x, left, right, tail, old, i, nativeRawValue(x) == nativeRawValue(left), nativeRawValue(left) == nativeRawValue(right), nativeRawValue(old) == nativeRawValue(seed)]
end function

function referenceFanout(n, seed)
  x = seed
  left = seed
  right = seed
  tail = seed
  old = seed
  i = 0
  while i < n
    first = referenceAdd(referenceMul(x, 0.8125), 0.012345678901234)
    second = referenceAdd(referenceMul(first, 0.3125), 0.034567890123456)
    x = first
    left = first
    right = first
    tail = second
    i = i + 1
  end while
  return [x, left, right, tail, old, i, nativeRawValue(x) == nativeRawValue(left), nativeRawValue(left) == nativeRawValue(right), nativeRawValue(old) == nativeRawValue(seed)]
end function

// Earlier cached definitions are tentative when the final arithmetic result
// normalizes to an integer. Reentry must rebuild them from the committed state.
function cacheLate(n as int, x as float, y as float, z as float)
  copy = x
  i as int = 0
  while i < n and x + y <= 20.0
    first = x * 0.875 + 0.012345678901234
    second = first * 0.75 + 0.023456789012345
    x = second * 0.5 + y
    y = first * 0.5 + z
    z = z + 0.25
    copy = second
    i = i + 1
  end while
  return [x, y, z, copy, i]
end function

function referenceLate(n, x, y, z)
  copy = x
  i = 0
  while i < n and referenceAdd(x, y) <= 20.0
    first = referenceAdd(referenceMul(x, 0.875), 0.012345678901234)
    second = referenceAdd(referenceMul(first, 0.75), 0.023456789012345)
    x = referenceAdd(referenceMul(second, 0.5), y)
    y = referenceAdd(referenceMul(first, 0.5), z)
    z = referenceAdd(z, 0.25)
    copy = second
    i = i + 1
  end while
  return [x, y, z, copy, i]
end function

// Right-hand arithmetic needs one saved left operand. The live cached result
// from the first assignment must survive that scratch register in the second.
function cachePressureOne(n as int, x as float, y as float, a as float, b as float)
  i as int = 0
  while i < n
    first = x * a + y * b
    second = first * 0.5 + x * 0.25
    x = second
    y = first
    i = i + 1
  end while
  return [x, y, i]
end function

function referencePressureOne(n, x, y, a, b)
  i = 0
  while i < n
    first = referenceAdd(referenceMul(x, a), referenceMul(y, b))
    second = referenceAdd(referenceMul(first, 0.5), referenceMul(x, 0.25))
    x = second
    y = first
    i = i + 1
  end while
  return [x, y, i]
end function

// The body needs no saved-left register, but the escape predicate does.
function cacheConditionOne(n as int, x as float, y as float, limit as float)
  i as int = 0
  while i < n and x <= y * limit
    first = x * 0.5 + 0.012345678901234
    second = first * 0.5 + 0.023456789012345
    x = first
    y = second
    i = i + 1
  end while
  return [x, y, i]
end function

function referenceConditionOne(n, x, y, limit)
  i = 0
  while i < n and x <= referenceMul(y, limit)
    first = referenceAdd(referenceMul(x, 0.5), 0.012345678901234)
    second = referenceAdd(referenceMul(first, 0.5), 0.023456789012345)
    x = first
    y = second
    i = i + 1
  end while
  return [x, y, i]
end function

// All eight state slots and both saved-left registers are live. This shape
// must retain the uncached path, including each intermediate normalizer.
function cachePressureTwo(n as int, x as float, a as float, b as float, c as float, d as float, e as float, f as float, g as float)
  i as int = 0
  while i < n
    x = (x * a + b * c) * (d * e + f * g)
    i = i + 1
  end while
  return [x, i]
end function

function referencePressureTwo(n, x, a, b, c, d, e, f, g)
  i = 0
  while i < n
    x = referenceMul(referenceAdd(referenceMul(x, a), referenceMul(b, c)), referenceAdd(referenceMul(d, e), referenceMul(f, g)))
    i = i + 1
  end while
  return [x, i]
end function

// Two condition trees jointly need both saved-left registers, even though
// each body assignment would otherwise permit two cached definitions.
function cacheConditionTwo(n as int, x as float, y as float, a as float, b as float, c as float, d as float)
  i as int = 0
  while i < n and (x * a + y * b) <= (x * c + y * d)
    first = x * 0.5 + 0.012345678901234
    second = y * 0.5 + 0.023456789012345
    x = first
    y = second
    i = i + 1
  end while
  return [x, y, i]
end function

function referenceConditionTwo(n, x, y, a, b, c, d)
  i = 0
  while i < n and referenceAdd(referenceMul(x, a), referenceMul(y, b)) <= referenceAdd(referenceMul(x, c), referenceMul(y, d))
    first = referenceAdd(referenceMul(x, 0.5), 0.012345678901234)
    second = referenceAdd(referenceMul(y, 0.5), 0.023456789012345)
    x = first
    y = second
    i = i + 1
  end while
  return [x, y, i]
end function

// Four equally used definitions compete for two slots. Cross-compiler byte
// parity checks deterministic tie handling as well as the resulting values.
function cacheTies(n as int, x as float, y as float, z as float, w as float)
  i as int = 0
  while i < n
    first = x * 0.5 + 0.012345678901234
    second = y * 0.5 + 0.023456789012345
    third = z * 0.5 + 0.034567890123456
    fourth = w * 0.5 + 0.045678901234567
    x = first
    y = second
    z = third
    w = fourth
    i = i + 1
  end while
  return [x, y, z, w, i]
end function

function referenceTies(n, x, y, z, w)
  i = 0
  while i < n
    first = referenceAdd(referenceMul(x, 0.5), 0.012345678901234)
    second = referenceAdd(referenceMul(y, 0.5), 0.023456789012345)
    third = referenceAdd(referenceMul(z, 0.5), 0.034567890123456)
    fourth = referenceAdd(referenceMul(w, 0.5), 0.045678901234567)
    x = first
    y = second
    z = third
    w = fourth
    i = i + 1
  end while
  return [x, y, z, w, i]
end function

// Integer locals are hot in the outer loop and live across the inner raw
// region. Its volatile float cache must not corrupt their promoted XMM homes.
function cachePromoted(rounds as int, n as int, x as float)
  a as int = 17
  b as int = 23
  c as int = 31
  d as int = 43
  e as int = 59
  f as int = 71
  total as int = 0
  round as int = 0
  while round < rounds
    a = a + 1
    b = b + 2
    c = c + 3
    d = d + 4
    e = e + 5
    f = f + 6
    total = total + a + a + a + b + b + b + c + c + c + d + d + d + e + e + e + f + f + f
    i as int = 0
    while i < n
      first = x * 0.75 + 0.012345678901234
      second = first * 0.5 + 0.023456789012345
      x = second
      i = i + 1
    end while
    total = total + a + a + a + b + b + b + c + c + c + d + d + d + e + e + e + f + f + f
    round = round + 1
  end while
  return [x, a, b, c, d, e, f, total, round]
end function

function referencePromoted(rounds, n, x)
  a = 17
  b = 23
  c = 31
  d = 43
  e = 59
  f = 71
  total = 0
  round = 0
  while round < rounds
    a = a + 1
    b = b + 2
    c = c + 3
    d = d + 4
    e = e + 5
    f = f + 6
    total = total + a + a + a + b + b + b + c + c + c + d + d + d + e + e + e + f + f + f
    i = 0
    while i < n
      first = referenceAdd(referenceMul(x, 0.75), 0.012345678901234)
      second = referenceAdd(referenceMul(first, 0.5), 0.023456789012345)
      x = second
      i = i + 1
    end while
    total = total + a + a + a + b + b + b + c + c + c + d + d + d + e + e + e + f + f + f
    round = round + 1
  end while
  return [x, a, b, c, d, e, f, total, round]
end function

function main(args)
  global failures
  seed = 0.123456789012345
  other = 0.234567890123456
  for each n in [0, 1, 3, 7]
    sameState(cacheRepeated(n, seed), referenceRepeated(n, seed), "repeated definition " + n)
    sameState(cacheFanout(n, seed), referenceFanout(n, seed), "alias fanout " + n)
    sameState(cachePressureOne(n, seed, other, 0.375, 0.625), referencePressureOne(n, seed, other, 0.375, 0.625), "one saved left " + n)
    sameState(cacheConditionOne(n, seed, other, 3.5), referenceConditionOne(n, seed, other, 3.5), "condition saved left " + n)
    sameState(cachePressureTwo(n, seed, 0.234567891, 0.345678912, 0.456789123, 0.567891234, 0.678912345, 0.789123456, 0.891234567), referencePressureTwo(n, seed, 0.234567891, 0.345678912, 0.456789123, 0.567891234, 0.678912345, 0.789123456, 0.891234567), "two saved lefts " + n)
    sameState(cacheConditionTwo(n, seed, other, 0.125, 0.25, 0.5, 0.625), referenceConditionTwo(n, seed, other, 0.125, 0.25, 0.5, 0.625), "two condition saved lefts " + n)
    sameState(cacheTies(n, seed, other, 0.345678901234567, 0.456789012345678), referenceTies(n, seed, other, 0.345678901234567, 0.456789012345678), "tied definitions " + n)
    sameState(cachePromoted(3, n, seed), referencePromoted(3, n, seed), "promoted integers " + n)
  end for
  for each n in [1, 2, 3, 4, 9, 13, 40]
    sameState(cacheLate(n, 0.125, 0.0625, 0.25), referenceLate(n, 0.125, 0.0625, 0.25), "late cached rollback " + n)
  end for
  sameState(cacheLate(1, 0.125, 0.0625, 0.75), referenceLate(1, 0.125, 0.0625, 0.75), "first-iteration cached rollback")
  late = cacheLate(3, 0.125, 0.0625, 0.25)
  same(late[2], 1, "late result normalizes to integer")
  same(late[4], 3, "failed iteration advances exactly once")
  sameState(cacheConditionOne(9, 4.25, other, 3.5), [4.25, other, 0], "false first predicate preserves homes")
  sameState(cacheConditionTwo(9, seed, other, 0.5, 0.625, 0.125, 0.25), [seed, other, 0], "false two-tree predicate preserves homes")
  nan = nativeValueFromRaw((2143289344 << 3) | 5)
  infinity = nativeValueFromRaw((2139095040 << 3) | 5)
  negativeZero = nativeValueFromRaw((2147483648 << 3) | 5)
  tiny = nativeValueFromRaw((1 << 3) | 5)
  for each special in [nan, infinity, negativeZero, tiny]
    sameState(cacheRepeated(3, special), referenceRepeated(3, special), "cached special arithmetic")
    sameState(cacheFanout(0, special), referenceFanout(0, special), "zero trips retain original Value")
  end for

  // Cached output groups must already be committed before boxing can collect.
  expected = referenceFanout(7, seed)
  check((nativeRawValue(expected[0]) & 7) == 0, "fanout result requires a float box")
  check((nativeRawValue(expected[3]) & 7) == 0, "independent result requires a float box")
  retained = array(4)
  before = gc_stat(0)
  gc_set_limit(1)
  repeat as int = 0
  while repeat < 12
    result = cacheFanout(7, seed)
    sameState(result, expected, "cached results during collection")
    retained[repeat % 4] = result
    repeat = repeat + 1
  end while
  gc_set_limit(0)
  check(gc_stat(0) > before, "cache stress actually collected")
  gc_collect()
  for each result in retained
    sameState(result, expected, "cached aliases survive collection")
  end for
  if failures != 0 then return 1 end if
  print "NUMERIC FLOAT CACHE [OK]"
  return 0
end function
