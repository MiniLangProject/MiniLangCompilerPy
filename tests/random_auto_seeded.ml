// Automatic PRNG seeding: deterministic provider tests avoid probabilistic
// assertions about distinct samples. Real providers are exercised separately.
import std.assert as t
import std.random as random

providerCalls = 0

function entropyAfterZeros(length)
  global providerCalls
  t.assertEq(length, 4, "request exactly four seed bytes")
  providerCalls = providerCalls + 1
  raw = bytes(4, 0)
  if providerCalls >= 3 then
    raw[0] = 0x78
    raw[1] = 0x56
    raw[2] = 0x34
    raw[3] = 0xF2
  end if
  return raw
end function

function failingEntropy(length)
  global providerCalls
  providerCalls = providerCalls + 1
  return error(240, "injected entropy failure")
end function

function zeroThenFailure(length)
  global providerCalls
  providerCalls = providerCalls + 1
  if providerCalls == 1 then return bytes(4, 0) end if
  return error(240, "failure after zero seed")
end function

function checkPlatformGenerator()
  generated = random.autoSeeded()
  t.assertEq(typeof(generated.state), "int", "integer seed")
  t.assertTrue(generated.state > 0 and generated.state <= 0xFFFFFFFF, "nonzero 32-bit seed")
  expected = random.seeded(generated.state)
  matching = true
  inRange = true
  for i = 0 to 31
    value = generated.nextU32()
    if value != expected.nextU32() then matching = false end if
    if value <= 0 or value > 0xFFFFFFFF then inRange = false end if
  end for
  t.assertTrue(matching, "auto seed uses existing deterministic algorithm")
  t.assertTrue(inRange, "xorshift remains nonzero")
  value = generated.rangeInt(1, 7)
  t.assertTrue(value >= 1 and value < 7, "auto generator integer range")
  real = generated.nextFloat()
  t.assertTrue(real >= 0 and real < 1, "auto generator float range")
  t.assertEq(typeof(generated.nextBool()), "bool", "auto generator boolean")
end function

function worker()
  // Each worker owns its RNG; no shared PRNG state or global seed counter.
  for i = 0 to 7
    checkPlatformGenerator()
  end for
end function

function main(args)
  global providerCalls
  original = random.seeded(123)
  vector = [31682556, 4018661298, 2101636938, 3842487452, 1628673942]
  for i = 0 to len(vector) - 1
    t.assertEq(original.nextU32(), vector[i], "seeded sequence remains unchanged")
  end for
  t.assertEq(random.seeded(0).state, random.DEFAULT_SEED, "explicit zero seed keeps legacy behavior")

  providerCalls = 0
  generated = random._autoSeededFrom(entropyAfterZeros)
  t.assertEq(providerCalls, 3, "zero entropy retries")
  t.assertEq(generated.state, 0xF2345678, "explicit little-endian high-bit seed")
  expected = random.seeded(0xF2345678)
  for i = 0 to 31
    t.assertEq(generated.nextU32(), expected.nextU32(), "injected seed sequence")
  end for

  providerCalls = 0
  failed = try(random._autoSeededFrom(failingEntropy))
  t.assertEq(typeof(failed), "error", "provider error is not a fallback RNG")
  t.assertEq(failed.code, 240, "provider error code preserved")
  t.assertEq(failed.message, "injected entropy failure", "provider error message preserved")
  t.assertEq(providerCalls, 1, "failure does not retry")

  providerCalls = 0
  failed = try(random._autoSeededFrom(zeroThenFailure))
  t.assertEq(typeof(failed), "error", "error after rejected zero propagates")
  t.assertEq(failed.code, 240, "retry failure code preserved")
  t.assertEq(failed.message, "failure after zero seed", "retry failure message preserved")
  t.assertEq(providerCalls, 2, "retry stops on failure")

  checkPlatformGenerator()
  left = random.autoSeeded()
  right = random.autoSeeded()
  rightState = right.state
  left.nextU32()
  t.assertEq(right.state, rightState, "instances have independent mutable state")
  expected = random.seeded(rightState)
  gc_collect()
  t.assertEq(right.nextU32(), expected.nextU32(), "auto RNG survives collection")

  threads = array(4)
  for i = 0 to 3
    threads[i] = Thread(worker)
    t.assertTrue(threads[i].Start(), "start random worker")
  end for
  for i = 0 to 3
    t.assertTrue(threads[i].Join(10000), "join random worker")
    t.assertEq(threads[i].Status(), "Completed", "random worker completed")
  end for
  print "[OK] auto-seeded random"
  return 0
end function
