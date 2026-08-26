/*
Copyright (c) 2026 Nils Kopal
SPDX-License-Identifier: Apache-2.0

Inline expansion uses caller stack slots; body-level float boxing remains observable.
*/

function inlineAllocationAssert(value, message)
  if not value then return error(1780, message) end if
  return true
end function

function inline inlineIntegerAdd(value, amount)
  return value + amount
end function

function inline inlineBoxedFloatStep(value)
  return value * 1.0000000001
end function

function runInlineIntegerLoop(iterations)
  total = 0
  index = 0
  while index < iterations
    total = inlineIntegerAdd(total, 1)
    index = index + 1
  end while
  return total
end function

function runInlineFloatLoop(iterations)
  value = 1.0000000001
  index = 0
  while index < iterations
    value = inlineBoxedFloatStep(value)
    index = index + 1
  end while
  return value
end function

gc_collect()
inlineIntegerHeapBefore = heap_bytes_used()
inlineIntegerResult = runInlineIntegerLoop(200000)
inlineIntegerHeapGrowth = heap_bytes_used() - inlineIntegerHeapBefore
inlineAllocationAssert(inlineIntegerResult == 200000,
  "inline integer result changed")
inlineAllocationAssert(inlineIntegerHeapGrowth == 0,
  "stack-only inline integer helper allocated managed heap")

gc_collect()
inlineFloatHeapBefore = heap_bytes_used()
inlineFloatResult = runInlineFloatLoop(20000)
inlineFloatHeapGrowth = heap_bytes_used() - inlineFloatHeapBefore
inlineAllocationAssert(typeof(inlineFloatResult) == "float",
  "inline float result changed representation")
inlineAllocationAssert(inlineFloatHeapGrowth > 0,
  "non-immediate float results unexpectedly avoided body-level boxing")

print "inline_allocation_contract: PASS integer_heap_growth=" +
  inlineIntegerHeapGrowth + " float_heap_growth=" + inlineFloatHeapGrowth
