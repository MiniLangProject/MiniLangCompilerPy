/*
Copyright 2026 Nils Kopal
Licensed under the Apache License, Version 2.0.
*/

// Regression coverage for safe indexing and explicit integer conversions.

import std.assert as t
import std.array as arrays
import std.math as math
import std.string as strings

struct SaveSlot
  id as int
  name as string = "unnamed"
  level as int = 1
end struct

function writeInvalidByte()
  data = bytes(1)
  data[0] = void
end function

function makeBoundsError(index)
  localValues = [1]
  return localValues[index]
end function

values = [41, 42]
values[0] = void
t.assertTrue(values[0] is void, "array slots accept void")
gc_collect()
t.assertTrue(values[0] is void, "stored void survives collection")

t.assertEq(arrays.getOr(values, 9, "missing"), "missing", "array.getOr fallback")
t.assertEq(arrays.getOr(values, -1, 0), 42, "array.getOr negative index")
presentVoid = arrays.getOption(values, 0)
t.assertTrue(presentVoid.isSome(), "array.getOption distinguishes stored void")
t.assertTrue(presentVoid.unwrap() is void, "array.getOption preserves void")
t.assertTrue(arrays.getOption(values, 9).isNone(), "array.getOption missing")
t.assertTrue(arrays.setIfPresent(values, 1, void), "array.setIfPresent writes void")
t.assertTrue(values[1] is void, "array.setIfPresent result")
t.assertFalse(arrays.setIfPresent(values, 9, 1), "array.setIfPresent rejects bounds")

boundsError = try(arrays.getOrError(values, 9))
t.assertEq(typeof(boundsError), "error", "array.getOrError is catchable")
t.assertTrue(strings.contains(boundsError.message, "index 9"), "bounds error contains index")
t.assertTrue(strings.contains(boundsError.message, "length 2"), "bounds error contains length")

byteError = try(writeInvalidByte())
t.assertEq(typeof(byteError), "error", "bytes still reject void")

t.assertEq(math.toIntExact(7.0), 7, "math.toIntExact exact float")
t.assertEq(math.floorInt(3.9), 3, "math.floorInt")
t.assertEq(math.ceilInt(-3.9), -3, "math.ceilInt")
t.assertEq(math.truncInt(-3.9), -3, "math.truncInt")
t.assertEq(math.roundInt(2.5), 3, "math.roundInt")
t.assertEq(7 div 2, 3, "integer div positive")
t.assertEq(-7 div 2, -4, "integer div floors negative")
t.assertEq(7 div -2, -4, "integer div negative divisor")
quarters = [10, 20, 30]
t.assertEq(quarters[8 div 4], 30, "integer div is index-safe")
slot = SaveSlot(9)
t.assertEq(slot.name, "unnamed", "struct positional defaults")
t.assertEq(slot.level, 1, "struct trailing defaults")
namedSlot = SaveSlot(level = 4, id = 10)
t.assertEq(namedSlot.name, "unnamed", "struct named defaults")
t.assertEq(namedSlot.level, 4, "struct named override")
t.assertEq("item=" + 1 + ",next=" + 2 + ",done=" + true, "item=1,next=2,done=true", "iterative string concat chain")
t.assertEq("sum=" + (1 + 2) + "!", "sum=3!", "string concat preserves parentheses")
fractionError = try(math.toIntExact(7.25))
t.assertEq(typeof(fractionError), "error", "math.toIntExact rejects fraction")

originError = try(makeBoundsError(8))
t.assertEq(typeof(originError), "error", "dynamic bounds error is catchable")
t.assertEq(originError.func, "makeBoundsError", "runtime error records function")
t.assertTrue(typeof(originError.script) == "string", "runtime error records source")
t.assertTrue(originError.line > 0, "runtime error records line")

print "SAFE INDEXING AND INTEGER CONVERSIONS [OK]"
