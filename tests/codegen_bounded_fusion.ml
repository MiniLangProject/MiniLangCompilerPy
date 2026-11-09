// Regression: bounded concat fusion and rooted scalar fields preserve semantics.
import std.assert as check

struct TypedLocal
  count as int,
  text as string?,
end struct

effects = ""
globalText = "G"

function touch()
  global effects
  global globalText
  effects = effects + "t"
  globalText = "H"
  return "x"
end function

function concatFour(a, b, c)
  prefix = "p"
  return prefix + a + b + c
end function

function concatEight(a, b, c, d, e, f, g)
  prefix = "p"
  return prefix + a + b + c + d + e + f + g
end function

function concatNine(a, b, c, d, e, f, g, h)
  prefix = "p"
  return prefix + a + b + c + d + e + f + g + h
end function

function sequential(parts)
  value = "p"
  for each part in parts
    value = value + part
  end for
  return value
end function

function withEffects()
  prefix = "p"
  return prefix + globalText + touch() + globalText
end function

function scalarTyped(n, text)
  value = TypedLocal(n, text)
  gc_collect()
  value.count = value.count + 2
  return value.count + len(value.text)
end function

function scalarOptional(n)
  value = TypedLocal(n, void)
  if typeof(value.text) != "void" then return -1 end if
  value.text = "ok"
  gc_collect()
  return value.count + len(value.text)
end function

function invalidScalar(n)
  value = TypedLocal(n, touch())
  return value.count
end function

// Passing the object itself must keep its identity and ordinary heap storage.
function alter(value)
  value.count = value.count + 5
end function

function escaping(n)
  value = TypedLocal(n, "a")
  alias = value
  alter(alias)
  gc_collect()
  return value.count
end function

function sameResult(left, right)
  if typeof(left) != typeof(right) then return false end if
  if typeof(left) == "error" then return left.code == right.code end if
  return left == right
end function

function main(args)
  ok = true
  if not check.assertEq(concatFour("a", "b", "c"), "pabc", "four strings") then ok = false end if
  if not check.assertEq(concatEight("a", "b", "c", "d", "e", "f", "g"), "pabcdefg", "eight strings") then ok = false end if
  if not check.assertEq(concatNine("a", "b", "c", "d", "e", "f", "g", "h"), "pabcdefgh", "bounded fallback") then ok = false end if
  if not check.assertEq(concatEight("a", "", "c", "d", "", "f", "g"), "pacdfg", "empty fallback") then ok = false end if
  if not check.assertEq(concatFour("ä", "界", "🙂"), "pä界🙂", "UTF-8 bytes") then ok = false end if
  for each value in [42, false, void, error(987, "expected")]
    if not check.assertEq(sameResult(try(concatFour("a", value, "c")), try(sequential(["a", value, "c"]))), true, "dynamic fallback") then ok = false end if
  end for
  if not check.assertEq(withEffects(), "pGxH", "effects remain ordered") then ok = false end if
  if not check.assertEq(effects, "t", "effect exactly once") then ok = false end if
  invalid = try(invalidScalar("bad"))
  if not check.assertEq(typeof(invalid), "error", "typed constructor guard") then ok = false end if
  if not check.assertEq(invalid.code, 1308, "typed constructor error") then ok = false end if
  if not check.assertEq(invalid.func, "invalidScalar", "guard function provenance") then ok = false end if
  if not check.assertEq(invalid.line > 0, true, "guard source line") then ok = false end if
  if not check.assertEq(len(invalid.script) > 0, true, "guard source file") then ok = false end if
  if not check.assertEq(effects, "t", "failed guard stops later argument") then ok = false end if
  invalidOptional = try(scalarTyped(1, 7))
  if not check.assertEq(invalidOptional.code, 1308, "optional field rejects other types") then ok = false end if
  if not check.assertEq(scalarOptional(40), 42, "optional scalar root") then ok = false end if
  if not check.assertEq(escaping(37), 42, "escaping object") then ok = false end if
  gc_set_limit(65536)
  for i = 0 to 31
    text = decode(bytes(4093, 65 + (i % 26)))
    joined = concatEight(text, text, text, text, text, text, text)
    if not check.assertEq(len(joined), 1 + 7 * 4093, "concat GC roots") then ok = false end if
    if not check.assertEq(decode(slice(bytes(joined), 1, 4093)), text, "concat contents") then ok = false end if
    if not check.assertEq(scalarTyped(i, text), i + 4095, "typed scalar GC root") then ok = false end if
  end for
  if not ok then return 1 end if
  print "[OK] bounded concat and typed scalar replacement"
  return 0
end function
