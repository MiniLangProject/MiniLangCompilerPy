/*
   Copyright 2026 Nils Kopal

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

// MiniLang Compiler Test Suite (extended)
// Goal: broad coverage of the implemented language features.
// Note: INPUT() tests are interactive. Toggle RUN_INPUT_TESTS below.

import std.assert as a
import std.core as c
import std.result as r

// ------------------------------------------------------------
// Minimal assert helpers (consistent output format)
// ------------------------------------------------------------
function assertEq(actual, expected, label)
  return a.assertEq(actual, expected, label)
end function

function assertTrue(cond, label)
  return a.assertTrue(cond, label)
end function

function assertFalse(cond, label)
  return a.assertFalse(cond, label)
end function

// ------------------------------------------------------------
// STDLIB SMOKE TESTS
// ------------------------------------------------------------
print "=== STDLIB (SMOKE) ==="

// core helpers
assertTrue(c.isNumber(123), "core: isNumber(int)")
assertTrue(c.isNumber(3.14), "core: isNumber(float)")
assertFalse(c.isNumber("x"), "core: isNumber(string)")
assertEq(c.min(5, 2), 2, "core: min")
assertEq(c.max(5, 2), 5, "core: max")
assertEq(c.clamp(9, 0, 7), 7, "core: clamp hi")
assertEq(c.clamp(-1, 0, 7), 0, "core: clamp lo")
assertEq(c.abs(-8), 8, "core: abs")
assertEq(c.sign(-8), -1, "core: sign -")
assertEq(c.sign(0), 0, "core: sign 0")
assertEq(c.sign(8), 1, "core: sign +")
assertEq(c.safeToNumber("123", -1), 123, "core: safeToNumber ok")
assertEq(c.safeToNumber("xx", -1), -1, "core: safeToNumber fallback")

// result/option
opt = r.Option.Some(42)
assertTrue(opt.isSome(), "option: isSome")
assertFalse(opt.isNone(), "option: isNone")
assertEq(opt.unwrapOr(0), 42, "option: unwrapOr (some)")

none = r.Option.None()
assertFalse(none.isSome(), "option: isSome (none)")
assertTrue(none.isNone(), "option: isNone (none)")
assertEq(none.unwrapOr(7), 7, "option: unwrapOr (none)")

ok = r.Result.Ok("yay")
assertTrue(ok.isOk(), "result: isOk")
assertFalse(ok.isErr(), "result: isErr")
assertEq(ok.unwrapOr("no"), "yay", "result: unwrapOr (ok)")

err = r.Result.Err("bad")
assertFalse(err.isOk(), "result: isOk (err)")
assertTrue(err.isErr(), "result: isErr (err)")
assertEq(err.unwrapOr("no"), "no", "result: unwrapOr (err)")

print "=== STDLIB (SMOKE) DONE ==="

// ------------------------------------------------------------
// Helpers for short-circuit + side effects
// ------------------------------------------------------------
side = 0

function bumpTrue()
  global side
  side = side + 1
  return true
end function

function bumpFalse()
  global side
  side = side + 1
  return false
end function

// ------------------------------------------------------------
// BASIC: literals, int ops, bool ops, precedence
// ------------------------------------------------------------
print "=== BASIC (INT/BOOL) ==="

assertEq(123, 123, "int literal")
assertEq(-5, -5, "negative int literal")
assertEq(true, true, "bool true literal")
assertEq(false, false, "bool false literal")

assertEq(2 + 3, 5, "addition")
assertEq(7 - 3, 4, "subtraction")
assertEq(6 * 7, 42, "multiplication")
assertEq(20 / 4, 5, "division (exact int)")
assertEq(17 % 5, 2, "modulo")

assertEq(-8, -8, "unary minus")
assertEq(not false, true, "unary not")

assertEq(5 > 3, true, "comparison >")
assertEq(5 < 3, false, "comparison <")
assertEq(5 >= 5, true, "comparison >=")
assertEq(5 <= 4, false, "comparison <=")
assertEq(5 == 5, true, "comparison ==")
assertEq(5 != 5, false, "comparison !=")

assertEq(true and true, true, "logical and")
assertEq(true or false, true, "logical or")
assertEq(not(true and false), true, "not with parentheses")

// precedence / associativity
assertEq(1 + 2 * 3, 7, "precedence: mul before add")
assertEq((1 + 2) * 3, 9, "precedence: parentheses")
assertEq(10 - 3 - 2, 5, "associativity: left (sub)")
assertEq(7 / 2, 3.5, "int division produces floa")

// short-circuit: AND
side = 0
assertFalse(false and bumpTrue(), "and short-circuit (rhs not evaluated)")
assertEq(side, 0, "and short-circuit keeps side==0")
side = 0
assertTrue(true and bumpTrue(), "and evaluates rhs when lhs true")
assertEq(side, 1, "and rhs evaluated once")

// short-circuit: OR
side = 0
assertTrue(true or bumpTrue(), "or short-circuit (rhs not evaluated)")
assertEq(side, 0, "or short-circuit keeps side==0")
side = 0
assertTrue(false or bumpTrue(), "or evaluates rhs when lhs false")
assertEq(side, 1, "or rhs evaluated once")

// ------------------------------------------------------------
// STRINGS + ARRAYS
// ------------------------------------------------------------
print "=== STRINGS + ARRAYS ==="

s = "hello"
assertEq(len(s), 5, "len(string)")

arr =[10, 20, 30]
assertEq(len(arr), 3, "len(array)")
assertEq(arr[0], 10, "array index read 0")
assertEq(arr[2], 30, "array index read 2")

arr[1] = 99
assertEq(arr[1], 99, "array index write")

// printing strings/arrays should not crash
print "print string literal"
print s
print "print array"
print arr

// nested arrays
nest =[1,[2, 3],[4,[5]]]
assertEq(len(nest), 3, "nested array len")
assertEq(nest[1][0], 2, "nested array read")

// string equality / inequality
assertTrue("abc" == "abc", "string == same")
assertFalse("abc" == "abd", "string == different")
assertTrue("abc" != "abd", "string != different")

// ------------------------------------------------------------
// STRING INDEX
// ------------------------------------------------------------
print "=== STRING INDEX ==="

assertEq(len(s[0]), 1, "string index len 0")
assertEq(len(s[1]), 1, "string index len 1")
assertEq(len(s[4]), 1, "string index len 4")
assertEq(len(s[-1]), 1, "string index len -1")

print "string index prints"
print s[0]
print s[1]
print s[4]
print s[-1]

print "string index in loop"
idx = 0
acc = ""
while idx < len(s)
  acc = acc + s[idx]
  idx = idx + 1
end while
assertEq(acc, "hello", "string index loop rebuild")

// ------------------------------------------------------------
// FLOAT ARITHMETIC
// ------------------------------------------------------------
print "=== FLOAT ARITHMETIC ==="

assertEq(1.0 + 2, 3.0, "float add mixed")
assertEq(3.5 - 2.5, 1, "float sub normalizes to int")
assertEq(2.0 * 3.0, 6, "float mul normalizes to int")
assertEq(7.0 / 2.0, 3.5, "float div")
assertEq(7.5 % 2.0, 1.5, "float mod")

assertEq(-7 % 3, 2, "mod negative int")
assertEq(-7.5 % 2.0, 0.5, "mod negative float")

print "pi=" + 3.14

// ------------------------------------------------------------
// FLOAT COMPARISONS
// ------------------------------------------------------------
print "=== FLOAT COMPARISONS ==="

assertEq(1.0 < 2.0, true, "float <")
assertEq(2.0 > 1.0, true, "float >")
assertEq(2.0 <= 2.0, true, "float <=")
assertEq(2.0 >= 3.0, false, "float >=")
assertEq(2.0 == 2, true, "float == int")
assertEq(2.0 != 3, true, "float != int")

// ------------------------------------------------------------
// IF / ELSE
// ------------------------------------------------------------
print "=== IF / ELSE ==="

x = 0
if true then
  x = 1
else
  x = 2
end if
assertEq(x, 1, "if/else basic")

x = 0
if false then
  x = 1
else if true then
  x = 2
else
  x = 3
end if
assertEq(x, 2, "else-if branch")

// ------------------------------------------------------------
// ROBUST SYNTAX (statement seps, multiline, inline if, expr continuation)
// ------------------------------------------------------------
print "=== ROBUST SYNTAX ==="

// semicolon statement separator
t = 0; t = t + 1; t = t + 1
assertEq(t, 2, "semicolon statement separators")

// inline if (single stmt)
r = 0
if true then r = 1 end if
assertEq(r, 1, "inline if (then)")

r = 0
if false then r = 1 else r = 2 end if
assertEq(r, 2, "inline if/else")

// inline if with multiple statements using semicolons
a1 = 0
b1 = 0
if true then a1 = 10; b1 = 20 end if
assertEq(a1 + b1, 30, "inline if: multi-stmt via semicolons")

// expression continuation across newlines (binary + unary)
ec = 1 +
2 +
3
assertEq(ec, 6, "expr continuation after binary op")

un = -
5
assertEq(un, -5, "expr continuation after unary -")

nn = not
false
assertEq(nn, true, "expr continuation after unary not")

// multiline array literal + trailing comma
marr =[
1, 2, 3,
4, 5, 6,
]
assertEq(len(marr), 6, "multiline array + trailing comma")
assertEq(marr[0], 1, "multiline array index 0")
assertEq(marr[5], 6, "multiline array index 5")

// multiline indexing
assertEq(marr[
3
], 4, "multiline indexing")

// multiline function params + multiline call args + trailing commas
function w3(
  a,
  b,
  c,
)
  return a * 100 + b * 10 + c
end function

assertEq(w3(
9,
8,
7,
), 987, "multiline params + multiline args + trailing commas")

// trailing comma in global decl list (inside function)
gA = 0
gB = 0
function setGlobalsBoth()
  global gA, gB,
  gA = 5
  gB = 6
end function
setGlobalsBoth()
assertEq(gA * 10 + gB, 56, "global decl trailing comma")

// ------------------------------------------------------------
// WHILE + DO-WHILE
// ------------------------------------------------------------
print "=== WHILE ==="

sum = 0
i = 0
while i < 5
  sum = sum + i
  i = i + 1
end while
assertEq(sum, 10, "while sum 0..4")
assertEq(i, 5, "while end value")

print "=== DO-WHILE ==="

n = 0
loop
  n = n + 1
end loop while false
assertEq(n, 1, "do-while runs once even if cond false")

n = 0
loop
  n = n + 1
end loop while n < 3
assertEq(n, 3, "do-while increments until 3")

// do-while continue
n = 0
sum = 0
loop
  n = n + 1
  if n == 2 then
    continue
  end if
  sum = sum + n
end loop while n < 3
assertEq(sum, 4, "do-while continue sum (skip 2)")

// do-while break
n = 0
loop
  n = n + 1
  if n == 2 then
    break
  end if
end loop while true
assertEq(n, 2, "do-while break")

// ------------------------------------------------------------
// FOR
// ------------------------------------------------------------
print "=== FOR ==="

sum = 0
for i = 1 to 5
  sum = sum + i
end for
assertEq(sum, 15, "for ascending 1..5")

sum = 0
for i = 5 to 1
  sum = sum + i
end for
assertEq(sum, 15, "for descending 5..1 (start > end)")

// continue in for
sum = 0
for i = 1 to 6
  if i % 2 == 0 then
    continue
  end if
  sum = sum + i
end for
assertEq(sum, 9, "for continue skips evens (1+3+5)")

// break in for
sum = 0
for i = 1 to 10
  if i == 4 then
    break
  end if
  sum = sum + 1
end for
assertEq(sum, 3, "for break stops at 4")

// ------------------------------------------------------------
// FOR EACH (ARRAY / STRING)
// ------------------------------------------------------------
print "=== FOR EACH (ARRAY) ==="

sum = 0
for each v in[1, 2, 3, 4]
  sum = sum + v
end for
assertEq(sum, 10, "for each sum")

print "=== FOR EACH (STRING) ==="

cnt = 0
for each ch in "hello"
  cnt = cnt + 1
end for
assertEq(cnt, 5, "for each string counts chars")

ok = true
for each ch in "hello"
  if len(ch) != 1 then
    ok = false
  end if
end for
assertTrue(ok, "for each string each char len==1")

// continue + break
cnt = 0
for each ch in "hello"
  if ch == "e" then
    continue
  end if
  cnt = cnt + 1
  if ch == "l" then
    break
  end if
end for
assertEq(cnt, 2, "for each string continue+break")

// ------------------------------------------------------------
// BREAK / CONTINUE (nested loops + break n)
// ------------------------------------------------------------

// ------------------------------------------------------------
// BYTES
// ------------------------------------------------------------
print "=== BYTES ==="

b = bytes(8)
assertEq(typeof(b), "bytes", "typeof(bytes)")
assertEq(len(b), 8, "len(bytes)")

b[0] = 1
b[1] = 255
b[-1] = 7
assertEq(b[0], 1, "bytes index read/write 0")
assertEq(b[1], 255, "bytes index write 255")
assertEq(b[7], 7, "bytes negative index write/read")

bf = bytes(4, 17)
assertEq(bf[0], 17, "bytes fill")
sumB = 0
for each x in bf
  sumB = sumB + x
end for
assertEq(sumB, 68, "foreach(bytes) yields ints")

b2 = bytes(2, 3)
b3 = bf + b2
assertEq(len(b3), 6, "bytes concat len")
assertEq(b3[0], 17, "bytes concat content a")
assertEq(b3[4], 3, "bytes concat content b")

// bytes value equality (content-based)
be1 = bytes(4, 9)
be2 = bytes(4, 9)
assertEq(be1 == be2, true, "bytes == same content")
be2[2] = 10
assertEq(be1 == be2, false, "bytes == different content")
assertEq(be1 != be2, true, "bytes != different content")
be3 = bytes(5, 9)
assertEq(be1 == be3, false, "bytes == different len")
assertEq(be1 == 123, false, "bytes == non-bytes")

// decode(bytes) -> string (native backend)
// ASCII bytes for "ABC"
btxt = bytes(3)
btxt[0] = 65
btxt[1] = 66
btxt[2] = 67
sdec = decode(btxt)
assertEq(sdec, "ABC", "decode(bytes)")
assertEq(decode(btxt, "utf-8"), "ABC", "decode(bytes, utf-8)")
assertEq(typeof(decode(btxt, 1)), "void", "decode(bytes, bad encoding) -> void")
assertEq(typeof(decode(123)), "void", "decode(int) -> void")

// hex(bytes) <-> fromHex(string)
bh = bytes(4)
bh[0] = 0
bh[1] = 17
bh[2] = 170
bh[3] = 255
hs = hex(bh)
assertEq(hs, "0011aaff", "hex(bytes)")

bx = fromHex("00 11 aa ff")
assertEq(len(bx), 4, "fromHex len")
assertEq(bx[0], 0, "fromHex content 0")
assertEq(bx[1], 17, "fromHex content 1")
assertEq(bx[2], 170, "fromHex content 2")
assertEq(bx[3], 255, "fromHex content 3")
assertEq(hex(fromHex("0x0011AAff")), "0011aaff", "fromHex 0x prefix + case")
assertEq(typeof(fromHex("0x001")), "void", "fromHex odd digits -> void")
assertEq(typeof(fromHex("zz")), "void", "fromHex invalid -> void")
assertEq(typeof(hex(123)), "void", "hex(int) -> void")

// slice(bytes, off, len) -> bytes
bs = bytes(10)
i = 0
while i < 10
  bs[i] = i
  i = i + 1
end while

s1 = slice(bs, 2, 4)
assertEq(typeof(s1), "bytes", "slice typeof")
assertEq(len(s1), 4, "slice len")
assertEq(s1[0], 2, "slice content 0")
assertEq(s1[3], 5, "slice content 3")

s2 = slice(bs, -3, 2)
assertEq(len(s2), 2, "slice negative off len")
assertEq(s2[0], 7, "slice negative off content 0")
assertEq(s2[1], 8, "slice negative off content 1")

s0 = slice(bs, 5, 0)
assertEq(len(s0), 0, "slice zero len")

assertEq(typeof(slice(bs, 9, 2)), "void", "slice OOB -> void")
assertEq(typeof(slice(bs, 0, -1)), "void", "slice neg len -> void")
assertEq(typeof(slice(123, 0, 1)), "void", "slice bad type -> void")

bad = bf + "a"
assertEq(typeof(bad), "void", "bytes + string -> void")

print "=== BREAK / CONTINUE ==="

sum = 0
i = 0
while i < 10
  i = i + 1
  if i % 2 == 0 then
    continue
  end if
  sum = sum + i
end while
assertEq(sum, 25, "continue skips evens")

outer = 0
inner = 0
while outer < 3
  outer = outer + 1
  inner = 0
  while inner < 3
    inner = inner + 1
    if outer == 2 and inner == 2 then
      break 2
    end if
  end while
end while
assertEq(outer, 2, "break 2 breaks two loops (outer)")
assertEq(inner, 2, "break 2 breaks two loops (inner)")

// ------------------------------------------------------------
// FUNCTIONS
// ------------------------------------------------------------
print "=== FUNCTIONS ==="

function add(a, b)
  return a + b
end function
assertEq(add(2, 3), 5, "function call add")

function add4(a, b, c, d)
  return a + b + c + d
end function
assertEq(add4(1, 2, 3, 4), 10, "function call 4 args")

// function values (first-class + indirect calls)
f = add
assertEq(f(2, 3), 5, "function value call via var")

fs =[add, add4]
assertEq(fs[0](2, 3), 5, "function value call via array index")

function sub2(a, b)
  return a - b
end function

function chooseOp(flag)
  if flag then
    return add
  else
    return sub2
  end if
end function

assertEq(chooseOp(true)(10, 3), 13, "function value return + call (add)")
assertEq(chooseOp(false)(10, 3), 7, "function value return + call (sub2)")

function fact(n)
  if n <= 1 then
    return 1
  else
    return n * fact(n - 1)
  end if
end function
assertEq(fact(5), 120, "recursion factorial")

// early return path
function abs(x)
  if x < 0 then
    return - x
  end if
  return x
end function
assertEq(abs(-7), 7, "function early return (neg)")
assertEq(abs(7), 7, "function early return (pos)")

// return string / array
function greet(name)
  return "hi " + name
end function
assertEq(greet("bob"), "hi bob", "function returns string")

function mkPair(x)
  return [x, x + 1]
end function
p = mkPair(41)
assertEq(len(p), 2, "function returns array len")
assertEq(p[0], 41, "function returns array elem0")
assertEq(p[1], 42, "function returns array elem1")

// mutual recursion
function isEven(n)
  if n == 0 then
    return true
  end if
  return isOdd(n - 1)
end function
function isOdd(n)
  if n == 0 then
    return false
  end if
  return isEven(n - 1)
end function
assertTrue(isEven(10), "mutual recursion even(10)")
assertFalse(isEven(9), "mutual recursion even(9)")

// implicit void return (no explicit return)
function doNothing(x)
  y = x + 1
end function
v = doNothing(1)
assertEq(v, v, "function implicit void return self-eq")

// ------------------------------------------------------------
// CLOSURES / NESTED FUNCTIONS
// ------------------------------------------------------------
print "=== CLOSURES ==="

// capture read + mutation before returning closure
function makeReader()
  x = 10
  function inner()
    return x
  end function
  x = 20
  return inner
end function

rd = makeReader()
assertEq(rd(), 20, "closure captures outer local (read after mutate)")

// capture write (counter)
function makeCounter()
  i = 0
  function inc()
    i = i + 1
    return i
  end function
  return inc
end function

c = makeCounter()
assertEq(c(), 1, "closure write 1")
assertEq(c(), 2, "closure write 2")
assertEq(c(), 3, "closure write 3")

// capture parameter
function makeAdder(a)
  function addb(b)
    return a + b
  end function
  return addb
end function

add10 = makeAdder(10)
assertEq(add10(7), 17, "closure captures parameter")

// multi-level capture (grandparent)
function makeGrand()
  x = 5
  function makeParent()
    function child()
      return x
    end function
    return child
  end function
  return makeParent()
end function

g = makeGrand()
assertEq(g(), 5, "closure captures from grandparent")

// two closures share the same boxed slot
function makeIncDec()
  x = 0
  function inc()
    x = x + 1
    return x
  end function
  function dec()
    x = x - 1
    return x
  end function
  return [inc, dec]
end function

pair = makeIncDec()
incf = pair[0]
decf = pair[1]
assertEq(incf(), 1, "shared capture inc 1")
assertEq(incf(), 2, "shared capture inc 2")
assertEq(decf(), 1, "shared capture dec back to 1")

// assignment to unknown name inside nested function should create a local (no outer write)
function makeLocalWriteTest()
  x = 1
  function inner()
    y = 5
    return y
  end function
  return [inner(), x]
end function

t = makeLocalWriteTest()
assertEq(t[0], 5, "nested assigns new local")
assertEq(t[1], 1, "nested local assign does not touch outer")

// shadowing: nested function should be able to create a local that shadows an outer name
// if the first reference to that name is a write (no read-before-write).
function makeShadowLocal()
  x = 10
  function inner()
    x = 99
    return x
  end function
  y = inner()
  return [x, y]
end function

r = makeShadowLocal()
assertEq(r[0], 10, "closure shadow local keeps outer")
assertEq(r[1], 99, "closure shadow local returns inner")

// parameter shadowing must win over captures
function makeShadowParam()
  x = 10
  function inner(x)
    x = x + 1
    return x
  end function
  y = inner(5)
  return [x, y]
end function

p = makeShadowParam()
assertEq(p[0], 10, "closure param shadow keeps outer")
assertEq(p[1], 6, "closure param shadow uses param")

// multi-level: intermediate local shadows grandparent; child captures the intermediate
function makeMidShadow()
  x = 1
  function mid()
    x = 2
    function child()
      return x
    end function
    return child
  end function
  f = mid()
  return [x, f()]
end function

m = makeMidShadow()
assertEq(m[0], 1, "mid shadow keeps outer")
assertEq(m[1], 2, "mid shadow captured by child")

// ------------------------------------------------------------
// toNumber()
// ------------------------------------------------------------
print "=== toNumber() ==="

assertEq(toNumber("123"), 123, "toNumber int from string")
assertEq(toNumber("-7"), -7, "toNumber negative int")
assertEq(toNumber("3.5"), 3.5, "toNumber float")
assertEq(toNumber("3.0"), 3, "toNumber float normalizes to int")
assertEq(toNumber(9), 9, "toNumber int passthrough")
assertEq(toNumber(2.5), 2.5, "toNumber float passthrough")

// ------------------------------------------------------------
// STRING CONCAT (+)
// ------------------------------------------------------------
print "=== STRING CONCAT (+) ==="

t = "x=" + 42
print t
assertEq(len(t), 4, "concat string+int len")

u = "hi" + "!"
print u
assertEq(len(u), 3, "concat string+string len")

vv = "ok?" + true
print vv
assertEq(len(vv), 7, "concat string+bool len")

w = "f=" + 1.25
print w
assertTrue(len(w) >= 4, "concat string+float len>=4")

// ------------------------------------------------------------
// ARRAY CONCAT (+)
// ------------------------------------------------------------
print "=== ARRAY CONCAT (+) ==="

a1 =[1, 2, 3] +[4, 5]
print a1
assertEq(len(a1), 5, "array concat len")
assertEq(a1[0], 1, "array concat first")
assertEq(a1[1], 2, "array concat second")
assertEq(a1[2], 3, "array concat third")
assertEq(a1[4], 5, "array concat last")

// ------------------------------------------------------------
// VALUE EQUALITY (ARRAYS): deep equality
// ------------------------------------------------------------
print "=== VALUE EQUALITY (ARRAYS) ==="

assertTrue([1, 2] ==[1, 2], "array == same")
assertTrue([1, 2] !=[1, 2, 3], "array != different len")
assertTrue([1, 2] !=[2, 1], "array != different order")

assertTrue([[1, 2],[3]] ==[[1, 2],[3]], "nested array == same")
assertTrue([[1, 2],[3]] !=[[1, 2],[4]], "nested array != different")

assertTrue(["a", "b"] ==["a", "b"], "array of strings == same")
assertTrue(["a", "b"] !=["a", "c"], "array of strings != different")

assertTrue([1.0, 2.5] ==[1, 2.5], "array float/int normalize equality")
assertTrue([true, false] ==[true, false], "array of bools == same")

// ------------------------------------------------------------
// INPUT(): interactive (optional)
// ------------------------------------------------------------
RUN_INPUT_TESTS = false
if RUN_INPUT_TESTS then
  print "=== INPUT() ==="
  print "(Type two lines and press Enter. Or: out.exe < file.txt)"
  print "> hello"
  a = input()
  print "you typed"
  print a
  print "len"
  print len(a)

  print "world"
  b = input("second line\n")
  print "second line"
  print b
  print "len"
  print len(b)
end if

// ------------------------------------------------------------
// SWITCH / CASE
// ------------------------------------------------------------
print "=== SWITCH / CASE ==="

x = 3
hit = 0
switch x
  case 1
    hit = 1
    break
  end case

  case 2, 3
    hit = 2
    break
  end case

  case 4 to 10
    hit = 3
    break
  end case

  case default
    hit = 9
    break
  end case
end switch
assertEq(hit, 2, "switch list hit (2,3)")

x = 7
hit = 0
switch x
  case 1
    hit = 1
    break
  end case

  case 2, 3
    hit = 2
    break
  end case

  case 4 to 10
    hit = 3
    break
  end case

  case default
    hit = 9
    break
  end case
end switch
assertEq(hit, 3, "switch range hit (4 to 10)")

x = 99
hit = 0
switch x
  case 1
    hit = 1
    break
  end case

  case default
    hit = 9
    break
  end case
end switch
assertEq(hit, 9, "switch default hit")

// switch inside loop + break 2
i = 0
hit = 0
while i < 5
  i = i + 1
  switch i
    case 3
      hit = 42
      break 2
    end case

    case default
      hit = hit
      break
    end case
  end switch
end while
assertEq(hit, 42, "switch break 2 breaks loop")

// additional robustness: trailing comma + multiline case values
x = 2
hit = 0
switch x
  case 1, 2,
    hit = 11
    break
  end case

  case default
    hit = 99
    break
  end case
end switch
assertEq(hit, 11, "switch: trailing comma before body")

x = 6
hit = 0
switch x
  case 1, 2, 3,
    4, 5, 6
    hit = 22
    break
  end case

  case 7,
    hit = 33
    break
  end case

  case default
    hit = 99
    break
  end case
end switch
assertEq(hit, 22, "switch: multiline case values")

x = 7
hit = 0
switch x
  case 7,
    hit = 33
    break
  end case

  case default
    hit = 99
    break
  end case
end switch
assertEq(hit, 33, "switch: single value trailing comma")

print "=== ENUMS ==="

// basic enum
enum Color are
  Red
  Green
  Blue
end enum

assertEq(typeof(Color.Red), "enum", "typeof enum")
assertTrue(Color.Red == Color.Red, "enum == same")
assertTrue(Color.Red != Color.Green, "enum != different")
assertFalse(Color.Red == 1, "enum != int")
assertEq("" + Color.Blue, "Color.Blue", "enum to string")

arrE =[Color.Red, Color.Green]
assertTrue(arrE[0] == Color.Red, "enum in array index compare")

x = Color.Green
hit = 0
switch x
  case Color.Red
    hit = 1
    break
  end case

  case Color.Green
    hit = 2
    break
  end case

  case default
    hit = 9
    break
  end case
end switch
assertEq(hit, 2, "switch enum match")

// namespaced enum (qualified name formatting)
namespace geom
  enum Dir are
    N
    S
  end enum
end namespace

assertEq(typeof(geom.Dir.N), "enum", "typeof namespaced enum")
assertEq("" + geom.Dir.N, "geom.Dir.N", "namespaced enum to string")

// ------------------------------------------------------------
// CONST + VALUE-ENUMS + NAMESPACE GLOBALS
// ------------------------------------------------------------
print "=== CONST + VALUE ENUMS ==="

// top-level const (constexpr)
const topAnswer = 40 + 2
assertEq(topAnswer, 42, "const: top-level constexpr")

// const + globals in namespaces (incl. nested)
namespace nsc
  const c = 5
  v = 6

  namespace inner
    const k = 9
    w = 10
  end namespace

  // In a function: plain assignment to a global name is LOCAL by default.
  function localAssignDoesNotTouchGlobal()
    v = 99
    return v
  end function

  // Explicit global write via `global`
  function bump()
    global v
    v = v + 1
  end function
end namespace

assertEq(nsc.c, 5, "const: in namespace")
assertEq(nsc.v, 6, "global: in namespace")

// Qualified global write
nsc.v = nsc.v + 1
assertEq(nsc.v, 7, "global: qualified write ns.v")

assertEq(nsc.inner.k, 9, "const: nested namespace")
assertEq(nsc.inner.w, 10, "global: nested namespace")

assertEq(nsc.localAssignDoesNotTouchGlobal(), 99, "ns fn: local assign")
assertEq(nsc.v, 7, "ns global unchanged by local assign")

nsc.bump()
assertEq(nsc.v, 8, "global keyword resolves to ns global")

// value-enum: explicit numeric values
enum Flags are
  Read = 0x01
  Write = 0x02
  All = 0x03
end enum

assertEq(Flags.Read, 1, "value enum: numeric member")
assertEq(Flags.All, 3, "value enum: numeric member 3")

// value-enum: auto-fill (0,1,...) and auto after explicit int
enum Auto are
  A
  B
  C = 10
  D
end enum

assertEq(Auto.A, 0, "value enum: auto start 0")
assertEq(Auto.B, 1, "value enum: auto +1")
assertEq(Auto.C, 10, "value enum: explicit 10")
assertEq(Auto.D, 11, "value enum: auto after explicit 10")

// value-enum: mixed types (int + string)
enum Mixed are
  X = 0x01
  Y = 0x12
  Z = "hallo welt"
end enum

assertEq(Mixed.X, 1, "value enum: mixed X")
assertEq(Mixed.Y, 18, "value enum: mixed Y")
assertEq(Mixed.Z, "hallo welt", "value enum: mixed Z string")

print "=== FUNCTIONS >4 PARAMS/ARGS ==="

function weigh6(a, b, c, d, e, f)
  return a * 100000 + b * 10000 + c * 1000 + d * 100 + e * 10 + f
end function
assertEq(weigh6(6, 5, 4, 3, 2, 1), 654321, "weigh6 order + stack args")

function weigh10(a, b, c, d, e, f, g, h, i, j)
  return a * 1000000000 + b * 100000000 + c * 10000000 + d * 1000000 + e * 100000 + f * 10000 + g * 1000 + h * 100 + i * 10 + j
end function
assertEq(weigh10(9, 8, 7, 6, 5, 4, 3, 2, 1, 0), 9876543210, "weigh10 order + stack args")

function forward10(x)
  return weigh10(x, x -1, x -2, x -3, x -4, x -5, x -6, x -7, x -8, x -9)
end function
assertEq(forward10(9), 9876543210, "forward10 nested call")

// ------------------------------------------------------------
// typeof()
// ------------------------------------------------------------
print "=== typeof() ==="

a = 123
assertEq(typeof(a), "int", "typeof int")

b = true
assertEq(typeof(b), "bool", "typeof bool")

s = "hi"
assertEq(typeof(s), "string", "typeof string")

arr =[1, 2, 3]
assertEq(typeof(arr), "array", "typeof array")

f = 1.25
assertEq(typeof(f), "float", "typeof float")

// void value (implicit void return)
function tf_doNothing(x)
  y = x + 1
end function
v = tf_doNothing(1)
assertEq(typeof(v), "void", "typeof void")

// function value
function tf_add(x, y)
  return x + y
end function

assertEq(typeof(tf_add), "function", "typeof function value")
assertEq(typeof(tf_add(1, 2)), "int", "typeof function result")

// namespaced function value (compile-time namespace lookup)
namespace nsfun
  function inc(x)
    return x + 1
  end function
end namespace

assertEq(typeof(nsfun.inc), "function", "typeof namespaced function value")
f_ns = nsfun.inc
assertEq(typeof(f_ns), "function", "assign namespaced function value")
assertTrue(f_ns == nsfun.inc, "namespaced function identity")

// ------------------------------------------------------------
// GLOBAL KEYWORD (functions must declare globals explicitly)
// ------------------------------------------------------------
print "=== GLOBAL KEYWORD ==="

gx = 5

function setFunctionLocalGX()
  gex = 42
end function

setFunctionLocalGX()

assertEq(gx, 5, "function local write does not overwrite global variable")

function readGX()
  global gx
  return gx
end function

function setGX(v)
  global gx
  gx = v
end function

assertEq(readGX(), 5, "global read via global decl")
setGX(7)
assertEq(gx, 7, "global write via global decl")

// Creating a new global via `global` (no top-level initializer).
function setNewGlobal()
  global gy
  gy = 123
end function

function getNewGlobal()
  // No `global` needed for reading; this must compile even if the
  // global was introduced by another function.
  return gy
end function

setNewGlobal()
assertEq(getNewGlobal(), 123, "global: create new global via global decl")
assertEq(gy, 123, "global: top-level sees created global")
// ------------------------------------------------------------
// STRUCTS
// ------------------------------------------------------------
print "=== STRUCTS ==="

// basic define + construct + member read/write
struct Point are
  x
  y
end struct

p = Point(1, 2)
assertEq(p.x, 1, "struct member read x")
assertEq(p.y, 2, "struct member read y")

// struct constructor as value
ctor = Point
p2 = ctor(3, 4)
assertEq(p2.x, 3, "struct ctor value call x")
assertEq(p2.y, 4, "struct ctor value call y")

p.x = 7
assertEq(p.x, 7, "struct member write x")
p.y = p.x + 3
assertEq(p.y, 10, "struct member write y depends on x")

// struct inside array + member access through index
pts =[Point(10, 20), Point(30, 40)]
assertEq(pts[0].x, 10, "array of struct member read (0)")
assertEq(pts[1].y, 40, "array of struct member read (1)")
pts[1].x = 99
assertEq(pts[1].x, 99, "array of struct member write (index)")

// nested structs
struct Pair are
  a
  b
end struct

pr = Pair(Point(1, 1), Point(2, 2))
assertEq(pr.a.x, 1, "nested struct read pr.a.x")
assertEq(pr.b.y, 2, "nested struct read pr.b.y")
pr.a.y = 5
assertEq(pr.a.y, 5, "nested struct write pr.a.y")

// struct holding array (and mutating through member)
struct Box are
  v
end struct

bx = Box([1, 2, 3])
assertEq(len(bx.v), 3, "struct holds array len")
bx.v[0] = 9
assertEq(bx.v[0], 9, "struct holds array write via member")
assertEq(bx.v[1], 2, "struct holds array keep other elem")

// simple GC stress: allocate many structs, drop ref, collect (should not crash)
i = 0
tmp =[]
while i < 200
  tmp = tmp +[Point(i, i + 1)]
  i = i + 1
end while
tmp = 0
gc_collect()
gc_collect()
assertEq(1, 1, "struct gc_collect does not crash")

// ------------------------------------------------------------
// MEMORY / GC / HEAP (native backend)
// Requires debug builtins added in Step 9:
// heap_bytes_committed()
// heap_bytes_reserved()
// ------------------------------------------------------------
// namespaced struct constructor as value
namespace geom2
  struct Point are
    x
    y
  end struct
end namespace

ctor2 = geom2.Point
p3 = ctor2(5, 6)
assertEq(p3.x, 5, "namespaced struct ctor value call x")
assertEq(p3.y, 6, "namespaced struct ctor value call y")

print "=== MEMORY / GC ==="

// basic invariants (native backend debug builtins)
c0 = heap_bytes_committed()
r0 = heap_bytes_reserved()
u0 = heap_bytes_used()
fb0 = heap_free_bytes()
fc0 = heap_free_blocks()

assertTrue(r0 >= c0, "heap invariant: reserved >= committed")
assertTrue(c0 > 0, "heap invariant: committed > 0")
assertTrue(r0 > 0, "heap invariant: reserved > 0")
assertTrue(u0 >= 0, "heap invariant: used >= 0")
assertTrue(u0 <= c0, "heap invariant: used <= committed")
assertTrue(fb0 >= 0, "heap invariant: free_bytes >= 0")
assertTrue(fc0 >= 0, "heap invariant: free_blocks >= 0")

// Stress allocator + GC without building huge arrays (avoid OOM / quadratic concat).
// We create temporary heap objects, periodically collect, and ensure we never crash.
i = 0
keepOne = 0
while i < 20000
  // strings allocate (concat allocates)
  s = "deadbeef" + i
  t = "cafebabe" +(i * 3)
  // small arrays allocate
  a =[s, t, i]
  // mutate to exercise pointer writes
  a[1] = "x" +(i + 1)

  // occasionally keep a tiny live object to prevent "all dead" edge cases
  if (i % 5000) == 0 then
    keepOne = a
  end if

  // periodic GC to stress root handling
  if (i % 250) == 0 then
    gc_collect()
  end if

  i = i + 1
end while

// Drop the kept reference and collect again.
keepOne = 0
gc_collect()
gc_collect()

c1 = heap_bytes_committed()
r1 = heap_bytes_reserved()
u1 = heap_bytes_used()
fb1 = heap_free_bytes()
fc1 = heap_free_blocks()

assertTrue(r1 >= c1, "heap invariant (after stress): reserved >= committed")
assertTrue(c1 > 0, "heap committed still > 0")
assertTrue(u1 >= 0, "heap invariant (after stress): used >= 0")
assertTrue(u1 <= c1, "heap invariant (after stress): used <= committed")
assertTrue(fb1 >= 0, "heap invariant (after stress): free_bytes >= 0")
assertTrue(fc1 >= 0, "heap invariant (after stress): free_blocks >= 0")

// After GC, we expect *some* free space to exist in the free-list (unless the program is tiny).
// Keep this test soft to avoid false failures due to different heap layouts.
// Note: depending on allocator strategy and heap top-trimming, the free-list may be empty here.
// We treat this as informational rather than a hard failure.
if (fb1 > 0) or(fc1 > 0) then
  print "gc produced at least one free block/byte" + " [OK]"
else
  print "gc produced at least one free block/byte" + " [INFO: free-list empty]"
end if

// ------------------------------------------------------------
// Free-list reuse "proof" test (soft but meaningful)
// Idea: create a lot of garbage with a bounded live set, GC, then allocate again.
// Expectation: second burst should NOT increase committed much (reuse/space),
// and/or free-list counters should become non-zero at some point.
// ------------------------------------------------------------
print "free-list reuse test (burst1 -> GC -> burst2)"

// Record baseline
c_base = heap_bytes_committed()

// Bounded live set (8 slots) to avoid quadratic array concat.
k0 = 0
k1 = 0
k2 = 0
k3 = 0
k4 = 0
k5 = 0
k6 = 0
k7 = 0

i = 0
while i < 12000
  s = "aaaaaaaa" + i
  t = "bbbbbbbb" +(i * 7)
  obj =[s, t, i, i + 1] // fixed-ish size array

  // keep 1/8 objects alive (rotating)
  m = i % 8
  if m == 0 then
    k0 = obj
  end if
  if m == 1 then
    k1 = obj
  end if
  if m == 2 then
    k2 = obj
  end if
  if m == 3 then
    k3 = obj
  end if
  if m == 4 then
    k4 = obj
  end if
  if m == 5 then
    k5 = obj
  end if
  if m == 6 then
    k6 = obj
  end if
  if m == 7 then
    k7 = obj
  end if

  if (i % 400) == 0 then
    gc_collect()
  end if
  i = i + 1
end while

c_peak1 = heap_bytes_committed()
fb_mid = heap_free_bytes()
fc_mid = heap_free_blocks()

// Drop everything and collect
k0 = 0
k1 = 0
k2 = 0
k3 = 0
k4 = 0
k5 = 0
k6 = 0
k7 = 0
gc_collect()
gc_collect()

c_after_gc = heap_bytes_committed()
fb_after = heap_free_bytes()
fc_after = heap_free_blocks()

// Burst 2 (same pattern)
i = 0
while i < 12000
  s = "cccccccc" + i
  t = "dddddddd" +(i * 9)
  obj =[s, t, i, i + 2]
  // keep only a tiny live set
  m = i % 8
  if m == 0 then
    k0 = obj
  end if
  if m == 1 then
    k1 = obj
  end if
  if m == 2 then
    k2 = obj
  end if
  if m == 3 then
    k3 = obj
  end if
  if m == 4 then
    k4 = obj
  end if
  if m == 5 then
    k5 = obj
  end if
  if m == 6 then
    k6 = obj
  end if
  if m == 7 then
    k7 = obj
  end if

  if (i % 400) == 0 then
    gc_collect()
  end if
  i = i + 1
end while
c_peak2 = heap_bytes_committed()

// Clean up
k0 = 0
k1 = 0
k2 = 0
k3 = 0
k4 = 0
k5 = 0
k6 = 0
k7 = 0
gc_collect()

// Assertions (soft thresholds)
// If the heap had to grow in burst1, burst2 should typically not grow much more.
tol = 1048576 // 1 MiB tolerance for alignment/grow-step differences
assertTrue(c_peak2 <=(c_peak1 + tol), "free-list/space reuse: burst2 does not significantly increase committed")

// Additionally, at some point free-list should have been observable, OR committed stayed stable.
// (We don't fail on free-list being 0 because some strategies trim-top aggressively.)
if (fb_mid > 0) or(fc_mid > 0) or(fb_after > 0) or(fc_after > 0) then
  print "free-list observed (bytes/blocks > 0) [OK]"
else
  print "free-list not observed (may be trim-top strategy) [INFO]"
end if

print "gc stress: completed" + " [OK]"

// ------------------------------------------------------------
// OOP / struct methods (instance + static)
// ------------------------------------------------------------

print "=== OOP / STRUCT METHODS ==="

struct Thing
  feld1
  feld2
  function doSomething()
    print this.feld1
  end function
end struct

o = Thing("hello", 123)
o.doSomething()
assertEq(o.feld1, "hello", "oop: field read")
assertEq(o.feld2, 123, "oop: field2 read")

struct Counter
  value
  function inc(delta)
    this.value = this.value + delta
    return this.value
  end function
end struct

c = Counter(10)
assertEq(c.inc(5), 15, "oop: instance method returns")
assertEq(c.value, 15, "oop: instance method updated field")

// dispatch by struct_id (same method name on different structs)
struct A
  x
  function who()
    return 1
  end function
end struct

struct B
  y
  function who()
    return 2
  end function
end struct

aa = A(0)
bb = B(0)
assertEq(aa.who(), 1, "oop: dispatch A.who")
assertEq(bb.who(), 2, "oop: dispatch B.who")

struct Math
  dummy
  static function add(a, b)
  return a + b
end function
end struct

assertEq(Math.add(2, 3), 5, "oop: static method call")

// ------------------------------------------------------------
// ERROR values + try() (Phase 1) + extern mismatch returns error (Phase 2)
// ------------------------------------------------------------

print "=== ERROR + try() ==="

// create + read
err = error(1, "abc")
assertEq(err.code, 1, "error field read code")
assertEq(err.message, "abc", "error field read message")

// write
err.code = 1231
err.message = "es trat ein xyz fehler auf"
assertEq(err.code, 1231, "error field write code")
assertEq(err.message, "es trat ein xyz fehler auf", "error field write message")

// try() catches error values (propagation stopper)
function compute_number_or_error(flag)
  if flag then
    return 7
  end if
  return error(5, "nope")
end function

v = try(compute_number_or_error(false))
assertEq(typeof(v), "error", "try catches error")
assertEq(v.code, 5, "try caught code")
assertEq(v.message, "nope", "try caught message")

// automatic propagation without try()
function wrapper_propagates()
  // if compute_number_or_error returns error, it should immediately return from this function
  tmp = compute_number_or_error(false)
  // should never reach here
  return 99
end function

p = try(wrapper_propagates())
assertEq(typeof(p), "error", "propagation without try (caught at callsite)")
assertEq(p.code, 5, "propagated code")

print "=== INLINE FUNCTIONS ==="

function inline add2(a, b)
  return a + b
end function

assertEq(add2(3, 4), 7, "inline: direct call")

x_inline = 1 + add2(2, 3) * 2
assertEq(x_inline, 11, "inline: expression context")

f_inline = add2
assertEq(f_inline(5, 6), 11, "inline: indirect call still works")

function inline max2(a, b)
  if a > b then
    return a
  end if
  return b
end function

assertEq(max2(3, 4), 4, "inline: multi-stmt if/return")
assertEq(max2(10, -1), 10, "inline: multi-stmt if/return 2")

function inline sumTo(n)
  s = 0
  for i = 1 to n
    s = s + i
  end for
  return s
end function

assertEq(sumTo(10), 55, "inline: for loop + locals")

print "=== EXTERN FUNCTIONS ==="

// Windows externs
extern function GetCurrentProcessId() from "kernel32.dll" returns u32
extern function GetTickCount() from "kernel32.dll" returns u32
extern function SetLastError(code as u32) from "kernel32.dll" returns void
extern function GetLastError() from "kernel32.dll" returns u32
extern function GetFileType(hFile as ptr) from "kernel32.dll" returns u32

// basic extern calls
pid = GetCurrentProcessId()
assertTrue(pid > 0, "extern: GetCurrentProcessId > 0")

// monotonic tick
t1 = GetTickCount()
t2 = GetTickCount()
assertTrue(t2 >= t1, "extern: GetTickCount monotonic")

// u32 masking + last error roundtrip
SetLastError(-1)
le = GetLastError()
assertEq(le, 0xFFFFFFFF, "extern: u32 masking (-1 -> 0xFFFFFFFF)")

// GetFileType invalid handle (INVALID_HANDLE_VALUE = -1)
SetLastError(0)
ft = GetFileType(-1)
assertEq(ft, 0, "extern: GetFileType(invalid handle) -> 0")
assertTrue(GetLastError() != 0, "extern: GetFileType(invalid handle) sets last error")

bad = try(GetFileType(true))
assertEq(typeof(bad), "error", "extern: type mismatch returns error (caught via try)")

// ------------------------------------------------------------
// Regression: namespaced extern calls + import-as alias
// ------------------------------------------------------------

namespace win32
  extern function GetCurrentProcessId() from "kernel32.dll" returns u32
end namespace

pid_ns = win32.GetCurrentProcessId()
assertTrue(pid_ns > 0, "extern: namespaced + call")

import "winapi_extern_smoke.ml" as w
t3 = w.GetTickCount()
print t3
t4 = w.GetTickCount()
print t4
assertTrue(t4 >= t3, "extern: namespaced + import-as alias")

print "=== DONE ==="
