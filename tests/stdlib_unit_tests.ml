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

import std.assert as a
import std.core as c
import std.string as s
import std.string_builder as sb
import std.bytes as b
import std.encoding.hex as hx
import std.encoding.base64 as b64
import std.array as arr
import std.sort as sort
import std.random as rand
import std.math as m
import std.fmt as fmt
import std.time as t
import std.fs as fs
import std.ds.stack as stack
import std.ds.queue as queue
import std.ds.hashmap as hm
import std.ds.set as hset
import std.ds.list as list
import std.net as net

function _assertNotError(v, msg)
  return a.assertTrue(typeof(v) != "error", msg)
end function

ok = true

function chk(v)
  global ok
  if not v then
    ok = false
  end if
end function

function times2(x)
  return x * 2
end function

function isSmall(x)
  // Avoid modulo here to stay compatible with older frontends.
  return x < 3
end function

function add(
  a,
  b,
)
  return a + b
end function

function ret99()
  return 99
end function

function test_core_assert_result()
  chk(a.assertEq(c.min(5, 2), 2, "core: min"))
  chk(a.assertEq(c.max(5, 2), 5, "core: max"))
  chk(a.assertEq(c.clamp(5, 0, 3), 3, "core: clamp hi"))
  chk(a.assertEq(c.clamp(-2, 0, 3), 0, "core: clamp lo"))

  okHex = hx.decode("4142")
  chk(a.assertTrue(typeof(okHex) != "error", "error-system: decode ok"))
  chk(a.assertEq(hx.encode(okHex), "4142", "error-system: decode value"))

  caught = try(error(210, "Invalid hex string"))
  chk(a.assertEq(typeof(caught), "error", "error-system: try returns error"))
  chk(a.assertEq(caught.code, 210, "error-system: code"))
  chk(a.assertEq(caught.message, "Invalid hex string", "error-system: message"))

end function

function test_string_hex_bytes()
  chk(a.assertEq(str(123), "123", "string: str int"))
  chk(a.assertEq(str(true), "true", "string: str bool"))
  chk(a.assertEq(str("abc"), "abc", "string: str string"))
  chk(a.assertEq(s.repeat("ab", 3), "ababab", "string: repeat"))
  chk(a.assertEq(s.substr("hello", 1, 3), "ell", "string: substr"))
  chk(a.assertEq(s.trim("  hi  "), "hi", "string: trim"))
  chk(a.assertTrue(s.startsWith("hello", "he"), "string: startsWith"))
  chk(a.assertTrue(s.endsWith("hello", "lo"), "string: endsWith"))

  parts = s.split("a,b,c", ",")
  chk(a.assertEq(len(parts), 3, "string: split len"))
  chk(a.assertEq(parts[1], "b", "string: split item"))
  chk(a.assertEq(s.join(["a", "b"], "-"), "a-b", "string: join"))
  chk(a.assertEq(s.replaceAll("aaab", "a", "x"), "xxxb", "string: replaceAll"))
  chk(a.assertEq(s.replaceFirst("aaab", "a", "x"), "xaab", "string: replaceFirst"))
  longHay = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxabcdefghijklmno---abcdefghijklmno"
  longNeedle = "abcdefghijklmno"
  chk(a.assertEq(s.indexOf(longHay, longNeedle, 0), 32, "string: indexOf long first"))
  chk(a.assertEq(s.indexOf(longHay, longNeedle, 33), 50, "string: indexOf long next"))
  chk(a.assertEq(s.lastIndexOf(longHay, longNeedle), 50, "string: lastIndexOf long"))
  chk(a.assertTrue(s.contains(longHay, longNeedle), "string: contains"))

  // new string helpers
  chk(a.assertTrue(s.isBlank(" \t\r\n"), "string: isBlank"))
  chk(a.assertEq(s.countOf("banana", "a"), 3, "string: countOf"))
  chk(a.assertEq(s.removeAll("aabbcc", "b"), "aacc", "string: removeAll"))
  chk(a.assertEq(s.reverse("abc"), "cba", "string: reverse"))
  chk(a.assertEq(s.toLowerAscii("HeLLo"), "hello", "string: toLowerAscii"))
  chk(a.assertEq(s.toUpperAscii("HeLLo"), "HELLO", "string: toUpperAscii"))
  chk(a.assertTrue(s.equalsIgnoreCaseAscii("AbC", "aBc"), "string: equalsIgnoreCaseAscii"))

  bb = fromHex("00 11 aa ff")
  chk(a.assertEq(hx.encode(bb), "0011aaff", "hex: encode"))
  chk(a.assertEq(hx.encodeUpper(bb), "0011AAFF", "hex: encodeUpper"))

  bb2 = hx.decode("0011AAFF")
  chk(a.assertEq(hex(bb2), "0011aaff", "hex: decode"))
  chk(a.assertTrue(hx.isValid("00ff"), "hex: isValid true"))
  chk(a.assertFalse(hx.isValid("0xz"), "hex: isValid false"))

  cc = b.concat(fromHex("0011"), fromHex("2233"))
  chk(a.assertEq(hex(cc), "00112233", "bytes: concat"))
  chk(a.assertTrue(b.equals(fromHex("0011"), fromHex("00 11")), "bytes: equals"))
  chk(a.assertTrue(b.ctEquals(fromHex("deadbeef"), fromHex("DE AD BE EF")), "bytes: ctEquals"))
  chk(a.assertFalse(b.ctEquals(fromHex("00"), fromHex("00 00")), "bytes: ctEquals len mismatch"))
  chk(a.assertTrue(b.startsWith(fromHex("00112233"), fromHex("0011")), "bytes: startsWith"))
  chk(a.assertTrue(b.endsWith(fromHex("00112233"), fromHex("2233")), "bytes: endsWith"))
  bh = bytes(longHay)
  bn = bytes(longNeedle)
  chk(a.assertEq(b.indexOf(fromHex("0011221122"), fromHex("1122"), 0), 1, "bytes: indexOf short first"))
  chk(a.assertEq(b.lastIndexOf(fromHex("0011221122"), fromHex("1122")), 3, "bytes: lastIndexOf short last"))
  chk(a.assertEq(b.indexOf(bh, bn, 0), 32, "bytes: indexOf long first"))
  chk(a.assertEq(b.indexOf(bh, bn, 33), 50, "bytes: indexOf long next"))
  chk(a.assertEq(b.compare(fromHex("0011"), fromHex("0011")), 0, "bytes: compare eq"))
  chk(a.assertEq(b.compare(fromHex("0011"), fromHex("0012")), -1, "bytes: compare lt"))
  chk(a.assertEq(b.compare(fromHex("0013"), fromHex("0012")), 1, "bytes: compare gt"))
  fillBuf = bytes(6, 0)
  b.fill(fillBuf, 0xAB)
  chk(a.assertEq(hex(fillBuf), "abababababab", "bytes: fill"))

  // bytes base64 helpers
  b64s = b64.toBase64(bytes("Hello"))
  chk(a.assertEq(b64s, "SGVsbG8=", "bytes: toBase64"))
  b64b = b64.fromBase64("SGVsbG8=")
  chk(a.assertEq(decode(b64b), "Hello", "bytes: fromBase64"))

  // bytes read/write integers
  tmp = bytes(8, 0)
  b.writeU16LE(tmp, 0, 0x1234)
  b.writeU16BE(tmp, 2, 0x1234)
  b.writeU32LE(tmp, 4, 0x89ABCDEF)
  chk(a.assertEq(b.readU16LE(tmp, 0), 0x1234, "bytes: readU16LE"))
  chk(a.assertEq(b.readU16BE(tmp, 2), 0x1234, "bytes: readU16BE"))
  chk(a.assertEq(b.readU32LE(tmp, 4), 0x89ABCDEF, "bytes: readU32LE"))

  // xor helpers
  x1 = fromHex("00 11 22 33")
  x2 = fromHex("FF 00 FF 00")
  x3 = b.xor(x1, x2)
  chk(a.assertEq(hex(x3), "ff11dd33", "bytes: xor"))
  b.xorInPlace(x1, x2)
  chk(a.assertEq(hex(x1), "ff11dd33", "bytes: xorInPlace"))
end function

function test_string_builder()
  bld = sb.StringBuilder.new()
  chk(a.assertEq(bld.len(), 0, "stringBuilder: len initial"))
  bld.appendString("hello")
  bld.appendString(" ")
  bld.append(123)
  chk(a.assertEq(bld.toString(), "hello 123", "stringBuilder: append"))
  bld.appendLine("!")
  chk(a.assertEq(bld.toString(), "hello 123!\n", "stringBuilder: appendLine"))
  bld.clear()
  chk(a.assertEq(bld.len(), 0, "stringBuilder: len clear"))
  chk(a.assertEq(bld.toString(), "", "stringBuilder: clear"))

  bld2 = sb.StringBuilder.withCapacity(2)
  bld2.appendString("ab")
  bld2.appendString("cd")
  bld2.appendString("ef")
  chk(a.assertEq(bld2.toString(), "abcdef", "stringBuilder: growth"))

  bld3 = sb.StringBuilder.new()
  bld3.appendSlice("abcdef", 1, 3)
  chk(a.assertEq(bld3.toString(), "bcd", "stringBuilder: appendSlice"))
end function

function test_array_sort_random()
  xs =[1, 2, 3, 4]
  ys = arr.map(xs, times2)
  chk(a.assertEq(ys[0], 2, "array: map"))

  sm = arr.filter(xs, isSmall)
  chk(a.assertEq(len(sm), 2, "array: filter len"))
  chk(a.assertEq(sm[0], 1, "array: filter item"))

  sum = arr.reduce(xs, add, 0)
  chk(a.assertEq(sum, 10, "array: reduce"))

  // new array helpers
  chk(a.assertEq(arr.length(xs), 4, "array: length"))
  chk(a.assertFalse(arr.isEmpty(xs), "array: isEmpty false"))
  chk(a.assertEq(arr.first(xs), 1, "array: first"))
  chk(a.assertEq(arr.last(xs), 4, "array: last"))
  chk(a.assertEq(arr.append([1, 2], 3)[2], 3, "array: append"))
  chk(a.assertEq(len(arr.concat([1],[2, 3])), 3, "array: concat"))

  sorted = sort.sort([3, 1, 2, 5, 4])
  chk(a.assertEq(sorted[0], 1, "sort: first"))
  chk(a.assertEq(sorted[4], 5, "sort: last"))

  // fast sort variants
  fast = sort.sortFast([9, 7, 8, 6])
  chk(a.assertEq(fast[0], 6, "sortFast: first"))
  chk(a.assertEq(fast[3], 9, "sortFast: last"))

  rng1 = rand.seeded(123)
  rng2 = rand.seeded(123)
  chk(a.assertEq(rng1.nextU32(), rng2.nextU32(), "random: deterministic"))

  // new rng helpers (range + shuffle deterministic)
  r1 = rand.seeded(7)
  v = r1.rangeInt(10, 20)
  chk(a.assertTrue(v >= 10 and v < 20, "random: rangeInt bounds"))

  a1 =[1, 2, 3, 4, 5]
  a2 =[1, 2, 3, 4, 5]
  rA = rand.seeded(9)
  rB = rand.seeded(9)
  rand.shuffleInPlace(rA, a1)
  rand.shuffleInPlace(rB, a2)
  chk(a.assertEq(a1, a2, "random: shuffleInPlace deterministic"))

  c1 = rand.choice(rand.seeded(11),["a", "b", "c"])
  chk(a.assertTrue(c1 == "a" or c1 == "b" or c1 == "c", "random: choice in set"))
end function

function test_math_fmt_time()
  chk(a.assertEq(m.abs(-5), 5, "math: abs int"))
  chk(a.assertEq(m.abs(-3.5), 3.5, "math: abs float"))
  chk(a.assertEq(typeof(1.5), "float", "float: immediate literal type"))
  chk(a.assertEq(1.5 + 2.25, 3.75, "float: immediate add"))
  chk(a.assertTrue(1.5 == 1.5, "float: immediate equality"))
  chk(a.assertEq(toNumber("1.5"), 1.5, "float: parsed immediate value"))
  chk(a.assertEq(typeof(toNumber("1.5")), "float", "float: parsed immediate type"))
  chk(a.assertEq(1.500000000000001, 1.500000000000001, "float: boxed fallback exact value"))
  chk(a.assertEq(typeof(1.500000000000001), "float", "float: boxed fallback type"))
  chk(a.assertEq(typeof(m.floor(2.0)), "float", "math: floor exact float type"))
  chk(a.assertEq(m.floor(2.0), 2.0, "math: floor exact float value"))
  chk(a.assertEq(typeof(m.ceil(2.0)), "float", "math: ceil exact float type"))
  chk(a.assertEq(m.ceil(-2.9), -2, "math: ceil negative"))
  chk(a.assertEq(typeof(m.trunc(2.0)), "int", "math: trunc exact float type"))
  chk(a.assertEq(m.trunc(-2.9), -2, "math: trunc negative"))
  chk(a.assertEq(typeof(m.round(2.0)), "int", "math: round exact float type"))
  chk(a.assertEq(m.round(2.5), 3, "math: round half away +"))
  chk(a.assertEq(m.round(-2.5), -3, "math: round half away -"))
  chk(a.assertEq(m.sign(-7), -1, "math: sign -"))
  chk(a.assertEq(m.sign(0), 0, "math: sign 0"))
  chk(a.assertEq(m.sign(9), 1, "math: sign +"))
  chk(a.assertEq(m.powi(2, 10), 1024, "math: powi"))
  chk(a.assertEq(m.gcd(54, 24), 6, "math: gcd"))
  chk(a.assertEq(m.lcm(6, 8), 24, "math: lcm"))

  // trig/exp/log: approx (pure MiniLang approximations)
  chk(a.assertApprox(m.sin(0.0), 0.0, 0.0001, "math: sin(0)"))
  chk(a.assertApprox(m.cos(0.0), 1.0, 0.0001, "math: cos(0)"))
  chk(a.assertApprox(m.sin(m.pi() / 2.0), 1.0, 0.01, "math: sin(pi/2)"))
  chk(a.assertApprox(m.cos(m.pi()), -1.0, 0.01, "math: cos(pi)"))

  chk(a.assertApprox(m.exp(0.0), 1.0, 0.0005, "math: exp(0)"))
  chk(a.assertApprox(m.ln(m.e()), 1.0, 0.01, "math: ln(e)"))
  chk(a.assertApprox(m.log10(1000.0), 3.0, 0.02, "math: log10"))

  chk(a.assertEq(fmt.padLeft("x", 3, "0"), "00x", "fmt: padLeft"))
  chk(a.assertEq(fmt.padRight("x", 3, "."), "x..", "fmt: padRight"))
  chk(a.assertEq(fmt.center("x", 3, "."), ".x.", "fmt: center"))
  chk(a.assertEq(fmt.quote("a\"b"), "\"a\\\"b\"", "fmt: quote"))
  chk(a.assertEq(fmt.quote("a\\b\n"), "\"a\\\\b\\n\"", "fmt: quote escapes"))
  chk(a.assertEq(fmt.repeat("ab", 3), "ababab", "fmt: repeat"))

  t1 = t.ticks()
  t.sleep(10)
  t2 = t.ticks()
  chk(a.assertTrue(t2 >= t1, "time: ticks monotonic"))
  dt = t.elapsed(t1, t2)
  chk(a.assertEq(typeof(dt), "int", "time: elapsed type"))
  chk(a.assertTrue(dt >= 0, "time: elapsed nonneg"))

  chk(a.assertEq(t.formatDuration(123), "123ms", "time: formatDuration ms"))
  chk(a.assertEq(t.formatDuration(3120), "3s 120ms", "time: formatDuration s"))
  chk(a.assertEq(t.formatDuration(125000), "2m 05s", "time: formatDuration m"))

  // --- calendar (deterministic) ---
  d0 = t.Date(2026, 2, 21)
  chk(a.assertEq(t.date.dayOfWeek(d0), 6, "date: dayOfWeek"))
  d7 = t.date.addDays(d0, 7)
  chk(a.assertEq(t.dateToString(d7), "2026-02-28", "date: addDays +7"))
  chk(a.assertEq(t.date.diffDays(d0, d7), 7, "date: diffDays"))

  tm0 = t.Time(13, 5, 10, 20)
  tm1 = t.clock.addMillis(tm0, 100)
  chk(a.assertEq(t.clockToString(tm1), "13:05:10.120", "time: addMillis"))

  dt0 = t.DateTime(d0, tm0)
  dt1 = t.datetime.addMillis(dt0, 100)
  chk(a.assertEq(t.datetimeToString(dt1), "2026-02-21 13:05:10.120", "datetime: addMillis"))

  dt2 = t.DateTime(d0, t.Time(23, 59, 59, 900))
  dt3 = t.datetime.addMillis(dt2, 200)
  chk(a.assertEq(t.datetimeToString(dt3), "2026-02-22 00:00:00.100", "datetime: carry day"))

  // unix conversion sanity
  epoch = t.DateTime(t.Date(1970, 1, 1), t.Time(0, 0, 0, 0))
  chk(a.assertEq(t.datetime.toUnixMillis(epoch), 0, "datetime: toUnixMillis epoch"))
  back = t.datetime.fromUnixMillis(0)
  chk(a.assertEq(t.datetimeToString(back), "1970-01-01 00:00:00.000", "datetime: fromUnixMillis"))

  // --- wall-clock (non-flaky) ---
  nowL = t.datetime.nowLocal()
  chk(a.assertTrue(t.datetime.isValid(nowL), "datetime: nowLocal valid"))
  nowU = t.datetime.nowUtc()
  chk(a.assertTrue(t.datetime.isValid(nowU), "datetime: nowUtc valid"))
end function

function test_fs_io()
  // Use relative paths; test harness runs in a temp directory.
  p_txt = "ml_stdlib_io_test.txt"
  p_bin = "ml_stdlib_io_test.bin"
  p_copy = "ml_stdlib_io_copy.bin"
  p_move = "ml_stdlib_io_move.bin"

  // text roundtrip
  w = try(fs.writeAllText(p_txt, "hello\nworld\n"))
  chk(_assertNotError(w, "fs: writeAllText ok"))
  chk(a.assertTrue(fs.exists(p_txt), "fs: exists true"))
  rtxt = try(fs.readAllText(p_txt))
  chk(_assertNotError(rtxt, "fs: readAllText ok"))
  chk(a.assertTrue(s.startsWith(rtxt, "hello"), "fs: readAllText content"))

  names = try(fs.listDir("."))
  chk(_assertNotError(names, "fs: listDir ok"))
  chk(a.assertTrue(arr.contains(names, p_txt), "fs: listDir contains txt"))
  chk(a.assertTrue(arr.contains(names, p_bin) == false, "fs: listDir before bin"))

  lines = try(fs.readAllLines(p_txt))
  chk(_assertNotError(lines, "fs: readAllLines ok"))
  chk(a.assertEq(lines[0], "hello", "fs: readAllLines[0]"))
  chk(a.assertEq(lines[1], "world", "fs: readAllLines[1]"))

  // bytes roundtrip
  bb = fromHex("00 11 aa ff")
  wb = try(fs.writeAllBytes(p_bin, bb))
  chk(_assertNotError(wb, "fs: writeAllBytes ok"))
  rb = try(fs.readAllBytes(p_bin))
  chk(_assertNotError(rb, "fs: readAllBytes ok"))
  chk(a.assertEq(hex(rb), "0011aaff", "fs: bytes roundtrip"))

  names2 = try(fs.listDir("."))
  chk(_assertNotError(names2, "fs: listDir after bin"))
  chk(a.assertTrue(arr.contains(names2, p_bin), "fs: listDir contains bin"))

  // file size
  sz = try(fs.fileSize(p_bin))
  chk(_assertNotError(sz, "fs: fileSize ok"))
  chk(a.assertEq(sz, 4, "fs: fileSize value"))

  // copy/move
  cp = try(fs.copyFile(p_bin, p_copy, true))
  chk(_assertNotError(cp, "fs: copyFile ok"))
  chk(a.assertTrue(fs.exists(p_copy), "fs: copy exists"))

  mv = try(fs.moveFile(p_copy, p_move, true))
  chk(_assertNotError(mv, "fs: moveFile ok"))
  chk(a.assertFalse(fs.exists(p_copy), "fs: moved src missing"))
  chk(a.assertTrue(fs.exists(p_move), "fs: moved dst exists"))

  // append helpers
  ap = fs.appendAllText(p_txt, "!!!")
  chk(_assertNotError(ap, "fs: appendAllText ok"))
  r2 = try(fs.readAllText(p_txt))
  chk(_assertNotError(r2, "fs: readAllText after append"))
  chk(a.assertTrue(s.endsWith(r2, "!!!"), "fs: appendAllText content"))

  // cleanup (delete treats already-missing as success)
  chk(a.assertTrue(fs.delete(p_txt), "fs: delete txt"))
  chk(a.assertTrue(fs.delete(p_bin), "fs: delete bin"))
  chk(a.assertTrue(fs.delete(p_move), "fs: delete moved"))
  chk(a.assertFalse(fs.exists(p_txt), "fs: exists false"))
end function

function test_base64_ds()
  hello = bytes("Hello")
  e = b64.toBase64(hello)
  chk(a.assertTrue(typeof(e) == "string", "base64: toBase64 type"))
  chk(a.assertEq(e, "SGVsbG8=", "base64: toBase64"))

  d = b64.fromBase64(e)
  chk(a.assertTrue(typeof(d) == "bytes", "base64: fromBase64 type"))
  chk(a.assertEq(decode(d), "Hello", "base64: roundtrip"))

  // ignore whitespace
  d2 = b64.fromBase64("  SGVsbG8=\n")
  chk(a.assertEq(decode(d2), "Hello", "base64: whitespace ok"))

  inv = b64.fromBase64("!!")
  chk(a.assertTrue(typeof(inv) == "void", "base64: invalid -> void"))

  // ds.stack
  st = stack.Stack.new()
  chk(a.assertTrue(st.isEmpty(), "stack: isEmpty"))
  st.pushAll([1, 2, 3])
  chk(a.assertEq(st.len(), 3, "stack: len"))
  chk(a.assertEq(st.peekOr(0), 3, "stack: peekOr"))
  chk(a.assertEq(st.popOr(0), 3, "stack: popOr"))
  chk(a.assertEq(st.popOr(0), 2, "stack: popOr2"))
  chk(a.assertEq(st.popOr(0), 1, "stack: popOr3"))
  chk(a.assertTrue(st.isEmpty(), "stack: empty after pops"))

  // growth + LIFO under larger load
  for i = 0 to 255
    st.push(i)
  end for
  chk(a.assertEq(st.len(), 256, "stack: len after growth"))
  chk(a.assertEq(st.peekOr(0), 255, "stack: peek after growth"))

  okLifo = true
  i = 255
  while i >= 0
    v = st.pop()
    if v != i then
      okLifo = false
    end if
    i = i - 1
  end while
  chk(a.assertTrue(okLifo, "stack: lifo after growth"))
  chk(a.assertTrue(st.isEmpty(), "stack: empty after growth pops"))

  // fromArray / toArray
  st2 = stack.Stack.fromArray([9, 8, 7])
  chk(a.assertEq(st2.len(), 3, "stack: fromArray len"))
  chk(a.assertEq(st2.popOr(0), 7, "stack: fromArray pop"))
  st2Arr = st2.toArray()
  chk(a.assertEq(len(st2Arr), 2, "stack: toArray len"))
  chk(a.assertEq(st2Arr[0], 9, "stack: toArray[0]"))
  chk(a.assertEq(st2Arr[1], 8, "stack: toArray[1]"))

  // direct constructor compatibility (legacy payload shape)
  legacy = stack.Stack([4, 5])
  legacy.push(6)
  chk(a.assertEq(legacy.popOr(0), 6, "stack: legacy ctor push/pop"))
  chk(a.assertEq(legacy.popOr(0), 5, "stack: legacy ctor pop2"))
  chk(a.assertEq(legacy.popOr(0), 4, "stack: legacy ctor pop3"))
  chk(a.assertTrue(legacy.isEmpty(), "stack: legacy ctor empty"))

  // ds.queue
  q = queue.Queue.new()
  q.enqueue("a")
  q.enqueue("b")
  chk(a.assertEq(q.peek(), "a", "queue: peek"))
  chk(a.assertEq(q.dequeue(), "a", "queue: dequeue"))
  chk(a.assertEq(q.dequeue(), "b", "queue: dequeue2"))
  chk(a.assertTrue(q.isEmpty(), "queue: isEmpty"))

  // ds.hashmap + set
  mp = hm.HashMap.new()
  chk(a.assertTrue(mp.set(1, "x"), "hashmap: set"))
  chk(a.assertTrue(mp.has(1), "hashmap: has"))
  chk(a.assertEq(mp.get(1), "x", "hashmap: get"))
  chk(a.assertTrue(mp.delete(1), "hashmap: delete"))
  chk(a.assertFalse(mp.has(1), "hashmap: has after delete"))
  chk(a.assertTrue(mp.set("alpha", 123), "hashmap: string set"))
  chk(a.assertTrue(mp.has("alpha"), "hashmap: string has"))
  chk(a.assertEq(mp.get("alpha"), 123, "hashmap: string get"))
  chk(a.assertTrue(mp.delete("alpha"), "hashmap: string delete"))
  chk(a.assertFalse(mp.has("alpha"), "hashmap: string has after delete"))

  hs = hset.HashSet.new()
  chk(a.assertTrue(hs.add(10), "set: add"))
  chk(a.assertTrue(hs.has(10), "set: has"))
  chk(a.assertTrue(hs.delete(10), "set: delete"))
  chk(a.assertFalse(hs.has(10), "set: has after delete"))
  chk(a.assertTrue(hs.add("beta"), "set: string add"))
  chk(a.assertTrue(hs.has("beta"), "set: string has"))
  chk(a.assertTrue(hs.delete("beta"), "set: string delete"))
  chk(a.assertFalse(hs.has("beta"), "set: string has after delete"))

  // ds.list
  lst = list.List.new()
  chk(a.assertTrue(lst.isEmpty(), "list: isEmpty"))
  lst.add(1)
  lst.push(2)
  lst.addAll([3, 4])
  chk(a.assertEq(lst.len(), 4, "list: len after addAll"))
  chk(a.assertEq(lst.first(), 1, "list: first"))
  chk(a.assertEq(lst.last(), 4, "list: last"))
  chk(a.assertEq(lst.get(1), 2, "list: get"))
  chk(a.assertTrue(lst.set(1, 20), "list: set ok"))
  chk(a.assertEq(lst.get(1), 20, "list: set value"))
  chk(a.assertTrue(lst.insert(2, 99), "list: insert"))
  chk(a.assertEq(lst.toArray(), [1, 20, 99, 3, 4], "list: toArray after insert"))
  chk(a.assertEq(lst.removeAt(2), 99, "list: removeAt"))
  chk(a.assertEq(lst.popOr(-1), 4, "list: popOr"))
  chk(a.assertEq(lst.toArray(), [1, 20, 3], "list: toArray final"))
  lst.reserve(64)
  chk(a.assertEq(lst.len(), 3, "list: len after reserve"))
  lst.clear()
  chk(a.assertTrue(lst.isEmpty(), "list: clear"))
  lst2 = list.List.fromArray(["a", "b", "c"])
  chk(a.assertEq(lst2.pop(), "c", "list: fromArray pop"))
  chk(a.assertEq(lst2.toArray(), ["a", "b"], "list: fromArray toArray"))
end function

function _tcpListenAny(backlog)
  // Pick a port range that is usually free; try a small number of attempts.
  base = 40000 +(t.ticks() % 20000)
  p = base
  i = 0
  while i < 200
    // std.net now returns either a value or an error(...) value.
    rr = try(net.tcpListen(p, backlog))
    if typeof(rr) != "error" then
      return [rr, p]
    end if
    p = p + 1
    i = i + 1
  end while
  return error(200, "no free TCP port")
end function

function _udpBindAny(sock)
  base = 45000 +(t.ticks() % 15000)
  p = base
  i = 0
  while i < 200
    rr = try(net.udpBind(sock, p))
    if typeof(rr) != "error" then
      return p
    end if
    p = p + 1
    i = i + 1
  end while
  return error(200, "no free UDP port")
end function

function test_net_tcp_udp()
  // TCP roundtrip on localhost
  lp = try(_tcpListenAny(8))
  chk(_assertNotError(lp, "net: tcpListenAny"))
  if typeof(lp) == "error" then
    return
  end if

  srv = lp[0]
  port = lp[1]

  cli = try(net.tcpConnect("127.0.0.1", port))
  chk(_assertNotError(cli, "net: tcpConnect"))
  if typeof(cli) == "error" then
    net.close(srv)
    return
  end if

  ar = try(net.tcpAcceptPeer(srv))
  chk(_assertNotError(ar, "net: tcpAcceptPeer"))
  if typeof(ar) == "error" then
    net.close(cli)
    net.close(srv)
    return
  end if

  acc = ar[0]
  peerIp = ar[1]
  chk(a.assertEq(peerIp, "127.0.0.1", "net: peerIp"))

  msg = "ping"
  sr = try(net.tcpSendAll(cli, msg))
  chk(_assertNotError(sr, "net: tcpSendAll"))
  if typeof(sr) == "error" then
    net.close(cli)
    net.close(acc)
    net.close(srv)
    return
  end if

  rr = try(net.tcpRecv(acc, 16))
  chk(_assertNotError(rr, "net: tcpRecv"))
  if typeof(rr) != "error" then
    chk(a.assertEq(decode(rr), "ping", "net: tcp payload"))
  end if

  sr2 = try(net.tcpSendAll(acc, "pong"))
  chk(_assertNotError(sr2, "net: tcpSendAll reply"))
  if typeof(sr2) == "error" then
    net.close(cli)
    net.close(acc)
    net.close(srv)
    return
  end if

  rr2 = try(net.tcpRecv(cli, 16))
  chk(_assertNotError(rr2, "net: tcpRecv client"))
  if typeof(rr2) != "error" then
    chk(a.assertEq(decode(rr2), "pong", "net: tcp reply"))
  end if

  net.tcpShutdown(cli, 2)
  net.tcpShutdown(acc, 2)
  net.close(cli)
  net.close(acc)
  net.close(srv)

  // UDP datagram
  u1 = try(net.udpOpen())
  u2 = try(net.udpOpen())
  chk(_assertNotError(u1, "net: udpOpen 1"))
  chk(_assertNotError(u2, "net: udpOpen 2"))
  if typeof(u1) == "error" or typeof(u2) == "error" then
    return
  end if

  up = try(_udpBindAny(u2))
  chk(_assertNotError(up, "net: udpBindAny"))
  if typeof(up) == "error" then
    net.close(u1)
    net.close(u2)
    return
  end if

  ur = try(net.udpSendTo(u1, "127.0.0.1", up, "hi"))
  chk(_assertNotError(ur, "net: udpSendTo"))
  if typeof(ur) == "error" then
    net.close(u1)
    net.close(u2)
    net.cleanup()
    return
  end if

  gr = try(net.udpRecvFrom(u2, 16))
  chk(_assertNotError(gr, "net: udpRecvFrom"))
  if typeof(gr) != "error" then
    chk(a.assertEq(decode(gr[0]), "hi", "net: udp payload"))
    chk(a.assertEq(gr[1], "127.0.0.1", "net: udp peerIp"))
  end if

  net.close(u1)
  net.close(u2)
  net.cleanup()
end function

function test_gc_periodic()
  // Ensure periodic GC triggers under allocation pressure.
  before = heap_free_blocks()

  // Small limit so the allocator triggers GC during this test.
  gc_set_limit(64 * 1024)

  i = 0
  while i < 600
    bytes(4096, 0)
    i = i + 1
  end while

  after = heap_free_blocks()
  chk(a.assertTrue(after > before, "gc: periodic GC ran (free_blocks increased)"))
end function

function main(args)
  print "=== STD (UNIT) ==="

  test_core_assert_result()
  test_string_hex_bytes()
  test_string_builder()
  test_array_sort_random()
  test_math_fmt_time()
  test_fs_io()
  test_base64_ds()
  test_net_tcp_udp()

  if ok then
    print "=== DONE ==="
    return 0
  end if

  print "=== STDLIB: FAIL ==="
  return 1
end function
