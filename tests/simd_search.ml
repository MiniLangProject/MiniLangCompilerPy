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

import std.assert as t
import std.bytes as b
import std.string as s
import std.cpu as cpu

function naiveIndexOf(hay, needle, start)
  n = len(hay)
  m = len(needle)
  if start < 0 then start = 0 end if
  if start > n then start = n end if
  if m == 0 then return start end if
  if m > n or start > n - m then return -1 end if
  for i = start to n - m
    match = true
    for j = 0 to m - 1
      if hay[i + j] != needle[j] then match = false break end if
    end for
    if match then return i end if
  end for
  return -1
end function

function naiveLastIndexOf(hay, needle)
  n = len(hay)
  m = len(needle)
  if m == 0 then return n end if
  if m > n then return -1 end if
  i = n - m
  while i >= 0
    match = true
    for j = 0 to m - 1
      if hay[i + j] != needle[j] then match = false break end if
    end for
    if match then return i end if
    i = i - 1
  end while
  return -1
end function

function boundaryCase(pos, total, label)
  hay = bytes(total, 120)
  needle = bytes("QZ")
  hay[pos] = 81
  hay[pos + 1] = 90
  t.assertEq(b.indexOf(hay, needle, 0), pos, label + " bytes boundary index")
  t.assertEq(b.lastIndexOf(hay, needle), pos, label + " bytes boundary last")
  text = decode(hay)
  t.assertEq(s.indexOf(text, "QZ", 0), pos, label + " string boundary index")
  t.assertEq(s.lastIndexOf(text, "QZ"), pos, label + " string boundary last")
end function

function deterministicDifferential(label)
  hay = bytes(4099, 0)
  seed = 17
  for i = 0 to len(hay) - 1
    seed = (seed * 25173 + 13849) % 65536
    hay[i] = seed % 251
  end for

  for caseNo = 0 to 95
    seed = (seed * 25173 + 13849) % 65536
    m = (seed % 11) + 1
    needle = bytes(m, 0)
    for j = 0 to m - 1
      seed = (seed * 25173 + 13849) % 65536
      needle[j] = seed % 251
    end for
    if caseNo % 3 != 0 then
      pos = (caseNo * 37) % (len(hay) - m)
      for j = 0 to m - 1
        hay[pos + j] = needle[j]
      end for
    end if
    start = (caseNo * 29) % (len(hay) + 40)
    t.assertEq(b.indexOf(hay, needle, start), naiveIndexOf(hay, needle, start), label + " random index " + caseNo)
    t.assertEq(b.lastIndexOf(hay, needle), naiveLastIndexOf(hay, needle), label + " random last " + caseNo)
  end for
end function

function checkCurrentDispatch(label)
  text = "a,b,c"
  t.assertEq(s.indexOf(text, ",", 0), 1, label + " string first")
  t.assertEq(s.indexOf(text, ",", 2), 3, label + " string next")
  t.assertEq(s.indexOf(text, ",", 4), -1, label + " string miss")
  t.assertEq(s.lastIndexOf(text, ","), 3, label + " string last")
  t.assertEq(s.indexOf("aaaaa", "aaa", 0), 0, label + " overlap first")
  t.assertEq(s.lastIndexOf("aaaaa", "aaa"), 2, label + " overlap last")
  t.assertEq(s.indexOf("abc", "", 2), 2, label + " empty string")
  t.assertEq(s.lastIndexOf("abc", ""), 3, label + " empty string last")
  t.assertEq(s.indexOf("abc", "z", 0), -1, label + " string no match")
  t.assertEq(s.startsWith("abcdef", "abc"), true, label + " startsWith")
  t.assertEq(s.endsWith("abcdef", "def"), true, label + " endsWith")

  data = bytes("a,b,c")
  comma = bytes(",")
  t.assertEq(b.indexOf(data, comma, 0), 1, label + " bytes first")
  t.assertEq(b.indexOf(data, comma, 2), 3, label + " bytes next")
  t.assertEq(b.indexOf(data, comma, 4), -1, label + " bytes miss")
  t.assertEq(b.lastIndexOf(data, comma), 3, label + " bytes last")
  t.assertEq(b.indexOf(data, bytes(0), -10), 0, label + " empty bytes negative start")
  t.assertEq(b.indexOf(data, bytes(0), 99), len(data), label + " empty bytes high start")
  t.assertEq(b.lastIndexOf(data, bytes(0)), len(data), label + " empty bytes last")

  nulHay = bytes(70, 7)
  nulNeedle = bytes(3, 0)
  nulNeedle[0] = 0
  nulNeedle[1] = 42
  nulNeedle[2] = 0
  nulHay[31] = 0
  nulHay[32] = 42
  nulHay[33] = 0
  t.assertEq(b.indexOf(nulHay, nulNeedle, 0), 31, label + " embedded NUL")
  t.assertEq(b.lastIndexOf(nulHay, nulNeedle), 31, label + " embedded NUL last")

  positions = [0, 15, 16, 17, 31, 32, 33, 62]
  for each p in positions
    boundaryCase(p, 64, label + " boundary " + p)
  end for

  large = bytes(262177, 97)
  marker = bytes("needle!")
  largePos = len(large) - len(marker)
  for j = 0 to len(marker) - 1
    large[largePos + j] = marker[j]
  end for
  t.assertEq(b.indexOf(large, marker, 0), largePos, label + " large found")
  t.assertEq(b.indexOf(large, bytes("missing"), 0), -1, label + " large miss")
  deterministicDifferential(label)
end function

function main(args)
  previous = cpu.activeFeatures()
  cpu.setDispatchMaskForTesting(0)
  checkCurrentDispatch("scalar")
  cpu.setDispatchMaskForTesting(cpu.SSE2)
  checkCurrentDispatch("SSE2")
  cpu.setDispatchMaskForTesting(cpu.SSE2 | cpu.AVX2)
  checkCurrentDispatch("AVX2")
  cpu.setDispatchMaskForTesting(previous)
  checkCurrentDispatch("detected")
  print "[OK] SIMD search"
end function
