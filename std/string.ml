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

package std.string

// ------------------------------------------------------------
// std.string
// String utilities built from core language features:
// - len(s)
// - indexing s[i] -> 1-char string
// - concatenation via +
//
// Conventions:
// - On type errors, most helpers return void (similar to builtins like fromHex/slice).
// - Indices follow MiniLang indexing rules (negative indices allowed for s[i]).
// - The case/character helpers are ASCII-only (fast + predictable).
// ------------------------------------------------------------

/*
checks whether a character is ASCII whitespace
input: string ch (1 character)
returns: bool isWhitespace
*/
function _isWhitespace(ch)
  // Keep it minimal + predictable (ASCII whitespace).
  return ch == " " or ch == "\t" or ch == "\n" or ch == "\r"
end function

function _isWhitespaceByte(v)
  return v == 32 or v == 9 or v == 10 or v == 13
end function

function _lowerAsciiByte(v)
  if v >= 65 and v <= 90 then
    return v + 32
  end if
  return v
end function

function _upperAsciiByte(v)
  if v >= 97 and v <= 122 then
    return v - 32
  end if
  return v
end function

function _decodeOrEmpty(b)
  if typeof(b) != "bytes" then
    return
  end if
  if len(b) == 0 then
    return ""
  end if
  return decode(b)
end function

function _indexOfBytesNaive(hay, needle, start)
  if typeof(hay) != "bytes" or typeof(needle) != "bytes" then
    return -1
  end if

  n = len(hay)
  m = len(needle)
  i0 = start
  if typeof(i0) != "int" then
    i0 = 0
  end if
  if i0 < 0 then
    i0 = 0
  end if
  if i0 > n then
    i0 = n
  end if

  if m == 0 then
    return i0
  end if
  if m > n then
    return -1
  end if

  last = n - m
  if i0 > last then
    return -1
  end if

  i = i0
  while i <= last
    j = 0
    while j < m and hay[i + j] == needle[j]
      j = j + 1
    end while
    if j == m then
      return i
    end if
    i = i + 1
  end while

  return -1
end function

function _indexOfBytes(hay, needle, start)
  if typeof(hay) != "bytes" or typeof(needle) != "bytes" then
    return -1
  end if

  n = len(hay)
  m = len(needle)
  i0 = start
  if typeof(i0) != "int" then
    i0 = 0
  end if
  if i0 < 0 then
    i0 = 0
  end if
  if i0 > n then
    i0 = n
  end if

  if m == 0 then
    return i0
  end if
  if m > n then
    return -1
  end if

  last = n - m
  if i0 > last then
    return -1
  end if

  if m == 1 then
    b0 = needle[0]
    i = i0
    while i <= last
      if hay[i] == b0 then
        return i
      end if
      i = i + 1
    end while
    return -1
  end if

  if m < 4 or (last - i0) < 32 then
    return _indexOfBytesNaive(hay, needle, i0)
  end if

  shift = array(256, m)
  for j = 0 to(m - 2)
    shift[needle[j]] = (m - 1) - j
  end for

  lastByte = needle[m - 1]
  i = i0
  while i <= last
    tail = hay[i + m - 1]
    if tail == lastByte then
      j = 0
      while j < m - 1 and hay[i + j] == needle[j]
        j = j + 1
      end while
      if j == m - 1 then
        return i
      end if
    end if
    i = i + shift[tail]
  end while

  return -1
end function

function _lastIndexOfBytes(hay, needle)
  if typeof(hay) != "bytes" or typeof(needle) != "bytes" then
    return -1
  end if

  n = len(hay)
  m = len(needle)

  if m == 0 then
    return n
  end if
  if m > n then
    return -1
  end if

  i = n - m
  while i >= 0
    j = 0
    while j < m and hay[i + j] == needle[j]
      j = j + 1
    end while
    if j == m then
      return i
    end if
    i = i - 1
  end while

  return -1
end function

/*
checks whether a string is empty
input: string s
returns: bool isEmpty
*/
function isEmpty(s)
  if typeof(s) != "string" then
    return false
  end if
  return len(s) == 0
end function

/*
repeats a string count times
input: string s, int count
returns: string repeated
*/
function repeat(s, count)
  if typeof(s) != "string" then
    return
  end if
  if typeof(count) != "int" then
    return
  end if
  if count <= 0 then
    return ""
  end if

  sb = bytes(s)
  sl = len(sb)
  if sl == 0 then
    return ""
  end if

  total = sl * count
  output = bytes(total, 0)
  pos = 0
  i = 0
  while i < count
    copyBytes(output, pos, sb, 0, sl)
    pos = pos + sl
    i = i + 1
  end while
  return _decodeOrEmpty(output)
end function

/*
returns a substring of s
input: string s, int start, int length
returns: string substring
*/
function substr(s, start, length)
  if typeof(s) != "string" then
    return
  end if
  if typeof(start) != "int" then
    return
  end if
  if typeof(length) != "int" then
    return
  end if

  n = len(s)

  // normalize start
  i = start
  if i < 0 then
    i = i + n
  end if
  if i < 0 then
    i = 0
  end if
  if i > n then
    i = n
  end if

  // normalize length
  l = length
  if l <= 0 then
    return ""
  end if

  if i + l > n then
    l = n - i
  end if
  if l <= 0 then
    return ""
  end if

  sb = bytes(s)
  output = slice(sb, i, l)
  return _decodeOrEmpty(output)
end function

/*
checks whether s starts with prefix
input: string s, string prefix
returns: bool startsWith
*/
function startsWith(s, prefix)
  if typeof(s) != "string" then
    return false
  end if
  if typeof(prefix) != "string" then
    return false
  end if

  hb = bytes(s)
  nb = bytes(prefix)
  n = len(hb)
  m = len(nb)
  if m == 0 then
    return true
  end if
  if m > n then
    return false
  end if

  for i = 0 to(m - 1)
    if hb[i] != nb[i] then
      return false
    end if
  end for
  return true
end function

/*
checks whether s ends with suffix
input: string s, string suffix
returns: bool endsWith
*/
function endsWith(s, suffix)
  if typeof(s) != "string" then
    return false
  end if
  if typeof(suffix) != "string" then
    return false
  end if

  hb = bytes(s)
  nb = bytes(suffix)
  n = len(hb)
  m = len(nb)
  if m == 0 then
    return true
  end if
  if m > n then
    return false
  end if

  start = n - m
  for i = 0 to(m - 1)
    if hb[start + i] != nb[i] then
      return false
    end if
  end for
  return true
end function

/*
finds needle in s starting from start
input: string s, string needle, int start
returns: int index (>=0) or -1 if not found
*/
function indexOf(s, needle, start)
  if typeof(s) != "string" then
    return
  end if
  if typeof(needle) != "string" then
    return
  end if
  if typeof(start) != "int" then
    return
  end if

  hb = bytes(s)
  nb = bytes(needle)
  n = len(hb)
  m = len(nb)

  i0 = start
  if i0 < 0 then
    i0 = 0
  end if
  if i0 > n then
    i0 = n
  end if

  // empty needle
  if m == 0 then
    return i0
  end if

  if m > n then
    return -1
  end if

  last = n - m
  if i0 > last then
    return -1
  end if
  return _indexOfBytes(hb, nb, i0)
end function

/*
finds the last occurrence of needle in s
input: string s, string needle
returns: int index (>=0) or -1 if not found
*/
function lastIndexOf(s, needle)
  if typeof(s) != "string" then
    return
  end if
  if typeof(needle) != "string" then
    return
  end if

  hb = bytes(s)
  nb = bytes(needle)
  n = len(hb)
  m = len(nb)

  if m == 0 then
    return n
  end if
  if m > n then
    return -1
  end if

  return _lastIndexOfBytes(hb, nb)
end function

/*
checks whether s contains needle
input: string s, string needle
returns: bool contains
*/
function contains(s, needle)
  idx = std.string.indexOf(s, needle, 0)
  if typeof(idx) == "void" then
    return false
  end if
  return idx >= 0
end function

/*
trims ASCII whitespace on the left
input: string s
returns: string trimmed
*/
function ltrim(s)
  if typeof(s) != "string" then
    return
  end if

  sb = bytes(s)
  n = len(sb)
  if n == 0 then
    return ""
  end if

  i = 0
  while i < n
    if not _isWhitespaceByte(sb[i]) then
      break
    end if
    i = i + 1
  end while

  if i == 0 then
    return s
  end if
  return _decodeOrEmpty(slice(sb, i, n - i))
end function

/*
trims ASCII whitespace on the right
input: string s
returns: string trimmed
*/
function rtrim(s)
  if typeof(s) != "string" then
    return
  end if

  sb = bytes(s)
  n = len(sb)
  if n == 0 then
    return ""
  end if

  i = n - 1
  while i >= 0
    if not _isWhitespaceByte(sb[i]) then
      break
    end if
    i = i - 1
  end while

  if i == n - 1 then
    return s
  end if
  if i < 0 then
    return ""
  end if
  return _decodeOrEmpty(slice(sb, 0, i + 1))
end function

/*
trims ASCII whitespace on both sides
input: string s
returns: string trimmed
*/
function trim(s)
  if typeof(s) != "string" then
    return
  end if

  sb = bytes(s)
  n = len(sb)
  if n == 0 then
    return ""
  end if

  left = 0
  while left < n and _isWhitespaceByte(sb[left])
    left = left + 1
  end while

  if left >= n then
    return ""
  end if

  right = n - 1
  while right >= left and _isWhitespaceByte(sb[right])
    right = right - 1
  end while

  if left == 0 and right == n - 1 then
    return s
  end if

  return _decodeOrEmpty(slice(sb, left, right - left + 1))
end function

/*
checks whether a string is blank (empty after trim)
input: string s
returns: bool isBlank
*/
function isBlank(s)
  if typeof(s) != "string" then
    return false
  end if
  sb = bytes(s)
  n = len(sb)
  i = 0
  while i < n
    if not _isWhitespaceByte(sb[i]) then
      return false
    end if
    i = i + 1
  end while
  return true
end function

/*
splits a string by a separator
input: string s, string sep
returns: array<string> parts
*/
function split(s, sep)
  if typeof(s) != "string" then
    return
  end if
  if typeof(sep) != "string" then
    return
  end if

  // split into chars
  if len(sep) == 0 then
    n = len(s)
    val = array(n)
    for i = 0 to(n - 1)
      val[i] = s[i]
    end for
    return val
  end if

  hb = bytes(s)
  nb = bytes(sep)
  n = len(hb)
  sl = len(nb)

  count = 1
  i = 0
  while i <= n - sl
    p = _indexOfBytes(hb, nb, i)
    if p < 0 then
      break
    end if
    count = count + 1
    i = p + sl
  end while

  val = array(count)
  i = 0
  oi = 0
  while true
    p = _indexOfBytes(hb, nb, i)
    if p < 0 then
      val[oi] = _decodeOrEmpty(slice(hb, i, n - i))
      break
    end if
    val[oi] = _decodeOrEmpty(slice(hb, i, p - i))
    oi = oi + 1
    i = p + sl
  end while

  return val
end function

/*
joins string parts with a separator
input: array<string> parts, string sep
returns: string joined
*/
function join(parts, sep)
  if typeof(parts) != "array" then
    return
  end if
  if typeof(sep) != "string" then
    return
  end if

  n = len(parts)
  if n == 0 then
    return ""
  end if

  sepBytes = bytes(sep)
  sepLen = len(sepBytes)
  partBytes = array(n)
  totalLen = 0

  for i = 0 to(n - 1)
    if typeof(parts[i]) != "string" then
      return
    end if
    pb = bytes(parts[i])
    partBytes[i] = pb
    totalLen = totalLen + len(pb)
    if i > 0 then
      totalLen = totalLen + sepLen
    end if
  end for

  if totalLen == 0 then
    return ""
  end if

  output = bytes(totalLen, 0)
  pos = 0
  for i = 0 to(n - 1)
    if i > 0 and sepLen > 0 then
      copyBytes(output, pos, sepBytes, 0, sepLen)
      pos = pos + sepLen
    end if
    pb = partBytes[i]
    plen = len(pb)
    if plen > 0 then
      copyBytes(output, pos, pb, 0, plen)
      pos = pos + plen
    end if
  end for
  return _decodeOrEmpty(output)
end function

/*
replaces all occurrences of needle with repl
input: string s, string needle, string repl
returns: string replaced
*/
function replaceAll(s, needle, repl)
  if typeof(s) != "string" then
    return
  end if
  if typeof(needle) != "string" then
    return
  end if
  if typeof(repl) != "string" then
    return
  end if

  if len(needle) == 0 then
    return s
  end if

  hb = bytes(s)
  nb = bytes(needle)
  rb = bytes(repl)
  n = len(hb)
  nl = len(nb)
  rl = len(rb)

  count = 0
  i = 0
  while i <= n - nl
    p = _indexOfBytes(hb, nb, i)
    if p < 0 then
      break
    end if
    count = count + 1
    i = p + nl
  end while

  if count == 0 then
    return s
  end if

  totalLen = n + count * (rl - nl)
  if totalLen == 0 then
    return ""
  end if

  output = bytes(totalLen, 0)
  pos = 0
  i = 0
  while true
    p = _indexOfBytes(hb, nb, i)
    if p < 0 then
      tailLen = n - i
      if tailLen > 0 then
        copyBytes(output, pos, hb, i, tailLen)
      end if
      break
    end if

    segLen = p - i
    if segLen > 0 then
      copyBytes(output, pos, hb, i, segLen)
      pos = pos + segLen
    end if
    if rl > 0 then
      copyBytes(output, pos, rb, 0, rl)
      pos = pos + rl
    end if
    i = p + nl
  end while

  return _decodeOrEmpty(output)
end function

/*
replaces the first occurrence of needle with repl
input: string s, string needle, string repl
returns: string replaced
*/
function replaceFirst(s, needle, repl)
  if typeof(s) != "string" then
    return
  end if
  if typeof(needle) != "string" then
    return
  end if
  if typeof(repl) != "string" then
    return
  end if

  if len(needle) == 0 then
    return s
  end if

  p = std.string.indexOf(s, needle, 0)
  if typeof(p) == "void" then
    return
  end if
  if p < 0 then
    return s
  end if

  n = len(s)
  nl = len(needle)

  left = std.string.substr(s, 0, p)
  right = std.string.substr(s, p + nl, n -(p + nl))
  return left + repl + right
end function

/*
counts non-overlapping occurrences of needle in s
input: string s, string needle
returns: int count
*/
function countOf(s, needle)
  if typeof(s) != "string" then
    return
  end if
  if typeof(needle) != "string" then
    return
  end if

  if len(needle) == 0 then
    return 0
  end if

  hb = bytes(s)
  nb = bytes(needle)
  n = len(hb)
  nl = len(nb)

  count = 0
  i = 0
  while i <= n - nl
    p = _indexOfBytes(hb, nb, i)
    if p < 0 then
      break
    end if
    count = count + 1
    i = p + nl
  end while

  return count
end function

/*
removes all occurrences of needle from s
input: string s, string needle
returns: string result
*/
function removeAll(s, needle)
  return std.string.replaceAll(s, needle, "")
end function

/*
reverses a string
input: string s
returns: string reversed
*/
function reverse(s)
  if typeof(s) != "string" then
    return
  end if

  sb = bytes(s)
  n = len(sb)
  if n == 0 then
    return ""
  end if
  output = bytes(n, 0)
  i = 0
  while i < n
    output[i] = sb[n - 1 - i]
    i = i + 1
  end while
  return _decodeOrEmpty(output)
end function

// ------------------------------------------------------------
// ASCII character helpers
// ------------------------------------------------------------

/*
checks whether a character is an ASCII digit
input: string ch (1 character)
returns: bool isDigit
*/
function isDigitAscii(ch)
  if typeof(ch) != "string" then
    return false
  end if
  if len(ch) != 1 then
    return false
  end if
  return ch >= "0" and ch <= "9"
end function

/*
checks whether a character is an ASCII letter (A-Z or a-z)
input: string ch (1 character)
returns: bool isAlpha
*/
function isAlphaAscii(ch)
  if typeof(ch) != "string" then
    return false
  end if
  if len(ch) != 1 then
    return false
  end if
  return (ch >= "A" and ch <= "Z") or(ch >= "a" and ch <= "z")
end function

/*
checks whether a character is ASCII alphanumeric
input: string ch (1 character)
returns: bool isAlnum
*/
function isAlnumAscii(ch)
  return std.string.isAlphaAscii(ch) or std.string.isDigitAscii(ch)
end function

/*
converts a string to lowercase (ASCII)
input: string s
returns: string lower
*/
function toLowerAscii(s)
  if typeof(s) != "string" then
    return
  end if

  sb = bytes(s)
  n = len(sb)
  if n == 0 then
    return ""
  end if
  output = bytes(n, 0)
  i = 0
  while i < n
    output[i] = _lowerAsciiByte(sb[i])
    i = i + 1
  end while
  return _decodeOrEmpty(output)
end function

/*
converts a string to uppercase (ASCII)
input: string s
returns: string upper
*/
function toUpperAscii(s)
  if typeof(s) != "string" then
    return
  end if

  sb = bytes(s)
  n = len(sb)
  if n == 0 then
    return ""
  end if
  output = bytes(n, 0)
  i = 0
  while i < n
    output[i] = _upperAsciiByte(sb[i])
    i = i + 1
  end while
  return _decodeOrEmpty(output)
end function

/*
compares two strings case-insensitively (ASCII)
input: string a, string b
returns: bool equalsIgnoreCase
*/
function equalsIgnoreCaseAscii(a, b)
  if typeof(a) != "string" then
    return false
  end if
  if typeof(b) != "string" then
    return false
  end if

  ab = bytes(a)
  bb = bytes(b)
  n = len(ab)
  if n != len(bb) then
    return false
  end if
  i = 0
  while i < n
    if _lowerAsciiByte(ab[i]) != _lowerAsciiByte(bb[i]) then
      return false
    end if
    i = i + 1
  end while
  return true
end function


