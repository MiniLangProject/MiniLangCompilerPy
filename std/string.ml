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

  val = ""
  for i = 1 to count
    val = val + s
  end for
  return val
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

  val = ""
  for k = i to(i + l - 1)
    val = val + s[k]
  end for
  return val
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

  n = len(s)
  m = len(prefix)
  if m == 0 then
    return true
  end if
  if m > n then
    return false
  end if

  for i = 0 to(m - 1)
    if s[i] != prefix[i] then
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

  n = len(s)
  m = len(suffix)
  if m == 0 then
    return true
  end if
  if m > n then
    return false
  end if

  start = n - m
  for i = 0 to(m - 1)
    if s[start + i] != suffix[i] then
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

  n = len(s)
  m = len(needle)

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

  for i = i0 to last
    ok = true
    for j = 0 to(m - 1)
      if s[i + j] != needle[j] then
        ok = false
        break
      end if
    end for
    if ok then
      return i
    end if
  end for

  return -1
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

  n = len(s)
  m = len(needle)

  if m == 0 then
    return n
  end if
  if m > n then
    return -1
  end if

  i = n - m
  while i >= 0
    ok = true
    for j = 0 to(m - 1)
      if s[i + j] != needle[j] then
        ok = false
        break
      end if
    end for
    if ok then
      return i
    end if
    i = i - 1
  end while

  return -1
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

  n = len(s)
  if n == 0 then
    return ""
  end if

  i = 0
  while i < n
    ch = s[i]
    if not std.string._isWhitespace(ch) then
      break
    end if
    i = i + 1
  end while

  return std.string.substr(s, i, n - i)
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

  n = len(s)
  if n == 0 then
    return ""
  end if

  i = n - 1
  while i >= 0
    ch = s[i]
    if not std.string._isWhitespace(ch) then
      break
    end if
    i = i - 1
  end while

  return std.string.substr(s, 0, i + 1)
end function

/*
trims ASCII whitespace on both sides
input: string s
returns: string trimmed
*/
function trim(s)
  return std.string.rtrim(std.string.ltrim(s))
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
  return len(std.string.trim(s)) == 0
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
    val =[]
    for each ch in s
      val = val +[ch]
    end for
    return val
  end if

  val =[]
  i = 0
  n = len(s)
  sl = len(sep)

  while true
    p = std.string.indexOf(s, sep, i)
    if typeof(p) == "void" then
      return
    end if

    if p < 0 then
      val = val +[std.string.substr(s, i, n - i)]
      break
    end if

    val = val +[std.string.substr(s, i, p - i)]
    i = p + sl

    if i > n then
      val = val +[""]
      break
    end if
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

  val = ""
  for i = 0 to(n - 1)
    if i == 0 then
      val = val + parts[i]
    else
      val = val + sep + parts[i]
    end if
  end for
  return val
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

  val = ""
  i = 0
  n = len(s)
  nl = len(needle)

  while true
    p = std.string.indexOf(s, needle, i)
    if typeof(p) == "void" then
      return
    end if
    if p < 0 then
      val = val + std.string.substr(s, i, n - i)
      break
    end if

    val = val + std.string.substr(s, i, p - i) + repl
    i = p + nl

    if i > n then
      break
    end if
  end while

  return val
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

  count = 0
  i = 0
  n = len(s)
  nl = len(needle)

  while i <=(n - nl)
    p = std.string.indexOf(s, needle, i)
    if typeof(p) == "void" then
      return
    end if
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

  n = len(s)
  output = ""
  i = n - 1
  while i >= 0
    output = output + s[i]
    i = i - 1
  end while
  return output
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

  upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  lower = "abcdefghijklmnopqrstuvwxyz"

  output = ""
  for each ch in s
    idx = std.string.indexOf(upper, ch, 0)
    if typeof(idx) == "void" then
      return
    end if
    if idx >= 0 then
      output = output + lower[idx]
    else
      output = output + ch
    end if
  end for
  return output
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

  upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  lower = "abcdefghijklmnopqrstuvwxyz"

  output = ""
  for each ch in s
    idx = std.string.indexOf(lower, ch, 0)
    if typeof(idx) == "void" then
      return
    end if
    if idx >= 0 then
      output = output + upper[idx]
    else
      output = output + ch
    end if
  end for
  return output
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

  if len(a) != len(b) then
    return false
  end if

  aa = std.string.toLowerAscii(a)
  bb = std.string.toLowerAscii(b)
  if typeof(aa) == "void" or typeof(bb) == "void" then
    return false
  end if
  return aa == bb
end function

