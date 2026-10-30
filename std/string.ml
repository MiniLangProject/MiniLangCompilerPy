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

//! Provides the std string package.

package std.string

import std.string_builder as sb

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

/// Checks whether a string is empty.
/// @param s Value supplied for `s`.
function isEmpty(s)
  if typeof(s) != "string" then
    return false
  end if
  return len(s) == 0
end function

/// Repeats a string count times.
/// @param s Value supplied for `s`.
/// @param count Number of items to process.
function repeat(s, count)
  return stringRepeat(s, count)
end function

/// Returns a substring of s.
/// @param s Value supplied for `s`.
/// @param start Value supplied for `start`.
/// @param length Number of elements or bytes to process.
function substr(s, start, length)
  return stringSlice(s, start, length)
end function

/// Checks whether s starts with prefix.
/// @param s Value supplied for `s`.
/// @param prefix Value supplied for `prefix`.
function startsWith(s, prefix)
  return stringStartsWith(s, prefix)
end function

/// Checks whether s ends with suffix.
/// @param s Value supplied for `s`.
/// @param suffix Value supplied for `suffix`.
function endsWith(s, suffix)
  return stringEndsWith(s, suffix)
end function

/// Finds needle in s starting from start.
/// @param s Value supplied for `s`.
/// @param needle Value supplied for `needle`.
/// @param start Value supplied for `start`.
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
  return stringIndexOf(s, needle, start)
end function

/// Finds the last occurrence of needle in s.
/// @param s Value supplied for `s`.
/// @param needle Value supplied for `needle`.
function lastIndexOf(s, needle)
  if typeof(s) != "string" then
    return
  end if
  if typeof(needle) != "string" then
    return
  end if
  return stringLastIndexOf(s, needle)
end function

/// Checks whether s contains needle.
/// @param s Value supplied for `s`.
/// @param needle Value supplied for `needle`.
function contains(s, needle)
  idx = stringIndexOf(s, needle, 0)
  if typeof(idx) == "void" then
    return false
  end if
  return idx >= 0
end function

/// Trims ASCII whitespace on the left.
/// @param s Value supplied for `s`.
function ltrim(s)
  return stringTrimLeftAscii(s)
end function

/// Trims ASCII whitespace on the right.
/// @param s Value supplied for `s`.
function rtrim(s)
  return stringTrimRightAscii(s)
end function

/// Trims ASCII whitespace on both sides.
/// @param s Value supplied for `s`.
function trim(s)
  return stringTrimAscii(s)
end function

/// Checks whether a string is blank (empty after trim).
/// @param s Value supplied for `s`.
function isBlank(s)
  return stringIsBlankAscii(s)
end function

/// Splits a string by a separator.
/// @param s Value supplied for `s`.
/// @param sep Value supplied for `sep`.
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

  n = len(s)
  sl = len(sep)

  count = 1
  i = 0
  while i <= n - sl
    p = stringIndexOf(s, sep, i)
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
    p = stringIndexOf(s, sep, i)
    if p < 0 then
      val[oi] = stringSlice(s, i, n - i)
      break
    end if
    val[oi] = stringSlice(s, i, p - i)
    oi = oi + 1
    i = p + sl
  end while

  return val
end function

/// Joins string parts with a separator.
/// @param parts Value supplied for `parts`.
/// @param sep Value supplied for `sep`.
function join(parts, sep)
  return stringJoin(parts, sep)
end function

/// Replaces all occurrences of needle with repl.
/// @param s Value supplied for `s`.
/// @param needle Value supplied for `needle`.
/// @param repl Value supplied for `repl`.
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
  n = len(s)
  nl = len(needle)
  first = stringIndexOf(s, needle, 0)
  if first < 0 then
    return s
  end if

  bld = sb.StringBuilder.withCapacity(n)
  i = 0
  while true
    p = stringIndexOf(s, needle, i)
    if p < 0 then
      tailLen = n - i
      if tailLen > 0 then
        bld.appendSlice(s, i, tailLen)
      end if
      break
    end if

    segLen = p - i
    if segLen > 0 then
      bld.appendSlice(s, i, segLen)
    end if
    if len(repl) > 0 then
      bld.appendString(repl)
    end if
    i = p + nl
  end while

  return bld.toString()
end function

/// Replaces the first occurrence of needle with repl.
/// @param s Value supplied for `s`.
/// @param needle Value supplied for `needle`.
/// @param repl Value supplied for `repl`.
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

  p = stringIndexOf(s, needle, 0)
  if typeof(p) == "void" then
    return
  end if
  if p < 0 then
    return s
  end if

  n = len(s)
  nl = len(needle)
  bld = sb.StringBuilder.withCapacity(n)
  if p > 0 then
    bld.appendSlice(s, 0, p)
  end if
  if len(repl) > 0 then
    bld.appendString(repl)
  end if
  tailOff = p + nl
  tailLen = n - tailOff
  if tailLen > 0 then
    bld.appendSlice(s, tailOff, tailLen)
  end if
  return bld.toString()
end function

/// Counts non-overlapping occurrences of needle in s.
/// @param s Value supplied for `s`.
/// @param needle Value supplied for `needle`.
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
  n = len(s)
  nl = len(needle)

  count = 0
  i = 0
  while i <= n - nl
    p = stringIndexOf(s, needle, i)
    if p < 0 then
      break
    end if
    count = count + 1
    i = p + nl
  end while

  return count
end function

/// Removes all occurrences of needle from s.
/// @param s Value supplied for `s`.
/// @param needle Value supplied for `needle`.
function removeAll(s, needle)
  return std.string.replaceAll(s, needle, "")
end function

/// Reverses a string.
/// @param s Value supplied for `s`.
function reverse(s)
  return stringReverse(s)
end function

// ------------------------------------------------------------
// ASCII character helpers
// ------------------------------------------------------------

/// Checks whether a character is an ASCII digit.
/// @param ch Value supplied for `ch`.
function isDigitAscii(ch)
  if typeof(ch) != "string" then
    return false
  end if
  if len(ch) != 1 then
    return false
  end if
  return ch >= "0" and ch <= "9"
end function

/// Checks whether a character is an ASCII letter (A-Z or a-z).
/// @param ch Value supplied for `ch`.
function isAlphaAscii(ch)
  if typeof(ch) != "string" then
    return false
  end if
  if len(ch) != 1 then
    return false
  end if
  return (ch >= "A" and ch <= "Z") or(ch >= "a" and ch <= "z")
end function

/// Checks whether a character is ASCII alphanumeric.
/// @param ch Value supplied for `ch`.
function isAlnumAscii(ch)
  return std.string.isAlphaAscii(ch) or std.string.isDigitAscii(ch)
end function

/// Converts a string to lowercase (ASCII).
/// @param s Value supplied for `s`.
function toLowerAscii(s)
  return stringToLowerAscii(s)
end function

/// Converts a string to uppercase (ASCII).
/// @param s Value supplied for `s`.
function toUpperAscii(s)
  return stringToUpperAscii(s)
end function

/// Compares two strings case-insensitively (ASCII).
/// @param a First input value.
/// @param b Second input value.
function equalsIgnoreCaseAscii(a, b)
  return stringEqualsIgnoreCaseAscii(a, b)
end function


