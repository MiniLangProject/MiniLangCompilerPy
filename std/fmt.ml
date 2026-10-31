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

//! Provides the std fmt package.

package std.fmt

import std.string_builder as sb

// Small allocation-conscious helpers for padding, centering and quoting text.

/// Repeats a string `ch` exactly `count` times.
/// @param ch Value supplied for `ch`.
/// @param count Number of items to process.
function repeat(ch, count)
  return stringRepeat(ch, count)
end function

/// Pads a string on the left to a desired width.
/// @param s Value supplied for `s`.
/// @param width Value supplied for `width`.
/// @param ch Value supplied for `ch`.
function padLeft(s, width, ch)
  if typeof(s) != "string" or typeof(width) != "int" or typeof(ch) != "string" then
    return
  end if
  n = width - len(s)
  if n <= 0 or len(ch) == 0 then
    return s
  end if
  return repeat(ch, n) + s
end function

/// Pads a string on the right to a desired width.
/// @param s Value supplied for `s`.
/// @param width Value supplied for `width`.
/// @param ch Value supplied for `ch`.
function padRight(s, width, ch)
  if typeof(s) != "string" or typeof(width) != "int" or typeof(ch) != "string" then
    return
  end if
  n = width - len(s)
  if n <= 0 or len(ch) == 0 then
    return s
  end if
  return s + repeat(ch, n)
end function

/// Centers a string within a given width.
/// @param s Value supplied for `s`.
/// @param width Value supplied for `width`.
/// @param ch Value supplied for `ch`.
function center(s, width, ch)
  if typeof(s) != "string" or typeof(width) != "int" or typeof(ch) != "string" then
    return
  end if
  n = width - len(s)
  if n <= 0 or len(ch) == 0 then
    return s
  end if

  // integer half: left = floor(n/2)
  left =(n -(n % 2)) / 2
  right = n - left

  return repeat(ch, left) + s + repeat(ch, right)
end function

/// Returns a JSON-like quoted string with minimal escaping.
/// @param s Value supplied for `s`.
function quote(s)
  // Escapes: \\  \"  \\n  \\r  \\t
  if typeof(s) != "string" then
    return
  end if

  src = bytes(s)
  n = len(src)
  if n >= 256 and n <= 0x3FFFFFFE then
    escapes = asm unsafe x64(in src as bytes, in n as int, scratch i as int, scratch ch as int) returns int
      mov result, 0
      mov i, 0
      label next
      cmp i, n
      jge done
      movzx ch, byte [src.data + i]
      cmp ch, 92
      je escaped
      cmp ch, 34
      je escaped
      cmp ch, 10
      je escaped
      cmp ch, 13
      je escaped
      cmp ch, 9
      jne advance
      label escaped
      add result, 1
      label advance
      add i, 1
      jmp next
      label done
    end asm
    output = bytes(n + escapes + 2, 0)
    output[0] = 34
    asm unsafe x64(in src as bytes, inout output as bytes, in n as int, scratch i as int, scratch oi as int, scratch ch as int, scratch slash as int)
      mov i, 0
      mov oi, 1
      mov slash, 92
      label next
      cmp i, n
      jge done
      movzx ch, byte [src.data + i]
      cmp ch, 92
      je escaped
      cmp ch, 34
      je escaped
      cmp ch, 10
      je newline
      cmp ch, 13
      je carriage
      cmp ch, 9
      je tab
      jmp write
      label newline
      mov ch, 110
      jmp escaped
      label carriage
      mov ch, 114
      jmp escaped
      label tab
      mov ch, 116
      label escaped
      mov byte [output.data + oi], slash
      add oi, 1
      label write
      mov byte [output.data + oi], ch
      add oi, 1
      add i, 1
      jmp next
      label done
    end asm
    output[n + escapes + 1] = 34
    return decode(output)
  end if
  bld = sb.StringBuilder.withCapacity(n + 8)
  bld.appendString("\"")
  runStart = 0
  i = 0
  while i < n
    c = src[i]
    esc = ""
    if c == 92 then
      esc = "\\\\"
    else if c == 34 then
      esc = "\\\""
    else if c == 10 then
      esc = "\\n"
    else if c == 13 then
      esc = "\\r"
    else if c == 9 then
      esc = "\\t"
    end if
    if len(esc) > 0 then
      if i > runStart then
        bld.appendSlice(s, runStart, i - runStart)
      end if
      bld.appendString(esc)
      runStart = i + 1
    end if
    i = i + 1
  end while

  if runStart < n then
    bld.appendSlice(s, runStart, n - runStart)
  end if
  bld.appendString("\"")
  return bld.toString()
end function

/// Creates a horizontal line.
/// @param ch Value supplied for `ch`.
/// @param width Value supplied for `width`.
function line(ch, width)
  if typeof(ch) != "string" or typeof(width) != "int" then
    return
  end if
  if width <= 0 then
    return ""
  end if
  if len(ch) == 0 then
    ch = "-"
  end if
  return repeat(ch, width)
end function


