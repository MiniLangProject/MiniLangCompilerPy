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

package std.fmt

/*
repeats a string `ch` exactly `count` times
input: string ch, int count
returns: string repeated
*/
function repeat(ch, count)
  if typeof(ch) != "string" or typeof(count) != "int" then
    return
  end if
  if count <= 0 or len(ch) == 0 then
    return ""
  end if

  // Fast repeat via doubling (O(log n) concatenations).
  output = ""
  piece = ch
  n = count
  while n > 0
    if (n & 1) == 1 then
      output = output + piece
    end if
    n = n >> 1
    if n > 0 then
      piece = piece + piece
    end if
  end while
  return output
end function

/*
pads a string on the left to a desired width
input: string s, int width, string ch
returns: string padded
*/
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

/*
pads a string on the right to a desired width
input: string s, int width, string ch
returns: string padded
*/
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

/*
centers a string within a given width
input: string s, int width, string ch
returns: string centered
*/
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

/*
returns a JSON-like quoted string with minimal escaping
input: string s
returns: string quoted
*/
function quote(s)
  // Escapes: \\  \"  \\n  \\r  \\t
  if typeof(s) != "string" then
    return
  end if

  output = ""
  i = 0
  while i < len(s)
    c = s[i]
    if c == "\\" then
      output = output + "\\\\"
    else if c == "\"" then
      output = output + "\\\""
    else if c == "\n" then
      output = output + "\\n"
    else if c == "\r" then
      output = output + "\\r"
    else if c == "\t" then
      output = output + "\\t"
    else
      output = output + c
    end if
    i = i + 1
  end while

  return "\"" + output + "\""
end function

/*
creates a horizontal line
input: string ch, int width
returns: string line
*/
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


