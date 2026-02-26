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

package std.bytes

import std.encoding.hex as hx

// ------------------------------------------------------------
// std.bytes
// Bytes helpers built on top of the built-in `bytes` type and operations.
// ------------------------------------------------------------

function alloc(size)
  if typeof(size) != "int" then
    return
  end if
  if size < 0 then
    return
  end if
  return bytes(size)
end function

function allocFill(size, fill)
  if typeof(size) != "int" then
    return
  end if
  if typeof(fill) != "int" then
    return
  end if
  if size < 0 then
    return
  end if
  return bytes(size, fill)
end function

function copy(b)
  if typeof(b) != "bytes" then
    return
  end if
  return slice(b, 0, len(b))
end function

function sub(b, offset, length)
  // wrapper for builtin slice(bytes, offset, length)
  if typeof(b) != "bytes" then
    return
  end if
  if typeof(offset) != "int" then
    return
  end if
  if typeof(length) != "int" then
    return
  end if
  return slice(b, offset, length)
end function

function concat(a, b)
  if typeof(a) != "bytes" then
    return
  end if
  if typeof(b) != "bytes" then
    return
  end if
  return a + b
end function

function equals(a, b)
  if typeof(a) != "bytes" then
    return false
  end if
  if typeof(b) != "bytes" then
    return false
  end if
  return a == b
end function

function fill(b, value)
  if typeof(b) != "bytes" then
    return
  end if
  if typeof(value) != "int" then
    return
  end if

  n = len(b)
  if n <= 0 then
    return
  end if

  for i = 0 to(n - 1)
    b[i] = value
  end for
end function

function startsWith(b, prefix)
  if typeof(b) != "bytes" then
    return false
  end if
  if typeof(prefix) != "bytes" then
    return false
  end if

  n = len(b)
  m = len(prefix)
  if m == 0 then
    return true
  end if
  if m > n then
    return false
  end if

  for i = 0 to(m - 1)
    if b[i] != prefix[i] then
      return false
    end if
  end for
  return true
end function

function endsWith(b, suffix)
  if typeof(b) != "bytes" then
    return false
  end if
  if typeof(suffix) != "bytes" then
    return false
  end if

  n = len(b)
  m = len(suffix)
  if m == 0 then
    return true
  end if
  if m > n then
    return false
  end if

  start = n - m
  for i = 0 to(m - 1)
    if b[start + i] != suffix[i] then
      return false
    end if
  end for
  return true
end function

function indexOf(hay, needle, start)
  if typeof(hay) != "bytes" then
    return
  end if
  if typeof(needle) != "bytes" then
    return
  end if
  if typeof(start) != "int" then
    return
  end if

  n = len(hay)
  m = len(needle)

  i0 = start
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

  for i = i0 to last
    ok = true
    for j = 0 to(m - 1)
      if hay[i + j] != needle[j] then
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

function compare(a, b)
  if typeof(a) != "bytes" then
    return
  end if
  if typeof(b) != "bytes" then
    return
  end if

  na = len(a)
  nb = len(b)
  n = na
  if nb < n then
    n = nb
  end if

  if n > 0 then
    for i = 0 to(n - 1)
      va = a[i]
      vb = b[i]
      if va < vb then
        return -1
      end if
      if va > vb then
        return 1
      end if
    end for
  end if

  if na < nb then
    return -1
  end if
  if na > nb then
    return 1
  end if
  return 0
end function

function toHex(b)
  return hx.encode(b)
end function

function fromHex(s)
  return hx.decode(s)
end function

function decodeUtf8(b)
  return decode(b)
end function

function decodeUtf8Z(b)
  // Wrapper around builtin decodeZ(bytes)
  return decodeZ(b)
end function

function decodeUtf16Z(b)
  // Wrapper around builtin decode16Z(bytes)
  return decode16Z(b)
end function

// ------------------------------------------------------------
// Binary read/write helpers (little-/big-endian)
// ------------------------------------------------------------

function _bytes_ok(b)
  return typeof(b) == "bytes"
end function

function _int_ok(x)
  return typeof(x) == "int"
end function

function _check_range(off, need, n)
  if off < 0 then
    return false
  end if
  if need < 0 then
    return false
  end if
  if off + need > n then
    return false
  end if
  return true
end function

function writeU8(b, off, value)
  if not _bytes_ok(b) then
    return false
  end if
  if not _int_ok(off) then
    return false
  end if
  if not _int_ok(value) then
    return false
  end if
  if value < 0 or value > 255 then
    return false
  end if
  n = len(b)
  if not _check_range(off, 1, n) then
    return false
  end if
  b[off] = value & 0xFF
  return true
end function

function readU8(b, off)
  if not _bytes_ok(b) then
    return
  end if
  if not _int_ok(off) then
    return
  end if
  n = len(b)
  if not _check_range(off, 1, n) then
    return
  end if
  return b[off] & 0xFF
end function

function writeU16LE(b, off, value)
  if not _bytes_ok(b) then
    return false
  end if
  if not _int_ok(off) then
    return false
  end if
  if not _int_ok(value) then
    return false
  end if
  if value < 0 or value > 0xFFFF then
    return false
  end if
  n = len(b)
  if not _check_range(off, 2, n) then
    return false
  end if
  b[off] = value & 0xFF
  b[off + 1] =(value >> 8) & 0xFF
  return true
end function

function writeU16BE(b, off, value)
  if not _bytes_ok(b) then
    return false
  end if
  if not _int_ok(off) then
    return false
  end if
  if not _int_ok(value) then
    return false
  end if
  if value < 0 or value > 0xFFFF then
    return false
  end if
  n = len(b)
  if not _check_range(off, 2, n) then
    return false
  end if
  b[off] =(value >> 8) & 0xFF
  b[off + 1] = value & 0xFF
  return true
end function

function readU16LE(b, off)
  if not _bytes_ok(b) then
    return
  end if
  if not _int_ok(off) then
    return
  end if
  n = len(b)
  if not _check_range(off, 2, n) then
    return
  end if
  lo = b[off] & 0xFF
  hi = b[off + 1] & 0xFF
  return lo |(hi << 8)
end function

function readU16BE(b, off)
  if not _bytes_ok(b) then
    return
  end if
  if not _int_ok(off) then
    return
  end if
  n = len(b)
  if not _check_range(off, 2, n) then
    return
  end if
  hi = b[off] & 0xFF
  lo = b[off + 1] & 0xFF
  return (hi << 8) | lo
end function

function writeU32LE(b, off, value)
  if not _bytes_ok(b) then
    return false
  end if
  if not _int_ok(off) then
    return false
  end if
  if not _int_ok(value) then
    return false
  end if
  if value < 0 or value > 0xFFFFFFFF then
    return false
  end if
  n = len(b)
  if not _check_range(off, 4, n) then
    return false
  end if
  b[off] = value & 0xFF
  b[off + 1] =(value >> 8) & 0xFF
  b[off + 2] =(value >> 16) & 0xFF
  b[off + 3] =(value >> 24) & 0xFF
  return true
end function

function writeU32BE(b, off, value)
  if not _bytes_ok(b) then
    return false
  end if
  if not _int_ok(off) then
    return false
  end if
  if not _int_ok(value) then
    return false
  end if
  if value < 0 or value > 0xFFFFFFFF then
    return false
  end if
  n = len(b)
  if not _check_range(off, 4, n) then
    return false
  end if
  b[off] =(value >> 24) & 0xFF
  b[off + 1] =(value >> 16) & 0xFF
  b[off + 2] =(value >> 8) & 0xFF
  b[off + 3] = value & 0xFF
  return true
end function

function readU32LE(b, off)
  if not _bytes_ok(b) then
    return
  end if
  if not _int_ok(off) then
    return
  end if
  n = len(b)
  if not _check_range(off, 4, n) then
    return
  end if
  b0 = b[off] & 0xFF
  b1 = b[off + 1] & 0xFF
  b2 = b[off + 2] & 0xFF
  b3 = b[off + 3] & 0xFF
  return b0 |(b1 << 8) |(b2 << 16) |(b3 << 24)
end function

function readU32BE(b, off)
  if not _bytes_ok(b) then
    return
  end if
  if not _int_ok(off) then
    return
  end if
  n = len(b)
  if not _check_range(off, 4, n) then
    return
  end if
  b0 = b[off] & 0xFF
  b1 = b[off + 1] & 0xFF
  b2 = b[off + 2] & 0xFF
  b3 = b[off + 3] & 0xFF
  return (b0 << 24) |(b1 << 16) |(b2 << 8) | b3
end function

function xor(a, b)
  if not typeof(a) == "bytes" then
    return
  end if
  if not typeof(b) == "bytes" then
    return
  end if
  if not len(a) == len(b) then
    return
  end if
  c = bytes(len(a))
  for i = 0 to len(a)
    c[i] = a[i] ^ b[i]
  end for
  return c
end function

function xorInPlace(a, b)
  if not typeof(a) == "bytes" then
    return
  end if
  if not typeof(b) == "bytes" then
    return
  end if
  if not len(a) == len(b) then
    return
  end if
  for i = 0 to len(a)
    a[i] = a[i] ^ b[i]
  end for
  return a
end function
