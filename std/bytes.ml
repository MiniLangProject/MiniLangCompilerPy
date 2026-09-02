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

//! Provides the std bytes package.

package std.bytes

/// Track the bytes err value used by this standard-library module.
const BYTES_ERR = 211

/// Construct a consistent argument/range error for this module.
/// @internal
function _bytesErr(msg)
  return error(BYTES_ERR, msg)
end function


import std.encoding.hex as hx

// Byte-sequence allocation, slicing, comparison, encoding and endian-aware
// integer I/O. Functions validate types and avoid implicit string conversion.

/// Std.bytes Bytes helpers built on top of the built-in `bytes` type and operations.
/// @param size Value supplied for `size`.
function alloc(size)
  if typeof(size) != "int" then
    return
  end if
  if size < 0 then
    return
  end if
  return bytes(size)
end function

/// Allocate size bytes initialized to the low eight bits of fill.
/// @param size Value supplied for `size`.
/// @param fill Value supplied for `fill`.
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

/// Return a detached copy of a bytes value.
/// @param b Second input value.
function copy(b)
  if typeof(b) != "bytes" then
    return
  end if
  return slice(b, 0, len(b))
end function

/// Return a clamped slice, or void when the input is not bytes.
/// @param b Second input value.
/// @param offset Zero-based starting offset.
/// @param length Number of elements or bytes to process.
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

/// Return an exact validated slice or a descriptive error value.
/// @param b Second input value.
/// @param offset Zero-based starting offset.
/// @param length Number of elements or bytes to process.
function subOrError(b, offset, length)
  if typeof(b) != "bytes" then
    return _bytesErr("bytes.subOrError expects bytes")
  end if
  if typeof(offset) != "int" then
    return _bytesErr("bytes.subOrError expects int offset")
  end if
  if typeof(length) != "int" then
    return _bytesErr("bytes.subOrError expects int length")
  end if
  if length < 0 then
    return _bytesErr("slice length must be >= 0")
  end if

  n = len(b)
  off = offset
  if off < 0 then
    off = off + n
  end if
  if off < 0 or off > n then
    return _bytesErr("slice out of bounds")
  end if
  if off + length > n then
    return _bytesErr("slice out of bounds")
  end if

  // Call the builtin with the original offset (supports negative offsets).
  output = slice(b, offset, length)
  if typeof(output) == "void" then
    return _bytesErr("slice failed")
  end if
  return output
end function


/// Concatenate two byte sequences into newly allocated storage.
/// @param a First input value.
/// @param b Second input value.
function concat(a, b)
  if typeof(a) != "bytes" then
    return
  end if
  if typeof(b) != "bytes" then
    return
  end if
  return a + b
end function

/// Compare two byte sequences with ordinary early-exit semantics.
/// @param a First input value.
/// @param b Second input value.
function equals(a, b)
  if typeof(a) != "bytes" then
    return false
  end if
  if typeof(b) != "bytes" then
    return false
  end if
  return a == b
end function

/// Compare equal-length sequences without data-dependent early exit.
/// @param a First input value.
/// @param b Second input value.
function ctEquals(a, b)
  /*
  Constant-time-ish equality check for bytes.

  Notes:
  - Always scans up to max(len(a), len(b)) (no early exit).
  - Still leaks lengths via the loop count, but avoids value-dependent timing.
  */
  if typeof(a) != "bytes" then
    return false
  end if
  if typeof(b) != "bytes" then
    return false
  end if

  na = len(a)
  nb = len(b)
  n = na
  if nb > n then
    n = nb
  end if

  diff = na ^ nb
  if n > 0 then
    for i = 0 to(n - 1)
      va = 0
      vb = 0
      if i < na then
        va = a[i]
      end if
      if i < nb then
        vb = b[i]
      end if
      diff = diff |(va ^ vb)
    end for
  end if

  return diff == 0
end function

/// Replace every byte in b with the low eight bits of value.
/// @param b Second input value.
/// @param value Value to process.
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

  fillBytes(b, 0, n, value)
end function

/// Report whether b begins with prefix.
/// @param b Second input value.
/// @param prefix Value supplied for `prefix`.
function startsWith(b, prefix)
  if typeof(b) != "bytes" then
    return false
  end if
  if typeof(prefix) != "bytes" then
    return false
  end if
  return bytesStartsWith(b, prefix)
end function

/// Report whether b ends with suffix.
/// @param b Second input value.
/// @param suffix Value supplied for `suffix`.
function endsWith(b, suffix)
  if typeof(b) != "bytes" then
    return false
  end if
  if typeof(suffix) != "bytes" then
    return false
  end if
  return bytesEndsWith(b, suffix)
end function

/// Use direct scanning for short inputs where preprocessing would cost more.
/// @internal
function _indexOfNaive(hay, needle, start)
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

/// Find the first needle occurrence at or after start, or return -1.
/// @param hay Value supplied for `hay`.
/// @param needle Value supplied for `needle`.
/// @param start Value supplied for `start`.
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
  return bytesIndexOf(hay, needle, start)
end function

/// Find the final needle occurrence, or return -1.
/// @param hay Value supplied for `hay`.
/// @param needle Value supplied for `needle`.
function lastIndexOf(hay, needle)
  if typeof(hay) != "bytes" then
    return
  end if
  if typeof(needle) != "bytes" then
    return
  end if
  return bytesLastIndexOf(hay, needle)
end function

/// Return a lexicographic three-way comparison result.
/// @param a First input value.
/// @param b Second input value.
function compare(a, b)
  if typeof(a) != "bytes" then
    return
  end if
  if typeof(b) != "bytes" then
    return
  end if
  return bytesCompare(a, b)
end function

/// Encode bytes as lowercase hexadecimal text.
/// @param b Second input value.
function toHex(b)
  return hx.encode(b)
end function

/// Decode hexadecimal text, returning void on invalid input.
/// @param s Value supplied for `s`.
function fromHex(s)
  return hx.decode(s)
end function

/// Decode hexadecimal text, preserving validation failures as errors.
/// @param s Value supplied for `s`.
function fromHexOrError(s)
  if typeof(s) != "string" then
    return _bytesErr("bytes.fromHexOrError expects a string")
  end if
  b = hx.decode(s)
  if typeof(b) == "void" then
    return _bytesErr("Invalid hex string")
  end if
  return b
end function


/// Decode UTF-8 bytes, returning void on invalid input.
/// @param b Second input value.
function decodeUtf8(b)
  return decode(b)
end function

/// Decode UTF-8 bytes, preserving validation failures as errors.
/// @param b Second input value.
function decodeUtf8OrError(b)
  if typeof(b) != "bytes" then
    return _bytesErr("bytes.decodeUtf8OrError expects bytes")
  end if
  s = decode(b)
  if typeof(s) == "void" then
    return _bytesErr("decode failed")
  end if
  return s
end function


/// Decode UTF-8 bytes up to the first zero terminator.
/// @param b Second input value.
function decodeUtf8Z(b)
  // Wrapper around builtin decodeZ(bytes)
  return decodeZ(b)
end function

/// Decode little-endian UTF-16 bytes up to the first zero code unit.
/// @param b Second input value.
function decodeUtf16Z(b)
  // Wrapper around builtin decode16Z(bytes)
  return decode16Z(b)
end function

/// Binary read/write helpers (little-/big-endian).
/// @internal
function _bytes_ok(b)
  return typeof(b) == "bytes"
end function

/// Centralize integer validation for binary read/write offsets.
/// @internal
function _int_ok(x)
  return typeof(x) == "int"
end function

/// Validate that a fixed-width access fits completely inside a buffer.
/// @internal
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

/// Write one unsigned byte and return the next offset.
/// @param b Second input value.
/// @param off Value supplied for `off`.
/// @param value Value to process.
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

/// Read one unsigned byte or return a range/type error.
/// @param b Second input value.
/// @param off Value supplied for `off`.
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

/// Write an unsigned 16-bit integer in little-endian order.
/// @param b Second input value.
/// @param off Value supplied for `off`.
/// @param value Value to process.
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

/// Write an unsigned 16-bit integer in big-endian order.
/// @param b Second input value.
/// @param off Value supplied for `off`.
/// @param value Value to process.
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

/// Read an unsigned little-endian 16-bit integer.
/// @param b Second input value.
/// @param off Value supplied for `off`.
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

/// Read an unsigned big-endian 16-bit integer.
/// @param b Second input value.
/// @param off Value supplied for `off`.
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

/// Write an unsigned 32-bit integer in little-endian order.
/// @param b Second input value.
/// @param off Value supplied for `off`.
/// @param value Value to process.
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

/// Write an unsigned 32-bit integer in big-endian order.
/// @param b Second input value.
/// @param off Value supplied for `off`.
/// @param value Value to process.
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

/// Read an unsigned little-endian 32-bit integer.
/// @param b Second input value.
/// @param off Value supplied for `off`.
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

/// Read an unsigned big-endian 32-bit integer.
/// @param b Second input value.
/// @param off Value supplied for `off`.
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

/// Return the bytewise XOR of two equal-length sequences.
/// @param a First input value.
/// @param b Second input value.
function xor(a, b)
  if typeof(a) != "bytes" then
    return
  end if
  if typeof(b) != "bytes" then
    return
  end if
  if len(a) != len(b) then
    return
  end if

  n = len(a)
  c = bytes(n)
  i = 0
  while i < n
    c[i] = a[i] ^ b[i]
    i = i + 1
  end while
  return c
end function


/// XOR b into a in place; both sequences must have equal length.
/// @param a First input value.
/// @param b Second input value.
function xorInPlace(a, b)
  if typeof(a) != "bytes" then
    return
  end if
  if typeof(b) != "bytes" then
    return
  end if
  if len(a) != len(b) then
    return
  end if

  n = len(a)
  i = 0
  while i < n
    a[i] = a[i] ^ b[i]
    i = i + 1
  end while
  return a
end function
