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

package std.string_builder

// Mutable UTF-8 builder used where repeated immutable concatenation would copy
// the growing prefix on every append.

// Round capacities to powers of two so repeated appends grow geometrically.
function _nextPow2(n)
  if typeof(n) != "int" then
    return 16
  end if
  if n <= 16 then
    return 16
  end if
  c = 16
  while c < n
    c = c << 1
  end while
  return c
end function

// Mutable UTF-8 byte builder for append-heavy string construction.
struct StringBuilder
  buf
  lenBytes
  capacity

  // Create an empty builder with a practical default capacity.
  static function new()
    return std.string_builder.StringBuilder.withCapacity(64)
  end function

  // Create an empty builder with at least cap bytes of capacity.
  static function withCapacity(cap)
    if typeof(cap) != "int" then
      cap = 64
    end if
    if cap < 16 then
      cap = 16
    end if
    cap = _nextPow2(cap)
    return std.string_builder.StringBuilder(bytes(cap, 0), 0, cap)
  end function

  // Return the number of UTF-8 bytes currently stored.
  function len()
    return this.lenBytes
  end function

  // Reset the logical length while retaining allocated capacity.
  function clear()
    this.lenBytes = 0
  end function

  // Ensure room for at least extra additional bytes.
  function reserve(extra)
    if typeof(extra) != "int" then
      return
    end if
    if extra <= 0 then
      return
    end if
    need = this.lenBytes + extra
    if need <= this.capacity then
      return
    end if

    newCap = _nextPow2(need)
    nb = bytes(newCap, 0)
    if this.lenBytes > 0 then
      copyBytes(nb, 0, this.buf, 0, this.lenBytes)
    end if
    this.buf = nb
    this.capacity = newCap
  end function

  // Append a string without creating an intermediate concatenation.
  function appendString(s)
    if typeof(s) != "string" then
      return
    end if
    sl = len(s)
    if sl <= 0 then
      return
    end if
    this.reserve(sl)
    copyStringBytes(this.buf, this.lenBytes, s, 0, sl)
    this.lenBytes = this.lenBytes + sl
  end function

  // Append a clamped byte slice; negative offsets count from the end.
  function appendSlice(s, offset, length)
    if typeof(s) != "string" then
      return
    end if
    if typeof(offset) != "int" then
      return
    end if
    if typeof(length) != "int" then
      return
    end if

    n = len(s)
    off = offset
    if off < 0 then
      off = off + n
    end if
    if off < 0 then
      off = 0
    end if
    if off > n then
      off = n
    end if
    if length <= 0 then
      return
    end if

    rem = n - off
    take = length
    if take > rem then
      take = rem
    end if
    if take <= 0 then
      return
    end if

    this.reserve(take)
    copyStringBytes(this.buf, this.lenBytes, s, off, take)
    this.lenBytes = this.lenBytes + take
  end function

  // Convert a value with str() and append its textual representation.
  function append(value)
    sv = str(value)
    if typeof(sv) != "string" then
      return
    end if
    this.appendString(sv)
  end function

  // Append a value followed by a newline byte.
  function appendLine(value)
    this.append(value)
    this.appendString("\n")
  end function

  // Materialize exactly the initialized bytes as an immutable string.
  function toString()
    if this.lenBytes <= 0 then
      return ""
    end if
    return decode(slice(this.buf, 0, this.lenBytes))
  end function
end struct
