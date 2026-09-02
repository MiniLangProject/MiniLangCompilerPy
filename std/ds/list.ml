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

//! Provides the std ds list package.

package std.ds.list

// ------------------------------------------------------------
// std.ds.list
// Simple growable list backed by a power-of-two array buffer.
//
// - add/push/pop are amortized O(1)
// - insert/removeAt are O(n)
// - keeps capacity on clear() to stay fast under reuse
// ------------------------------------------------------------

/// Allocates an array of length n filled with `fill`
/// @internal
function _allocArray(n, fill)
  if typeof(n) != "int" then
    return
  end if
  if n <= 0 then
    return []
  end if
  return array(n, fill)
end function

/// Returns the next power-of-two capacity (minimum 8).
/// @internal
function _nextPow2(n)
  if typeof(n) != "int" then
    return 8
  end if
  if n <= 8 then
    return 8
  end if
  c = 8
  while c < n
    c = c << 1
  end while
  return c
end function

/// Mutable growable sequence with indexed insertion and removal.
struct List
  /// Stores the buf member of `List`.
  buf
  /// Stores the size member of `List`.
  size
  /// Stores the cap member of `List`.
  cap

  /// Creates a new empty list.
  static function new()
  return List.withCapacity(8)
end function

/// Creates a new list with at least `minCap` capacity.
/// @param minCap Value supplied for `minCap`.
static function withCapacity(minCap)
c = _nextPow2(minCap)
b = _allocArray(c, 0)
return List(b, 0, c)
end function

/// Creates a new list from an array.
/// @param values Values to process.
static function fromArray(values)
if typeof(values) != "array" then
  return List.new()
end if
n = len(values)
lst = List.withCapacity(n)
if n > 0 then
  copyArray(lst.buf, 0, values, 0, n)
  lst.size = n
end if
return lst
end function

/// Returns number of elements.
function len()
  return this.size
end function

/// Checks whether the list is empty.
function isEmpty()
  return this.size == 0
end function

/// Removes all elements while keeping capacity.
function clear()
  if this.size > 0 then
    for i = 0 to(this.size - 1)
      this.buf[i] = 0
    end for
  end if
  this.size = 0
end function

/// Ensures that the capacity is at least `minCap`
/// @param minCap Value supplied for `minCap`.
function reserve(minCap)
  if typeof(minCap) != "int" then
    return
  end if
  if minCap <= this.cap then
    return
  end if
  this._grow(minCap)
end function

/// Grows the internal buffer to at least `newCap`
/// @internal
function _grow(newCap)
  c2 = _nextPow2(newCap)
  nb = _allocArray(c2, 0)
  if this.size > 0 then
    copyArray(nb, 0, this.buf, 0, this.size)
  end if
  this.buf = nb
  this.cap = c2
end function

/// Adds an element at the end of the list.
/// @param value Value to process.
function add(value)
  if this.size == this.cap then
    this._grow(this.cap << 1)
  end if
  this.buf[this.size] = value
  this.size = this.size + 1
end function

/// Alias for add(value).
/// @param value Value to process.
function push(value)
  this.add(value)
end function

/// Appends all values from an array.
/// @param values Values to process.
function addAll(values)
  if typeof(values) != "array" then
    return
  end if
  n = len(values)
  if n <= 0 then
    return
  end if
  needed = this.size + n
  if needed > this.cap then
    this._grow(needed)
  end if
  base = this.size
  copyArray(this.buf, base, values, 0, n)
  this.size = needed
end function

/// Returns the element at `index`
/// @param index Zero-based item index.
function get(index)
  if typeof(index) != "int" then
    return
  end if
  if index < 0 or index >= this.size then
    return
  end if
  return this.buf[index]
end function

/// Replaces the element at `index`
/// @param index Zero-based item index.
/// @param value Value to process.
function set(index, value)
  if typeof(index) != "int" then
    return false
  end if
  if index < 0 or index >= this.size then
    return false
  end if
  this.buf[index] = value
  return true
end function

/// Returns the first element.
function first()
  if this.size <= 0 then
    return
  end if
  return this.buf[0]
end function

/// Returns the last element.
function last()
  if this.size <= 0 then
    return
  end if
  return this.buf[this.size - 1]
end function

/// Removes and returns the last element.
function pop()
  if this.size <= 0 then
    return
  end if
  idx = this.size - 1
  v = this.buf[idx]
  this.buf[idx] = 0
  this.size = idx
  return v
end function

/// Removes and returns the last element or a fallback.
/// @param fallbackValue Value supplied for `fallbackValue`.
function popOr(fallbackValue)
  v = this.pop()
  if typeof(v) == "void" then
    return fallbackValue
  end if
  return v
end function

/// Inserts a value at `index`
/// @param index Zero-based item index.
/// @param value Value to process.
function insert(index, value)
  if typeof(index) != "int" then
    return false
  end if
  if index < 0 or index > this.size then
    return false
  end if
  if index == this.size then
    this.add(value)
    return true
  end if
  if this.size == this.cap then
    this._grow(this.cap << 1)
  end if
  i = this.size
  while i > index
    this.buf[i] = this.buf[i - 1]
    i = i - 1
  end while
  this.buf[index] = value
  this.size = this.size + 1
  return true
end function

/// Removes and returns the value at `index`
/// @param index Zero-based item index.
function removeAt(index)
  if typeof(index) != "int" then
    return
  end if
  if index < 0 or index >= this.size then
    return
  end if
  v = this.buf[index]
  i = index
  while i + 1 < this.size
    this.buf[i] = this.buf[i + 1]
    i = i + 1
  end while
  this.buf[this.size - 1] = 0
  this.size = this.size - 1
  return v
end function

/// Returns a snapshot array of all elements.
function toArray()
  output = array(this.size)
  if this.size <= 0 then
    return output
  end if
  copyArray(output, 0, this.buf, 0, this.size)
  return output
end function
end struct
