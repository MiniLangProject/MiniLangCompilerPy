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

package std.ds.list

// ------------------------------------------------------------
// std.ds.list
// Simple growable list backed by a power-of-two array buffer.
//
// - add/push/pop are amortized O(1)
// - insert/removeAt are O(n)
// - keeps capacity on clear() to stay fast under reuse
// ------------------------------------------------------------

/*
allocates an array of length n filled with `fill`
input: int n, any fill
returns: array output
*/
function _allocArray(n, fill)
  if typeof(n) != "int" then
    return
  end if
  if n <= 0 then
    return []
  end if
  return array(n, fill)
end function

/*
returns the next power-of-two capacity (minimum 8)
input: int n
returns: int capPow2
*/
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

struct List
  buf
  size
  cap

  /*
  creates a new empty list
  input: (none)
  returns: List list
  */
  static function new()
  return List.withCapacity(8)
end function

/*
creates a new list with at least `minCap` capacity
input: int minCap
returns: List list
*/
static function withCapacity(minCap)
c = _nextPow2(minCap)
b = _allocArray(c, 0)
return List(b, 0, c)
end function

/*
creates a new list from an array
input: array values
returns: List list
*/
static function fromArray(values)
if typeof(values) != "array" then
  return List.new()
end if
n = len(values)
lst = List.withCapacity(n)
if n > 0 then
  buf = lst.buf
  for i = 0 to(n - 1)
    buf[i] = values[i]
  end for
  lst.buf = buf
  lst.size = n
end if
return lst
end function

/*
returns number of elements
input: (none)
returns: int count
*/
function len()
  return this.size
end function

/*
checks whether the list is empty
input: (none)
returns: bool empty
*/
function isEmpty()
  return this.size == 0
end function

/*
removes all elements while keeping capacity
input: (none)
returns: void
*/
function clear()
  if this.size > 0 then
    for i = 0 to(this.size - 1)
      this.buf[i] = 0
    end for
  end if
  this.size = 0
end function

/*
ensures that the capacity is at least `minCap`
input: int minCap
returns: void
*/
function reserve(minCap)
  if typeof(minCap) != "int" then
    return
  end if
  if minCap <= this.cap then
    return
  end if
  this._grow(minCap)
end function

/*
grows the internal buffer to at least `newCap`
input: int newCap
returns: void
*/
function _grow(newCap)
  c2 = _nextPow2(newCap)
  nb = _allocArray(c2, 0)
  if this.size > 0 then
    for i = 0 to(this.size - 1)
      nb[i] = this.buf[i]
    end for
  end if
  this.buf = nb
  this.cap = c2
end function

/*
adds an element at the end of the list
input: any value
returns: void
*/
function add(value)
  if this.size == this.cap then
    this._grow(this.cap << 1)
  end if
  this.buf[this.size] = value
  this.size = this.size + 1
end function

/*
alias for add(value)
input: any value
returns: void
*/
function push(value)
  this.add(value)
end function

/*
appends all values from an array
input: array values
returns: void
*/
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
  for i = 0 to(n - 1)
    this.buf[base + i] = values[i]
  end for
  this.size = needed
end function

/*
returns the element at `index`
input: int index
returns: any value (or void if out of bounds)
*/
function get(index)
  if typeof(index) != "int" then
    return
  end if
  if index < 0 or index >= this.size then
    return
  end if
  return this.buf[index]
end function

/*
replaces the element at `index`
input: int index, any value
returns: bool ok
*/
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

/*
returns the first element
input: (none)
returns: any value (or void if empty)
*/
function first()
  if this.size <= 0 then
    return
  end if
  return this.buf[0]
end function

/*
returns the last element
input: (none)
returns: any value (or void if empty)
*/
function last()
  if this.size <= 0 then
    return
  end if
  return this.buf[this.size - 1]
end function

/*
removes and returns the last element
input: (none)
returns: any value (or void if empty)
*/
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

/*
removes and returns the last element or a fallback
input: any fallbackValue
returns: any value
*/
function popOr(fallbackValue)
  v = this.pop()
  if typeof(v) == "void" then
    return fallbackValue
  end if
  return v
end function

/*
inserts a value at `index`
input: int index, any value
returns: bool ok
*/
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

/*
removes and returns the value at `index`
input: int index
returns: any value (or void if out of bounds)
*/
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

/*
returns a snapshot array of all elements
input: (none)
returns: array values
*/
function toArray()
  output = array(this.size)
  if this.size <= 0 then
    return output
  end if
  for i = 0 to(this.size - 1)
    output[i] = this.buf[i]
  end for
  return output
end function
end struct
