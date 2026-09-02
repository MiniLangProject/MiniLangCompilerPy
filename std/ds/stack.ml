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

//! Provides the std ds stack package.

package std.ds.stack

/// Std.ds.stack Simple LIFO stack implemented with an internal growable buffer. Notes: - push/pop are amortized O(1). - Methods keep compatibility with legacy Stack([...]) constructor payloads.
/// @internal
const _STATE_TAG = "__std.ds.stack.v2__"

/// Allocates an array of length n filled with `fill`
/// @internal
function _allocArray(n, fill)
  if typeof(n) != "int" then
    return
  end if
  if n < 0 then
    return
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

/// Checks whether data is a valid v2 stack state shape: [buf(array), size(int), cap(int), tag].
/// @internal
function _isState(data)
  if typeof(data) != "array" then
    return false
  end if
  if len(data) != 4 then
    return false
  end if
  if typeof(data[0]) != "array" then
    return false
  end if
  if typeof(data[1]) != "int" then
    return false
  end if
  if typeof(data[2]) != "int" then
    return false
  end if
  if data[3] != _STATE_TAG then
    return false
  end if
  if data[2] < 8 then
    return false
  end if
  if data[1] < 0 then
    return false
  end if
  if data[1] > data[2] then
    return false
  end if
  if len(data[0]) != data[2] then
    return false
  end if
  return true
end function

/// Creates a new internal stack state with at least minCap capacity.
/// @internal
function _newState(minCap)
  cap = _nextPow2(minCap)
  return [_allocArray(cap, 0), 0, cap, _STATE_TAG]
end function

/// Creates stack state from a legacy flat array payload.
/// @internal
function _stateFromArray(values)
  if typeof(values) != "array" then
    return _newState(8)
  end if

  n = len(values)
  st = _newState(n)
  if n <= 0 then
    return st
  end if

  buf = st[0]
  for i = 0 to(n - 1)
    buf[i] = values[i]
  end for
  st[0] = buf
  st[1] = n
  return st
end function

/// LIFO stack with geometric backing-array growth.
struct Stack
  /// Backing data owned by `Stack`.
  data

  /// Creates a new empty stack.
  static function new()
  return std.ds.stack.Stack(_newState(8))
end function

/// Creates a stack from an array (copies the array).
/// @param values Values to process.
static function fromArray(values)
return std.ds.stack.Stack(_stateFromArray(values))
end function

/// Ensures that this.data is in internal v2 state form.
/// @internal
function _ensureState()
  if _isState(this.data) then
    return this.data
  end if
  this.data = _stateFromArray(this.data)
  return this.data
end function

/// Grows internal capacity to at least minCap.
/// @internal
function _grow(minCap)
  st = this._ensureState()
  oldCap = st[2]
  if minCap <= oldCap then
    return
  end if

  newCap = _nextPow2(minCap)
  nb = _allocArray(newCap, 0)
  oldBuf = st[0]
  n = st[1]
  for i = 0 to(n - 1)
    nb[i] = oldBuf[i]
  end for

  st[0] = nb
  st[2] = newCap
  this.data = st
end function

/// Gets the number of elements.
function len()
  st = this._ensureState()
  return st[1]
end function

/// Checks whether the stack is empty.
function isEmpty()
  st = this._ensureState()
  return st[1] == 0
end function

/// Removes all elements.
function clear()
  st = this._ensureState()
  cap = st[2]
  st[0] = _allocArray(cap, 0)
  st[1] = 0
  this.data = st
end function

/// Pushes a value onto the stack.
/// @param value Value to process.
function push(value)
  st = this._ensureState()
  n = st[1]
  if n >= st[2] then
    this._grow(n + 1)
    st = this.data
    n = st[1]
  end if

  buf = st[0]
  buf[n] = value
  st[0] = buf
  st[1] = n + 1
  this.data = st
end function

/// Pushes all values from an array onto the stack (in order).
/// @param values Values to process.
function pushAll(values)
  if typeof(values) != "array" then
    return
  end if

  m = len(values)
  if m <= 0 then
    return
  end if

  st = this._ensureState()
  n = st[1]
  needed = n + m
  if needed > st[2] then
    this._grow(needed)
    st = this.data
    n = st[1]
  end if

  buf = st[0]
  for i = 0 to(m - 1)
    buf[n + i] = values[i]
  end for
  st[0] = buf
  st[1] = n + m
  this.data = st
end function

/// Peeks the top element without removing it.
function peek()
  st = this._ensureState()
  n = st[1]
  if n <= 0 then
    return
  end if
  buf = st[0]
  return buf[n - 1]
end function

/// Peeks the top element or returns a fallback.
/// @param fallbackValue Value supplied for `fallbackValue`.
function peekOr(fallbackValue)
  v = this.peek()
  if typeof(v) == "void" then
    return fallbackValue
  end if
  return v
end function

/// Pops the top element and returns it.
function pop()
  st = this._ensureState()
  n = st[1]
  if n <= 0 then
    return
  end if

  idx = n - 1
  buf = st[0]
  v = buf[idx]
  buf[idx] = 0
  st[0] = buf
  st[1] = idx
  this.data = st
  return v
end function

/// Pops the top element or returns a fallback.
/// @param fallbackValue Value supplied for `fallbackValue`.
function popOr(fallbackValue)
  v = this.pop()
  if typeof(v) == "void" then
    return fallbackValue
  end if
  return v
end function

/// Returns a shallow copy of the backing array.
function toArray()
  st = this._ensureState()
  n = st[1]
  vals = array(n)
  if n <= 0 then
    return vals
  end if

  buf = st[0]
  for i = 0 to(n - 1)
    vals[i] = buf[i]
  end for
  return vals
end function
end struct
