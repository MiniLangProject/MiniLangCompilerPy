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

package std.ds.stack

/*
std.ds.stack

Simple LIFO stack implemented with an internal growable buffer.

Notes:
- push/pop are amortized O(1).
- Methods keep compatibility with legacy Stack([...]) constructor payloads.
*/

const _STATE_TAG = "__std.ds.stack.v2__"

/*
allocates an array of length n filled with `fill`
input: int n, any fill
returns: array output (or void on invalid input)
*/
function _allocArray(n, fill)
  if typeof(n) != "int" then
    return
  end if
  if n < 0 then
    return
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

/*
checks whether data is a valid v2 stack state
shape: [buf(array), size(int), cap(int), tag]
*/
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

/*
creates a new internal stack state with at least minCap capacity
input: int minCap
returns: array state
*/
function _newState(minCap)
  cap = _nextPow2(minCap)
  return [_allocArray(cap, 0), 0, cap, _STATE_TAG]
end function

/*
creates stack state from a legacy flat array payload
input: array values
returns: array state
*/
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

struct Stack
  data

  /*
  creates a new empty stack
  input: (none)
  returns: Stack emptyStack
  */
  static function new()
  return std.ds.stack.Stack(_newState(8))
end function

/*
creates a stack from an array (copies the array)
input: array values
returns: Stack stack
*/
static function fromArray(values)
return std.ds.stack.Stack(_stateFromArray(values))
end function

/*
ensures that this.data is in internal v2 state form
input: (none)
returns: array state
*/
function _ensureState()
  if _isState(this.data) then
    return this.data
  end if
  this.data = _stateFromArray(this.data)
  return this.data
end function

/*
grows internal capacity to at least minCap
input: int minCap
returns: void
*/
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

/*
gets the number of elements
input: (none)
returns: int count
*/
function len()
  st = this._ensureState()
  return st[1]
end function

/*
checks whether the stack is empty
input: (none)
returns: bool empty
*/
function isEmpty()
  st = this._ensureState()
  return st[1] == 0
end function

/*
removes all elements
input: (none)
returns: void
*/
function clear()
  st = this._ensureState()
  cap = st[2]
  st[0] = _allocArray(cap, 0)
  st[1] = 0
  this.data = st
end function

/*
pushes a value onto the stack
input: any value
returns: void
*/
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

/*
pushes all values from an array onto the stack (in order)
input: array values
returns: void
*/
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

/*
peeks the top element without removing it
input: (none)
returns: any topValue (or void if empty)
*/
function peek()
  st = this._ensureState()
  n = st[1]
  if n <= 0 then
    return
  end if
  buf = st[0]
  return buf[n - 1]
end function

/*
peeks the top element or returns a fallback
input: any fallbackValue
returns: any topOrFallback
*/
function peekOr(fallbackValue)
  v = this.peek()
  if typeof(v) == "void" then
    return fallbackValue
  end if
  return v
end function

/*
pops the top element and returns it
input: (none)
returns: any poppedValue (or void if empty)
*/
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

/*
pops the top element or returns a fallback
input: any fallbackValue
returns: any poppedOrFallback
*/
function popOr(fallbackValue)
  v = this.pop()
  if typeof(v) == "void" then
    return fallbackValue
  end if
  return v
end function

/*
returns a shallow copy of the backing array
input: (none)
returns: array values
*/
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
