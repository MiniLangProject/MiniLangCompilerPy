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

import std.array as arr

/*
std.ds.stack

Simple LIFO stack implemented on top of arrays.

Notes:
- push/pop are O(n) because arrays are immutable in size (we rebuild via slice/+).
- Intended for small/medium workloads and algorithmic convenience.
*/

struct Stack
  data

  /*
  creates a new empty stack
  input: (none)
  returns: Stack emptyStack
  */
  static function new()
  return std.ds.stack.Stack([])
end function

/*
creates a stack from an array (copies the array)
input: array values
returns: Stack stack
*/
static function fromArray(values)
if typeof(values) != "array" then
  return std.ds.stack.Stack([])
end if
return std.ds.stack.Stack(arr.copy(values))
end function

/*
gets the number of elements
input: (none)
returns: int count
*/
function len()
  return len(this.data)
end function

/*
checks whether the stack is empty
input: (none)
returns: bool empty
*/
function isEmpty()
  return len(this.data) == 0
end function

/*
removes all elements
input: (none)
returns: void
*/
function clear()
  this.data =[]
end function

/*
pushes a value onto the stack
input: any value
returns: void
*/
function push(value)
  this.data = this.data +[value]
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

  // append preserving order
  for each v in values
    this.data = this.data +[v]
  end for
end function

/*
peeks the top element without removing it
input: (none)
returns: any topValue (or void if empty)
*/
function peek()
  n = len(this.data)
  if n <= 0 then
    return
  end if
  return this.data[n - 1]
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
  n = len(this.data)
  if n <= 0 then
    return
  end if

  v = this.data[n - 1]
  if n == 1 then
    this.data =[]
  else
    this.data = arr.slice(this.data, 0, n - 1)
  end if
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
  return arr.copy(this.data)
end function
end struct

