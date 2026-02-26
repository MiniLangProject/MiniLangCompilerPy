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

package std.ds.queue

// ------------------------------------------------------------
// std.ds.queue
// FIFO queue implemented as a circular buffer (ring buffer).
//
// - enqueue/dequeue are O(1) amortized.
// - Capacity grows by powers of two.
// ------------------------------------------------------------

/*
allocates an array of length n filled with `fill`
input: int n, any fill
returns: array output
*/
function _allocArray(n, fill)
  output =[]
  if typeof(n) != "int" then
    return
  end if
  if n <= 0 then
    return output
  end if
  for i = 1 to n
    output = output +[fill]
  end for
  return output
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

struct Queue
  buf
  head
  tail
  size
  cap

  /*
  creates a new queue with default capacity
  input: (none)
  returns: Queue q
  */
  static function new()
  return Queue.withCapacity(8)
end function

/*
creates a new queue with at least `minCap` capacity
input: int minCap
returns: Queue q
*/
static function withCapacity(minCap)
c = _nextPow2(minCap)
b = _allocArray(c, 0)
return Queue(b, 0, 0, 0, c)
end function

/*
returns the number of elements
input: (none)
returns: int length
*/
function len()
  return this.size
end function

/*
checks whether the queue is empty
input: (none)
returns: bool empty
*/
function isEmpty()
  return this.size == 0
end function

/*
removes all items (keeps capacity)
input: (none)
returns: void
*/
function clear()
  this.head = 0
  this.tail = 0
  this.size = 0
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
    mask = this.cap - 1
    for i = 0 to(this.size - 1)
      nb[i] = this.buf[(this.head + i) & mask]
    end for
  end if

  this.buf = nb
  this.head = 0
  this.tail = this.size
  this.cap = c2
end function

/*
adds an element to the back of the queue
input: any v
returns: void
*/
function enqueue(v)
  if this.size == this.cap then
    this._grow(this.cap << 1)
  end if

  this.buf[this.tail] = v
  this.tail =(this.tail + 1) &(this.cap - 1)
  this.size = this.size + 1
end function

/*
returns the front element without removing it
input: (none)
returns: any value (or void if empty)
*/
function peek()
  if this.size == 0 then
    return
  end if
  return this.buf[this.head]
end function

/*
removes and returns the front element
input: (none)
returns: any value (or void if empty)
*/
function dequeue()
  if this.size == 0 then
    return
  end if

  v = this.buf[this.head]
  // optional: clear slot
  this.buf[this.head] = 0

  this.head =(this.head + 1) &(this.cap - 1)
  this.size = this.size - 1
  return v
end function

/*
returns a snapshot of the queue contents (front -> back)
input: (none)
returns: array values
*/
function toArray()
  output =[]
  if this.size == 0 then
    return output
  end if

  mask = this.cap - 1
  for i = 0 to(this.size - 1)
    output = output +[this.buf[(this.head + i) & mask]]
  end for
  return output
end function
end struct

