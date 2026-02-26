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

package std.array

// ------------------------------------------------------------
// std.array
// Common helpers for MiniLang arrays.
// Indexing is 0-based (see README).
// ------------------------------------------------------------

/*
checks whether a value is an array
input: any x
returns: bool is_array
*/
function isArray(x)
  return typeof(x) == "array"
end function

/*
creates a shallow copy of an array
input: array a
returns: array copy (or void on invalid input)
*/
function copy(a)
  if typeof(a) != "array" then
    return
  end if

  n = len(a)
  val =[]
  if n <= 0 then
    return val
  end if

  for i = 0 to(n - 1)
    val = val +[a[i]]
  end for
  return val
end function

/*
returns a slice of an array with strict bounds
- supports negative offsets (like Python): offset < 0 means "from end"
input: array a, int offset, int length
returns: array slice (or void on invalid input / out-of-bounds)
*/
function slice(a, offset, length)
  if typeof(a) != "array" then
    return
  end if
  if typeof(offset) != "int" then
    return
  end if
  if typeof(length) != "int" then
    return
  end if

  n = len(a)
  off = offset
  if off < 0 then
    off = off + n
  end if

  // strict bounds (like bytes.slice)
  if off < 0 then
    return
  end if
  if length < 0 then
    return
  end if
  if off > n then
    return
  end if
  if off + length > n then
    return
  end if

  val =[]
  if length == 0 then
    return val
  end if

  for i = 0 to(length - 1)
    val = val +[a[off + i]]
  end for
  return val
end function

/*
finds the first index of a value in an array starting at 'start'
input: array a, any value, int start
returns: int index (>=0) or -1 if not found (or void on invalid input)
*/
function indexOf(a, value, start)
  if typeof(a) != "array" then
    return
  end if
  if typeof(start) != "int" then
    return
  end if

  n = len(a)
  i0 = start
  if i0 < 0 then
    i0 = 0
  end if
  if i0 > n then
    i0 = n
  end if

  for i = i0 to(n - 1)
    if a[i] == value then
      return i
    end if
  end for
  return -1
end function

/*
finds the last index of a value in an array
input: array a, any value
returns: int index (>=0) or -1 if not found (or void on invalid input)
*/
function lastIndexOf(a, value)
  if typeof(a) != "array" then
    return
  end if

  n = len(a)
  if n <= 0 then
    return -1
  end if

  i = n - 1
  while i >= 0
    if a[i] == value then
      return i
    end if
    i = i - 1
  end while
  return -1
end function

/*
checks whether an array contains a value
input: array a, any value
returns: bool contains (false on invalid input)
*/
function contains(a, value)
  if typeof(a) != "array" then
    return false
  end if
  // NOTE: In package files, declarations are registered as fully-qualified
  // names (e.g. std.array.indexOf). Use fully-qualified calls.
  return std.array.indexOf(a, value, 0) >= 0
end function

/*
applies a function to every element and returns a new array
input: array a, function fn(element) -> any
returns: array mapped (or void on invalid input)
*/
function map(a, fn)
  if typeof(a) != "array" then
    return
  end if
  if typeof(fn) != "function" then
    return
  end if

  n = len(a)
  val =[]
  if n <= 0 then
    return val
  end if

  for i = 0 to(n - 1)
    val = val +[fn(a[i])]
  end for
  return val
end function

/*
filters elements by predicate and returns a new array
input: array a, function pred(element) -> bool
returns: array filtered (or void on invalid input)
*/
function filter(a, pred)
  if typeof(a) != "array" then
    return
  end if
  if typeof(pred) != "function" then
    return
  end if

  n = len(a)
  val =[]
  if n <= 0 then
    return val
  end if

  for i = 0 to(n - 1)
    v = a[i]
    if pred(v) then
      val = val +[v]
    end if
  end for
  return val
end function

/*
reduces an array to a single value using an accumulator function
input: array arr, function f(acc, element) -> any, any init
returns: any reduced_value (or void on invalid input)
*/
function reduce(arr, f, init)
  if typeof(arr) != "array" then
    return
  end if
  if typeof(f) != "function" then
    return
  end if

  acc = init
  for i = 0 to(len(arr) - 1)
    acc = f(acc, arr[i])
  end for
  return acc
end function

/*
returns true if any element satisfies the predicate
input: array a, function pred(element) -> bool
returns: bool any_true (false on invalid input)
*/
function any(a, pred)
  if typeof(a) != "array" then
    return false
  end if
  if typeof(pred) != "function" then
    return false
  end if

  n = len(a)
  for i = 0 to(n - 1)
    if pred(a[i]) then
      return true
    end if
  end for
  return false
end function

/*
returns true if all elements satisfy the predicate
input: array a, function pred(element) -> bool
returns: bool all_true (false on invalid input)
*/
function all(a, pred)
  if typeof(a) != "array" then
    return false
  end if
  if typeof(pred) != "function" then
    return false
  end if

  n = len(a)
  for i = 0 to(n - 1)
    if not pred(a[i]) then
      return false
    end if
  end for
  return true
end function

/*
joins an array of strings using a separator
input: array a (strings), string sep
returns: string joined (or void on invalid input)
*/
function joinStrings(a, sep)
  if typeof(a) != "array" then
    return
  end if
  if typeof(sep) != "string" then
    return
  end if

  n = len(a)
  if n <= 0 then
    return ""
  end if

  val = ""
  for i = 0 to(n - 1)
    if typeof(a[i]) != "string" then
      return
    end if
    if i > 0 then
      val = val + sep
    end if
    val = val + a[i]
  end for
  return val
end function

/*
returns the number of elements in the array
input: array a
returns: int length (or void on invalid input)
*/
function length(a)
  if typeof(a) != "array" then
    return
  end if
  return len(a)
end function

/*
returns true if an array is empty
input: array a
returns: bool is_empty (false on invalid input)
*/
function isEmpty(a)
  if typeof(a) != "array" then
    return false
  end if
  return len(a) == 0
end function

/*
returns the first element of an array
input: array a
returns: any first (or void if invalid input or empty)
*/
function first(a)
  if typeof(a) != "array" then
    return
  end if
  if len(a) <= 0 then
    return
  end if
  return a[0]
end function

/*
returns the last element of an array
input: array a
returns: any last (or void if invalid input or empty)
*/
function last(a)
  if typeof(a) != "array" then
    return
  end if
  n = len(a)
  if n <= 0 then
    return
  end if
  return a[n - 1]
end function

/*
appends a value to an array and returns a new array
input: array a, any value
returns: array new_array (or void on invalid input)
*/
function append(a, value)
  if typeof(a) != "array" then
    return
  end if
  return a +[value]
end function

/*
concatenates two arrays and returns a new array
input: array a, array b
returns: array combined (or void on invalid input)
*/
function concat(a, b)
  if typeof(a) != "array" then
    return
  end if
  if typeof(b) != "array" then
    return
  end if

  // Copy 'a' first, then append elements of 'b'.
  val = std.array.copy(a)
  for i = 0 to(len(b) - 1)
    val = val +[b[i]]
  end for
  return val
end function

