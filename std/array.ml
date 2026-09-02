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

//! Provides the std array package.

package std.array

import std.string as s

// ------------------------------------------------------------
// std.array
// Common helpers for MiniLang arrays.
// Indexing is 0-based (see README).
// ------------------------------------------------------------

/// Checks whether a value is an array.
/// @param x Value supplied for `x`.
function isArray(x)
  return typeof(x) == "array"
end function

/// Creates a shallow copy of an array.
/// @param a First input value.
function copy(a)
  if typeof(a) != "array" then
    return
  end if

  n = len(a)
  val = array(n)
  if n <= 0 then
    return val
  end if

  for i = 0 to(n - 1)
    val[i] = a[i]
  end for
  return val
end function

/// Returns a slice of an array with strict bounds - supports negative offsets (like Python): offset < 0 means "from end".
/// @param a First input value.
/// @param offset Zero-based starting offset.
/// @param length Number of elements or bytes to process.
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

  val = array(length)
  if length == 0 then
    return val
  end if

  for i = 0 to(length - 1)
    val[i] = a[off + i]
  end for
  return val
end function

/// Finds the first index of a value in an array starting at 'start'.
/// @param a First input value.
/// @param value Value to process.
/// @param start Value supplied for `start`.
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

/// Finds the last index of a value in an array.
/// @param a First input value.
/// @param value Value to process.
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

/// Checks whether an array contains a value.
/// @param a First input value.
/// @param value Value to process.
function contains(a, value)
  if typeof(a) != "array" then
    return false
  end if
  // NOTE: In package files, declarations are registered as fully-qualified
  // names (e.g. std.array.indexOf). Use fully-qualified calls.
  return std.array.indexOf(a, value, 0) >= 0
end function

/// Applies a function to every element and returns a new array.
/// @param a First input value.
/// @param fn Function invoked by the operation.
function map(a, fn)
  if typeof(a) != "array" then
    return
  end if
  if typeof(fn) != "function" then
    return
  end if

  n = len(a)
  val = array(n)
  if n <= 0 then
    return val
  end if

  for i = 0 to(n - 1)
    val[i] = fn(a[i])
  end for
  return val
end function

/// Filters elements by predicate and returns a new array.
/// @param a First input value.
/// @param pred Predicate applied to each candidate value.
function filter(a, pred)
  if typeof(a) != "array" then
    return
  end if
  if typeof(pred) != "function" then
    return
  end if

  n = len(a)
  if n <= 0 then
    return []
  end if

  tmp = array(n)
  count = 0
  for i = 0 to(n - 1)
    v = a[i]
    if pred(v) then
      tmp[count] = v
      count = count + 1
    end if
  end for

  if count == 0 then
    return []
  end if
  if count == n then
    return tmp
  end if
  return std.array.slice(tmp, 0, count)
end function

/// Reduces an array to a single value using an accumulator function.
/// @param arr Value supplied for `arr`.
/// @param f Function invoked by the operation.
/// @param init Value supplied for `init`.
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

/// Returns true if any element satisfies the predicate.
/// @param a First input value.
/// @param pred Predicate applied to each candidate value.
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

/// Returns true if all elements satisfy the predicate.
/// @param a First input value.
/// @param pred Predicate applied to each candidate value.
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

/// Joins an array of strings using a separator.
/// @param a First input value.
/// @param sep Value supplied for `sep`.
function joinStrings(a, sep)
  if typeof(a) != "array" then
    return
  end if
  if typeof(sep) != "string" then
    return
  end if

  return stringJoin(a, sep)
end function

/// Returns the number of elements in the array.
/// @param a First input value.
function length(a)
  if typeof(a) != "array" then
    return
  end if
  return len(a)
end function

/// Returns true if an array is empty.
/// @param a First input value.
function isEmpty(a)
  if typeof(a) != "array" then
    return false
  end if
  return len(a) == 0
end function

/// Returns the first element of an array.
/// @param a First input value.
function first(a)
  if typeof(a) != "array" then
    return
  end if
  if len(a) <= 0 then
    return
  end if
  return a[0]
end function

/// Returns the last element of an array.
/// @param a First input value.
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

/// Appends a value to an array and returns a new array.
/// @param a First input value.
/// @param value Value to process.
function append(a, value)
  if typeof(a) != "array" then
    return
  end if

  n = len(a)
  val = array(n + 1)
  if n > 0 then
    for i = 0 to(n - 1)
      val[i] = a[i]
    end for
  end if
  val[n] = value
  return val
end function

/// Concatenates two arrays and returns a new array.
/// @param a First input value.
/// @param b Second input value.
function concat(a, b)
  if typeof(a) != "array" then
    return
  end if
  if typeof(b) != "array" then
    return
  end if

  n1 = len(a)
  n2 = len(b)
  val = array(n1 + n2)

  for i = 0 to(n1 - 1)
    val[i] = a[i]
  end for

  for i = 0 to(n2 - 1)
    val[n1 + i] = b[i]
  end for
  return val
end function

