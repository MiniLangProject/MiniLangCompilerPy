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

package std.sort

// -----------------------------------------------------------------------------
// std.sort
// -----------------------------------------------------------------------------
// Provides:
// - sort(arr)                : stable in-place sort (insertion sort), ascending
// - sortBy(arr, lessFn)      : stable in-place sort with custom comparator
// - sortFast(arr)            : faster in-place sort (not guaranteed stable)
// - sortFastBy(arr, lessFn)  : faster in-place sort with custom comparator
//
// lessFn(a, b) should return:
// - bool: true if a should come before b
// - int : negative if a < b, zero if equal, positive if a > b
//
// All sort functions return the (sorted) array, or void on invalid input.
// -----------------------------------------------------------------------------

/*
stable in-place sort using the default comparator (ascending)
input: array arr
returns: array arr_sorted (or void on invalid input)
*/
function sort(arr)
  return sortBy(arr, __defaultLess)
end function

/*
stable in-place sort with a custom comparator (insertion sort)
input: array arr, function lessFn(a, b) -> bool|int
returns: array arr_sorted (or void on invalid input)
*/
function sortBy(arr, lessFn)
  if typeof(arr) != "array" then
    return
  end if

  n = len(arr)
  if n <= 1 then
    return arr
  end if

  // If caller didn't pass a function, fall back to default comparator.
  if typeof(lessFn) != "function" then
    lessFn = __defaultLess
  end if

  // Insertion sort (stable, in-place, non-recursive)
  i = 1
  while i < n
    key = arr[i]
    j = i - 1

    while j >= 0 and __less(key, arr[j], lessFn)
      arr[j + 1] = arr[j]
      j = j - 1
    end while

    arr[j + 1] = key
    i = i + 1
  end while

  return arr
end function

/*
faster in-place sort using the default comparator (ascending)
- uses an iterative quicksort with insertion-sort fallback for small ranges
- not guaranteed stable
input: array arr
returns: array arr_sorted (or void on invalid input)
*/
function sortFast(arr)
  return sortFastBy(arr, __defaultLess)
end function

/*
faster in-place sort with a custom comparator
- uses an iterative quicksort with insertion-sort fallback for small ranges
- not guaranteed stable
input: array arr, function lessFn(a, b) -> bool|int
returns: array arr_sorted (or void on invalid input)
*/
function sortFastBy(arr, lessFn)
  if typeof(arr) != "array" then
    return
  end if

  n = len(arr)
  if n <= 1 then
    return arr
  end if

  if typeof(lessFn) != "function" then
    lessFn = __defaultLess
  end if

  // Iterative quicksort with explicit stacks.
  // Use insertion sort for very small segments for speed.
  SMALL = 16

  loStack = __allocArray(n, 0)
  hiStack = __allocArray(n, 0)

  sp = 0
  loStack[sp] = 0
  hiStack[sp] = n - 1
  sp = sp + 1

  while sp > 0
    sp = sp - 1
    lo = loStack[sp]
    hi = hiStack[sp]

    // Small segment: insertion sort directly
    if (hi - lo) <= SMALL then
      __insertionSortRange(arr, lo, hi, lessFn)
    else
      // Partition
      p = __partition(arr, lo, hi, lessFn)

      // Left: [lo, p-1], Right: [p, hi]
      leftLo = lo
      leftHi = p - 1
      rightLo = p
      rightHi = hi

      leftSize = leftHi - leftLo
      rightSize = rightHi - rightLo

      // Push larger segment first to keep stack shallow.
      if leftSize > rightSize then
        if leftLo < leftHi then
          loStack[sp] = leftLo
          hiStack[sp] = leftHi
          sp = sp + 1
        end if
        if rightLo < rightHi then
          loStack[sp] = rightLo
          hiStack[sp] = rightHi
          sp = sp + 1
        end if
      else
        if rightLo < rightHi then
          loStack[sp] = rightLo
          hiStack[sp] = rightHi
          sp = sp + 1
        end if
        if leftLo < leftHi then
          loStack[sp] = leftLo
          hiStack[sp] = leftHi
          sp = sp + 1
        end if
      end if
    end if
  end while

  return arr
end function

/*
checks whether an array is sorted according to the given comparator
input: array arr, function lessFn(a, b) -> bool|int
returns: bool is_sorted (false on invalid input)
*/
function isSorted(arr, lessFn)
  if typeof(arr) != "array" then
    return false
  end if
  if typeof(lessFn) != "function" then
    lessFn = __defaultLess
  end if

  n = len(arr)
  if n <= 1 then
    return true
  end if

  for i = 1 to(n - 1)
    // if arr[i] < arr[i-1] then not sorted
    if __less(arr[i], arr[i - 1], lessFn) then
      return false
    end if
  end for
  return true
end function

/*
internal helper: comparator adapter (bool|int -> bool)
input: any a, any b, function lessFn
returns: bool a_before_b
*/
function __less(a, b, lessFn)
  r = lessFn(a, b)
  if typeof(r) == "bool" then
    return r
  end if
  if typeof(r) == "int" then
    return r < 0
  end if
  // If comparator returned something unexpected, fall back to default.
  return __defaultLess(a, b)
end function

/*
internal helper: default comparator (ascending)
input: any a, any b
returns: bool a_before_b
*/
function __defaultLess(a, b)
  return a < b
end function

/*
internal helper: allocate an array of length n filled with 'fill'
input: int n, any fill
returns: array arr (or void on invalid input)
*/
function __allocArray(n, fill)
  if typeof(n) != "int" then
    return
  end if
  if n < 0 then
    return
  end if
  return array(n, fill)
end function

/*
internal helper: swap two elements in an array
input: array arr, int i, int j
returns: void
*/
function __swap(arr, i, j)
  tmp = arr[i]
  arr[i] = arr[j]
  arr[j] = tmp
end function

/*
internal helper: partition for quicksort (Hoare-style)
input: array arr, int lo, int hi, function lessFn
returns: int split_index
*/
function __partition(arr, lo, hi, lessFn)
  // Middle pivot
  pivot = arr[(lo + hi) / 2]
  i = lo
  j = hi

  while i <= j
    while __less(arr[i], pivot, lessFn)
      i = i + 1
    end while

    while __less(pivot, arr[j], lessFn)
      j = j - 1
    end while

    if i <= j then
      __swap(arr, i, j)
      i = i + 1
      j = j - 1
    end if
  end while

  // i is the first index of the right partition
  return i
end function

/*
internal helper: insertion sort for a slice [lo..hi]
input: array arr, int lo, int hi, function lessFn
returns: void
*/
function __insertionSortRange(arr, lo, hi, lessFn)
  i = lo + 1
  while i <= hi
    key = arr[i]
    j = i - 1

    while j >= lo and __less(key, arr[j], lessFn)
      arr[j + 1] = arr[j]
      j = j - 1
    end while

    arr[j + 1] = key
    i = i + 1
  end while
end function

