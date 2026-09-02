/*
   Copyright 2026 Nils Kopal
   Licensed under the Apache License, Version 2.0.
*/

//! Provides the std ds concurrent_list package.

package std.ds.concurrent_list

import std.threading as threading

/// A growable list whose managed backing array lives in the process-wide GC heap. Every public operation is serialized by a recursive Lock, so arbitrary MiniLang values (including arrays and structs) retain identity across threads.
const DEFAULT_CAPACITY = 8

/// Choose a geometric capacity large enough for the requested item count.
/// @internal
function _nextCapacity(value)
  capacity = DEFAULT_CAPACITY
  while capacity < value
    capacity = capacity << 1
  end while
  return capacity
end function

/// Allocate a backing array or the canonical empty array.
/// @internal
function _newBuffer(capacity)
  if capacity <= 0 then return [] end if
  return array(capacity)
end function

/// Lock-protected growable list whose values remain shared-heap objects.
struct ThreadSafeList
  /// Stores the guard member of `ThreadSafeList`.
  guard
  /// Stores the buf member of `ThreadSafeList`.
  buf
  /// Stores the size member of `ThreadSafeList`.
  size
  /// Stores the capacity member of `ThreadSafeList`.
  capacity
  /// Stores the closed member of `ThreadSafeList`.
  closed

  /// Create an empty list with the default initial capacity.
  static function new()
    return ThreadSafeList.withCapacity(DEFAULT_CAPACITY)
  end function

  /// Create an empty list preallocated for at least minimumCapacity items.
  /// @param minimumCapacity Value supplied for `minimumCapacity`.
  static function withCapacity(minimumCapacity)
    if typeof(minimumCapacity) != "int" or minimumCapacity < 0 then
      return error(1610, "list capacity must be a non-negative integer")
    end if
    guard = threading.Lock.new()
    capacity = _nextCapacity(minimumCapacity)
    return ThreadSafeList(guard, _newBuffer(capacity), 0, capacity, false)
  end function

  /// Copy an ordinary array into a new synchronized list.
  /// @param values Values to process.
  static function fromArray(values)
    if typeof(values) != "array" then
      return error(1610, "ThreadSafeList.fromArray expects an array")
    end if
    output = ThreadSafeList.withCapacity(len(values))
    i = 0
    while i < len(values)
      output.add(values[i])
      i = i + 1
    end while
    return output
  end function

  /// Grow the backing buffer; callers must already hold guard.
  /// @internal
  function _growLocked(minimumCapacity)
    if minimumCapacity <= this.capacity then return true end if
    newCapacity = _nextCapacity(minimumCapacity)
    newBuffer = _newBuffer(newCapacity)
    i = 0
    while i < this.size
      newBuffer[i] = this.buf[i]
      i = i + 1
    end while
    this.buf = newBuffer
    this.capacity = newCapacity
    return true
  end function

  /// Return a synchronized snapshot of the current item count.
  function len()
    if not this.guard.acquire() then return 0 end if
    result = 0
    if not this.closed then result = this.size end if
    this.guard.release()
    return result
  end function

  /// Alias for len().
  function count()
    return this.len()
  end function

  /// Report whether the synchronized item count is zero.
  function isEmpty()
    return this.len() == 0
  end function

  /// Report whether the collection has released its native lock.
  function isClosed()
    return this.closed
  end function

  /// Preallocate space without changing the logical length.
  /// @param minimumCapacity Value supplied for `minimumCapacity`.
  function reserve(minimumCapacity)
    if typeof(minimumCapacity) != "int" or minimumCapacity < 0 then return false end if
    if not this.guard.acquire() then return false end if
    ok = false
    if not this.closed then ok = this._growLocked(minimumCapacity) end if
    this.guard.release()
    return ok
  end function

  /// Append one managed value under the list lock.
  /// @param value Value to process.
  function add(value)
    if not this.guard.acquire() then return false end if
    if this.closed then
      this.guard.release()
      return false
    end if
    this._growLocked(this.size + 1)
    this.buf[this.size] = value
    this.size = this.size + 1
    this.guard.release()
    return true
  end function

  /// Stack-style alias for add().
  /// @param value Value to process.
  function push(value)
    return this.add(value)
  end function

  /// Append all values atomically with respect to other list operations.
  /// @param values Values to process.
  function addAll(values)
    if typeof(values) != "array" then return false end if
    if not this.guard.acquire() then return false end if
    if this.closed then
      this.guard.release()
      return false
    end if
    this._growLocked(this.size + len(values))
    i = 0
    while i < len(values)
      this.buf[this.size] = values[i]
      this.size = this.size + 1
      i = i + 1
    end while
    this.guard.release()
    return true
  end function

  /// Return the value at index, or void for invalid/closed access.
  /// @param index Zero-based item index.
  function get(index)
    if typeof(index) != "int" then return end if
    if not this.guard.acquire() then return end if
    if this.closed or index < 0 or index >= this.size then
      this.guard.release()
      return
    end if
    result = this.buf[index]
    this.guard.release()
    return result
  end function

  /// Replace an existing slot and report whether the write succeeded.
  /// @param index Zero-based item index.
  /// @param value Value to process.
  function set(index, value)
    if typeof(index) != "int" then return false end if
    if not this.guard.acquire() then return false end if
    if this.closed or index < 0 or index >= this.size then
      this.guard.release()
      return false
    end if
    this.buf[index] = value
    this.guard.release()
    return true
  end function

  /// Return the first value, or void when empty.
  function first()
    return this.get(0)
  end function

  /// Return the last value, or void when empty.
  function last()
    if not this.guard.acquire() then return end if
    if this.closed or this.size == 0 then
      this.guard.release()
      return
    end if
    result = this.buf[this.size - 1]
    this.guard.release()
    return result
  end function

  /// Insert before index while preserving the order of following values.
  /// @param index Zero-based item index.
  /// @param value Value to process.
  function insert(index, value)
    if typeof(index) != "int" then return false end if
    if not this.guard.acquire() then return false end if
    if this.closed or index < 0 or index > this.size then
      this.guard.release()
      return false
    end if
    this._growLocked(this.size + 1)
    i = this.size
    while i > index
      this.buf[i] = this.buf[i - 1]
      i = i - 1
    end while
    this.buf[index] = value
    this.size = this.size + 1
    this.guard.release()
    return true
  end function

  /// Remove and return one indexed value, shifting the tail left.
  /// @param index Zero-based item index.
  function removeAt(index)
    if typeof(index) != "int" then return end if
    if not this.guard.acquire() then return end if
    if this.closed or index < 0 or index >= this.size then
      this.guard.release()
      return
    end if
    result = this.buf[index]
    i = index
    while i + 1 < this.size
      this.buf[i] = this.buf[i + 1]
      i = i + 1
    end while
    this.size = this.size - 1
    this.buf[this.size] = 0
    this.guard.release()
    return result
  end function

  /// Remove and return the last value, or void when empty.
  function pop()
    if not this.guard.acquire() then return end if
    if this.closed or this.size == 0 then
      this.guard.release()
      return
    end if
    index = this.size - 1
    result = this.buf[index]
    this.buf[index] = 0
    this.size = index
    this.guard.release()
    return result
  end function

  /// Pop the last value or return fallback when no value is available.
  /// @param fallback Value supplied for `fallback`.
  function popOr(fallback)
    value = this.pop()
    if typeof(value) == "void" then return fallback end if
    return value
  end function

  /// Drop references to all values while retaining the backing capacity.
  function clear()
    if not this.guard.acquire() then return false end if
    if this.closed then
      this.guard.release()
      return false
    end if
    i = 0
    while i < this.size
      this.buf[i] = 0
      i = i + 1
    end while
    this.size = 0
    this.guard.release()
    return true
  end function

  /// Copy a consistent snapshot into an ordinary managed array.
  function toArray()
    if not this.guard.acquire() then return [] end if
    if this.closed then
      this.guard.release()
      return []
    end if
    output = array(this.size)
    i = 0
    while i < this.size
      output[i] = this.buf[i]
      i = i + 1
    end while
    this.guard.release()
    return output
  end function

  /// Clear storage and release the native lock after all users have stopped.
  function close()
    if this.closed or not this.guard.acquire() then return false end if
    this.buf = []
    this.size = 0
    this.capacity = 0
    this.closed = true
    this.guard.release()
    this.guard.close()
    return true
  end function
end struct
