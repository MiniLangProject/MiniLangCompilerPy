/*
   Copyright 2026 Nils Kopal
   Licensed under the Apache License, Version 2.0.
*/

package std.ds.concurrent_hashmap

import std.threading as threading

// A Lock-protected open-addressing hash map in the process-wide managed heap.
// Keys remain int/string/bytes; values may be arbitrary MiniLang object graphs.

const DEFAULT_BUCKETS = 64

// Return a power-of-two bucket count suitable for masked probing.
function _nextBuckets(value)
  count = 16
  while count < value
    count = count << 1
  end while
  return count
end function

// Allocate a zero-filled bucket array.
function _newArray(size)
  if size <= 0 then return [] end if
  return array(size, 0)
end function

// Avalanche integer keys into a stable unsigned 32-bit hash.
function _mix32(value)
  h = value & 0xFFFFFFFF
  h = h ^ (h >> 16)
  h = (h * 0x7feb352d) & 0xFFFFFFFF
  h = h ^ (h >> 15)
  h = (h * 0x846ca68b) & 0xFFFFFFFF
  h = h ^ (h >> 16)
  return h & 0xFFFFFFFF
end function

// Keep equality and hashing semantics limited to immutable key categories.
function _keySupported(key)
  t = typeof(key)
  return t == "int" or t == "string" or t == "bytes"
end function

// Dispatch to the deterministic hash implementation for each key type.
function _hashKey(key)
  t = typeof(key)
  if t == "int" then return _mix32(key) end if
  if t == "string" then return stringHash(key) end if
  if t == "bytes" then return bytesHash(key) end if
  return -1
end function

// states: 0=empty, 1=used, 2=tombstone
function _findSlot(keys, states, capacity, key, forInsert)
  index = _hashKey(key) & (capacity - 1)
  firstTombstone = -1
  scanned = 0
  while scanned < capacity
    state = states[index]
    if state == 0 then
      if forInsert and firstTombstone >= 0 then return firstTombstone end if
      if forInsert then return index end if
      return -1
    end if
    if state == 1 and keys[index] == key then return index end if
    if state == 2 and forInsert and firstTombstone < 0 then firstTombstone = index end if
    index = (index + 1) & (capacity - 1)
    scanned = scanned + 1
  end while
  return firstTombstone
end function

// Detached key/value snapshot returned by entriesArray().
struct Entry
  key
  value
end struct

// Lock-protected open-addressing map for shared managed values.
struct ThreadSafeHashMap
  guard
  bucketCount
  size
  keys
  values
  states
  closed

  // Create a map with the default bucket count.
  static function new()
    return ThreadSafeHashMap.withCapacity(DEFAULT_BUCKETS)
  end function

  // Create a map with at least the requested power-of-two capacity.
  static function withCapacity(minimumBuckets)
    if typeof(minimumBuckets) != "int" or minimumBuckets < 0 then
      return error(1620, "hash map capacity must be a non-negative integer")
    end if
    guard = threading.Lock.new()
    bucketCount = _nextBuckets(minimumBuckets)
    return ThreadSafeHashMap(guard, bucketCount, 0, _newArray(bucketCount), _newArray(bucketCount), _newArray(bucketCount), false)
  end function

  // Rebuild live entries into a larger table; guard must already be held.
  function _rehashLocked(minimumBuckets)
    newCount = _nextBuckets(minimumBuckets)
    newKeys = _newArray(newCount)
    newValues = _newArray(newCount)
    newStates = _newArray(newCount)
    i = 0
    while i < this.bucketCount
      if this.states[i] == 1 then
        index = _findSlot(newKeys, newStates, newCount, this.keys[i], true)
        newKeys[index] = this.keys[i]
        newValues[index] = this.values[i]
        newStates[index] = 1
      end if
      i = i + 1
    end while
    this.bucketCount = newCount
    this.keys = newKeys
    this.values = newValues
    this.states = newStates
  end function

  // Return a synchronized snapshot of the live entry count.
  function count()
    if not this.guard.acquire() then return 0 end if
    result = 0
    if not this.closed then result = this.size end if
    this.guard.release()
    return result
  end function

  // Alias for count().
  function len()
    return this.count()
  end function

  // Report whether the map contains no live entries.
  function isEmpty()
    return this.count() == 0
  end function

  // Report whether storage and its native lock have been released.
  function isClosed()
    return this.closed
  end function

  // Insert or replace one key/value pair atomically.
  function set(key, value)
    if not _keySupported(key) or not this.guard.acquire() then return false end if
    if this.closed then
      this.guard.release()
      return false
    end if
    if (this.size + 1) * 10 >= this.bucketCount * 7 then
      this._rehashLocked(this.bucketCount << 1)
    end if
    index = _findSlot(this.keys, this.states, this.bucketCount, key, true)
    if index < 0 then
      this.guard.release()
      return false
    end if
    if this.states[index] != 1 then
      this.keys[index] = key
      this.states[index] = 1
      this.size = this.size + 1
    end if
    this.values[index] = value
    this.guard.release()
    return true
  end function

  // Test whether a supported key is present.
  function has(key)
    if not _keySupported(key) or not this.guard.acquire() then return false end if
    result = false
    if not this.closed then
      result = _findSlot(this.keys, this.states, this.bucketCount, key, false) >= 0
    end if
    this.guard.release()
    return result
  end function

  // Return a key's value, or void when absent or unavailable.
  function get(key)
    if not _keySupported(key) or not this.guard.acquire() then return end if
    if this.closed then
      this.guard.release()
      return
    end if
    index = _findSlot(this.keys, this.states, this.bucketCount, key, false)
    if index < 0 then
      this.guard.release()
      return
    end if
    result = this.values[index]
    this.guard.release()
    return result
  end function

  // Return a key's value or the caller-supplied fallback.
  function getOr(key, fallback)
    if not _keySupported(key) or not this.guard.acquire() then return fallback end if
    if this.closed then
      this.guard.release()
      return fallback
    end if
    index = _findSlot(this.keys, this.states, this.bucketCount, key, false)
    if index < 0 then
      this.guard.release()
      return fallback
    end if
    result = this.values[index]
    this.guard.release()
    return result
  end function

  // Atomically add delta to an integer value, inserting delta when absent.
  function increment(key, delta)
    if not _keySupported(key) or typeof(delta) != "int" then return end if
    if not this.guard.acquire() then return end if
    if this.closed then
      this.guard.release()
      return
    end if
    index = _findSlot(this.keys, this.states, this.bucketCount, key, false)
    if index < 0 then
      if (this.size + 1) * 10 >= this.bucketCount * 7 then
        this._rehashLocked(this.bucketCount << 1)
      end if
      index = _findSlot(this.keys, this.states, this.bucketCount, key, true)
      this.keys[index] = key
      this.values[index] = delta
      this.states[index] = 1
      this.size = this.size + 1
      this.guard.release()
      return delta
    end if
    oldValue = this.values[index]
    if typeof(oldValue) != "int" then
      this.guard.release()
      return
    end if
    result = oldValue + delta
    this.values[index] = result
    this.guard.release()
    return result
  end function

  // Remove a live key and leave a tombstone for the probe chain.
  function remove(key)
    if not _keySupported(key) or not this.guard.acquire() then return false end if
    if this.closed then
      this.guard.release()
      return false
    end if
    index = _findSlot(this.keys, this.states, this.bucketCount, key, false)
    if index < 0 then
      this.guard.release()
      return false
    end if
    this.states[index] = 2
    this.keys[index] = 0
    this.values[index] = 0
    this.size = this.size - 1
    this.guard.release()
    return true
  end function

  // Alias for remove().
  function delete(key)
    return this.remove(key)
  end function

  // Replace all bucket arrays while retaining the current capacity.
  function clear()
    if not this.guard.acquire() then return false end if
    if this.closed then
      this.guard.release()
      return false
    end if
    this.keys = _newArray(this.bucketCount)
    this.values = _newArray(this.bucketCount)
    this.states = _newArray(this.bucketCount)
    this.size = 0
    this.guard.release()
    return true
  end function

  // Copy a consistent snapshot of all live keys.
  function keysArray()
    if not this.guard.acquire() then return [] end if
    if this.closed then
      this.guard.release()
      return []
    end if
    output = array(this.size)
    outputIndex = 0
    i = 0
    while i < this.bucketCount
      if this.states[i] == 1 then
        output[outputIndex] = this.keys[i]
        outputIndex = outputIndex + 1
      end if
      i = i + 1
    end while
    this.guard.release()
    return output
  end function

  // Copy a consistent snapshot of all live values.
  function valuesArray()
    if not this.guard.acquire() then return [] end if
    if this.closed then
      this.guard.release()
      return []
    end if
    output = array(this.size)
    outputIndex = 0
    i = 0
    while i < this.bucketCount
      if this.states[i] == 1 then
        output[outputIndex] = this.values[i]
        outputIndex = outputIndex + 1
      end if
      i = i + 1
    end while
    this.guard.release()
    return output
  end function

  // Copy live pairs into detached Entry snapshots.
  function entriesArray()
    if not this.guard.acquire() then return [] end if
    if this.closed then
      this.guard.release()
      return []
    end if
    output = array(this.size)
    outputIndex = 0
    i = 0
    while i < this.bucketCount
      if this.states[i] == 1 then
        output[outputIndex] = Entry(this.keys[i], this.values[i])
        outputIndex = outputIndex + 1
      end if
      i = i + 1
    end while
    this.guard.release()
    return output
  end function

  // Drop all managed references and release the native lock.
  function close()
    if this.closed or not this.guard.acquire() then return false end if
    this.keys = []
    this.values = []
    this.states = []
    this.bucketCount = 0
    this.size = 0
    this.closed = true
    this.guard.release()
    this.guard.close()
    return true
  end function
end struct
