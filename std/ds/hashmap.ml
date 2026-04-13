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

package std.ds.hashmap

// ------------------------------------------------------------
// std.ds.hashmap
// Open-addressing hash map (linear probing).
//
// Supported key types:
// - int
// - bytes
// - string
//
// Semantics:
// - get(k) returns `void` if not found or on type errors.
// - set/remove return true/false.
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
returns the next power-of-two capacity (minimum 16)
input: int n
returns: int capPow2
*/
function _nextPow2(n)
  if typeof(n) != "int" then
    return 16
  end if
  if n <= 16 then
    return 16
  end if
  c = 16
  while c < n
    c = c << 1
  end while
  return c
end function

/*
mixes an integer into a 32-bit hash value
input: int x
returns: int hashU32
*/
function _mix32(x)
  // 32-bit finalizer (Murmur-style), masked to u32.
  h = x & 0xFFFFFFFF
  h = h ^(h >> 16)
  h =(h * 0x7feb352d) & 0xFFFFFFFF
  h = h ^(h >> 15)
  h =(h * 0x846ca68b) & 0xFFFFFFFF
  h = h ^(h >> 16)
  return h & 0xFFFFFFFF
end function

/*
hashes a supported key type (int|bytes|string)
input: int|bytes|string k
returns: int hashU32 (or void)
*/
function _hashKey(k)
  t = typeof(k)
  if t == "int" then
    return _mix32(k)
  end if
  if t == "bytes" then
    return bytesHash(k)
  end if
  if t == "string" then
    return stringHash(k)
  end if
  return
end function

/*
finds a slot index for lookup/insert
input: array keys, array states, int cap, int|bytes|string key, bool forInsert
returns: int index (or -1)
*/
function _findSlot(keys, states, cap, key, forInsert)
  // states: 0=empty, 1=used, 2=tomb
  h = _hashKey(key)
  if typeof(h) == "void" then
    return -1
  end if

  mask = cap - 1
  idx = h & mask

  firstTomb = -1
  i = 0
  while i < cap
    st = states[idx]
    if st == 0 then
      if forInsert then
        if firstTomb >= 0 then
          return firstTomb
        end if
        return idx
      end if
      return -1
    end if

    if st == 1 then
      if keys[idx] == key then
        return idx
      end if
    else
      // tomb
      if forInsert and firstTomb < 0 then
        firstTomb = idx
      end if
    end if

    idx =(idx + 1) & mask
    i = i + 1
  end while

  if forInsert and firstTomb >= 0 then
    return firstTomb
  end if
  return -1
end function

struct Entry
  key
  value
end struct

struct HashMap
  cap
  size
  keys
  values
  states

  /*
  creates a new empty hash map
  input: (none)
  returns: HashMap map
  */
  static function new()
  return HashMap.withCapacity(16)
end function

/*
creates a hash map with at least `minCap` capacity
input: int minCap
returns: HashMap map
*/
static function withCapacity(minCap)
c = _nextPow2(minCap)
k = _allocArray(c, 0)
v = _allocArray(c, 0)
s = _allocArray(c, 0)
return HashMap(c, 0, k, v, s)
end function

/*
returns number of entries
input: (none)
returns: int count
*/
function count()
  return this.size
end function

/*
checks whether map is empty
input: (none)
returns: bool empty
*/
function isEmpty()
  return this.size == 0
end function

/*
removes all entries (keeps capacity)
input: (none)
returns: void
*/
function clear()
  // keep capacity, reset arrays
  this.keys = _allocArray(this.cap, 0)
  this.values = _allocArray(this.cap, 0)
  this.states = _allocArray(this.cap, 0)
  this.size = 0
end function

/*
checks whether inserting one element would exceed load factor
input: (none)
returns: bool shouldGrow
*/
function _maybeGrow()
  // Grow at ~0.7 load factor
  return (this.size + 1) * 10 >= this.cap * 7
end function

/*
rehashes entries into a new table size
input: int newCap
returns: void
*/
function _rehash(newCap)
  c2 = _nextPow2(newCap)
  nk = _allocArray(c2, 0)
  nv = _allocArray(c2, 0)
  ns = _allocArray(c2, 0)

  for i = 0 to(this.cap - 1)
    if this.states[i] == 1 then
      key = this.keys[i]
      val = this.values[i]
      idx = _findSlot(nk, ns, c2, key, true)
      nk[idx] = key
      nv[idx] = val
      ns[idx] = 1
    end if
  end for

  this.cap = c2
  this.keys = nk
  this.values = nv
  this.states = ns
end function

/*
inserts or updates a key/value pair
input: int|bytes|string key, any value
returns: bool ok
*/
function set(key, value)
  kt = typeof(key)
  if kt != "int" and kt != "bytes" and kt != "string" then
    return false
  end if

  if this._maybeGrow() then
    this._rehash(this.cap << 1)
  end if

  idx = _findSlot(this.keys, this.states, this.cap, key, true)
  if idx < 0 then
    return false
  end if

  if this.states[idx] != 1 then
    this.size = this.size + 1
    this.keys[idx] = key
    this.states[idx] = 1
  end if
  this.values[idx] = value
  return true
end function

/*
checks if a key exists
input: int|bytes|string key
returns: bool present
*/
function has(key)
  kt = typeof(key)
  if kt != "int" and kt != "bytes" and kt != "string" then
    return false
  end if
  idx = _findSlot(this.keys, this.states, this.cap, key, false)
  return idx >= 0
end function

/*
gets value by key
input: int|bytes|string key
returns: any value (or void)
*/
function get(key)
  kt = typeof(key)
  if kt != "int" and kt != "bytes" and kt != "string" then
    return
  end if
  idx = _findSlot(this.keys, this.states, this.cap, key, false)
  if idx < 0 then
    return
  end if
  return this.values[idx]
end function

/*
gets value by key or returns fallback
input: int|bytes|string key, any fallback
returns: any valueOrFallback
*/
function getOr(key, fallback)
  v = this.get(key)
  if typeof(v) == "void" then
    return fallback
  end if
  return v
end function

/*
removes a key from the map
input: int|bytes|string key
returns: bool removed
*/
function remove(key)
  kt = typeof(key)
  if kt != "int" and kt != "bytes" and kt != "string" then
    return false
  end if
  idx = _findSlot(this.keys, this.states, this.cap, key, false)
  if idx < 0 then
    return false
  end if

  this.states[idx] = 2
  this.keys[idx] = 0
  this.values[idx] = 0
  this.size = this.size - 1
  return true
end function

/*
alias for remove(key) to match common naming in the stdlib/tests
input: int|bytes|string key
returns: bool removed
*/
function delete(key)
  return this.remove(key)
end function

/*
returns all keys (order unspecified)
input: (none)
returns: array keys
*/
function keysArray()
  output = array(this.size)
  oi = 0
  for i = 0 to(this.cap - 1)
    if this.states[i] == 1 then
      output[oi] = this.keys[i]
      oi = oi + 1
    end if
  end for
  return output
end function

/*
returns all values (order unspecified)
input: (none)
returns: array values
*/
function valuesArray()
  output = array(this.size)
  oi = 0
  for i = 0 to(this.cap - 1)
    if this.states[i] == 1 then
      output[oi] = this.values[i]
      oi = oi + 1
    end if
  end for
  return output
end function

/*
returns all entries (order unspecified)
input: (none)
returns: array<Entry> entries
*/
function entriesArray()
  output = array(this.size)
  oi = 0
  for i = 0 to(this.cap - 1)
    if this.states[i] == 1 then
      output[oi] = Entry(this.keys[i], this.values[i])
      oi = oi + 1
    end if
  end for
  return output
end function
end struct
