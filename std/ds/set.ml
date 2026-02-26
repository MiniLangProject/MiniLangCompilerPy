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

package std.ds.set

import std.ds.hashmap as hm

// ------------------------------------------------------------
// std.ds.set
// Simple set built on top of std.ds.hashmap.HashMap.
//
// Supported key types are the same as the underlying HashMap:
// - int
// - bytes
// ------------------------------------------------------------

struct HashSet
  map

  /*
  creates a new empty hash set
  input: (none)
  returns: HashSet set
  */
  static function new()
  return HashSet(hm.HashMap.new())
end function

/*
returns the number of elements
input: (none)
returns: int length
*/
function len()
  return this.map.count()
end function

/*
checks whether the set is empty
input: (none)
returns: bool empty
*/
function isEmpty()
  return this.map.isEmpty()
end function

/*
removes all elements
input: (none)
returns: void
*/
function clear()
  this.map.clear()
end function

/*
adds a key to the set
input: int|bytes key
returns: bool ok
*/
function add(key)
  return this.map.set(key, true)
end function

/*
checks whether the set contains a key
input: int|bytes key
returns: bool present
*/
function has(key)
  return this.map.has(key)
end function

/*
removes a key from the set
input: int|bytes key
returns: bool removed
*/
function remove(key)
  return this.map.remove(key)
end function

/*
alias for remove(key) to match common naming in the stdlib/tests
input: int|bytes key
returns: bool removed
*/
function delete(key)
  return this.remove(key)
end function

/*
returns an array of all keys (order is unspecified)
input: (none)
returns: array keys
*/
function keysArray()
  return this.map.keysArray()
end function
end struct

