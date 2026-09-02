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

//! Provides the std ds set package.

package std.ds.set

import std.ds.hashmap as hm

/// Std.ds.set Simple set built on top of std.ds.hashmap.HashMap. Supported key types are the same as the underlying HashMap: - int - bytes - string.
struct HashSet
  /// Stores the map member of `HashSet`.
  map

  /// Creates a new empty hash set.
  static function new()
  return HashSet(hm.HashMap.new())
end function

/// Returns the number of elements.
function len()
  return this.map.count()
end function

/// Checks whether the set is empty.
function isEmpty()
  return this.map.isEmpty()
end function

/// Removes all elements.
function clear()
  this.map.clear()
end function

/// Adds a key to the set.
/// @param key Value supplied for `key`.
function add(key)
  return this.map.set(key, true)
end function

/// Checks whether the set contains a key.
/// @param key Value supplied for `key`.
function has(key)
  return this.map.has(key)
end function

/// Removes a key from the set.
/// @param key Value supplied for `key`.
function remove(key)
  return this.map.remove(key)
end function

/// Alias for remove(key) to match common naming in the stdlib/tests.
/// @param key Value supplied for `key`.
function delete(key)
  return this.remove(key)
end function

/// Returns an array of all keys (order is unspecified).
function keysArray()
  return this.map.keysArray()
end function
end struct

