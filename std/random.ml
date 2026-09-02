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

//! Provides the std random package.

package std.random

/// Std.random Simple deterministic PRNG (xorshift32). - Deterministic across runs. - Not cryptographically secure.
const U32_MASK = 0xFFFFFFFF
/// Stores the default seed.
const DEFAULT_SEED = 0x6d2b79f5
/// Stores the u32 range float.
const U32_RANGE_FLOAT = 4294967296.0

/// Deterministic per-instance pseudorandom number generator.
struct RNG
  /// Stores the state member of `RNG`.
  state

  /// Creates a deterministic RNG from a seed.
  /// @param seed Value supplied for `seed`.
  static function Seed(seed)
  s = seed
  if typeof(s) != "int" then
    s2 = toNumber(s)
    if typeof(s2) == "void" then
      s = 1
    else
      s = s2
    end if
  end if

  if s == 0 then
    s = std.random.DEFAULT_SEED
  end if

  // clamp to 32-bit
  return std.random.RNG(s & std.random.U32_MASK)
end function

/// Generates the next 32-bit unsigned value.
function nextU32()
  x = this.state
  x = x ^((x << 13) & std.random.U32_MASK)
  x = x ^(x >> 17)
  x = x ^((x << 5) & std.random.U32_MASK)
  this.state = x & std.random.U32_MASK
  return this.state
end function

/// Generates an integer in [0, maxExclusive).
/// @param maxExclusive Value supplied for `maxExclusive`.
function nextInt(maxExclusive)
  if typeof(maxExclusive) != "int" then
    return
  end if
  if maxExclusive <= 0 then
    return 0
  end if
  return this.nextU32() % maxExclusive
end function

/// Generates a float in [0, 1).
function nextFloat()
  // [0,1)
  return this.nextU32() / std.random.U32_RANGE_FLOAT
end function

/// Generates a random boolean.
function nextBool()
  return (this.nextU32() & 1) == 1
end function

/// Generates an integer in [minInclusive, maxExclusive).
/// @param minInclusive Value supplied for `minInclusive`.
/// @param maxExclusive Value supplied for `maxExclusive`.
function rangeInt(minInclusive, maxExclusive)
  if typeof(minInclusive) != "int" or typeof(maxExclusive) != "int" then
    return
  end if
  if maxExclusive <= minInclusive then
    return minInclusive
  end if
  return minInclusive + this.nextInt(maxExclusive - minInclusive)
end function

/// Generates a float in [minInclusive, maxExclusive).
/// @param minInclusive Value supplied for `minInclusive`.
/// @param maxExclusive Value supplied for `maxExclusive`.
function rangeFloat(minInclusive, maxExclusive)
  return minInclusive +(this.nextFloat() *(maxExclusive - minInclusive))
end function
end struct

/// Constructs a seeded RNG.
/// @param seed Value supplied for `seed`.
function seeded(seed)
  return std.random.RNG.Seed(seed)
end function

/// Shuffles an array in place using Fisher-Yates.
/// @param rng Value supplied for `rng`.
/// @param xs Value supplied for `xs`.
function shuffleInPlace(rng, xs)
  if typeof(xs) != "array" then
    return xs
  end if

  i = len(xs) - 1
  while i > 0
    j = rng.nextInt(i + 1)
    tmp = xs[i]
    xs[i] = xs[j]
    xs[j] = tmp
    i = i - 1
  end while
  return xs
end function

/// Picks a random element from an array.
/// @param rng Value supplied for `rng`.
/// @param xs Value supplied for `xs`.
function choice(rng, xs)
  if typeof(xs) != "array" then
    return
  end if
  n = len(xs)
  if n <= 0 then
    return
  end if
  return xs[rng.nextInt(n)]
end function


