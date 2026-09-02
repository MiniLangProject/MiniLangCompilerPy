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

//! Provides the std core package.

package std.core

// ------------------------------------------------------------
// std.core
// Small, dependency-free helpers that are safe to import anywhere.
//
// Notes:
// - The native backend has no exceptions: many type errors evaluate to `void`.
// - These helpers make it easy to check types and provide fallbacks.
// ------------------------------------------------------------

/// Checks whether a value is void.
/// @param x Value supplied for `x`.
function isVoid(x)
  return typeof(x) == "void"
end function

/// Checks whether a value is an int.
/// @param x Value supplied for `x`.
function isInt(x)
  return typeof(x) == "int"
end function

/// Checks whether a value is a float.
/// @param x Value supplied for `x`.
function isFloat(x)
  return typeof(x) == "float"
end function

/// Checks whether a value is a number (int or float).
/// @param x Value supplied for `x`.
function isNumber(x)
  ty = typeof(x)
  return ty == "int" or ty == "float"
end function

/// Checks whether a value is a bool.
/// @param x Value supplied for `x`.
function isBool(x)
  return typeof(x) == "bool"
end function

/// Checks whether a value is a string.
/// @param x Value supplied for `x`.
function isString(x)
  return typeof(x) == "string"
end function

/// Checks whether a value is an array.
/// @param x Value supplied for `x`.
function isArray(x)
  return typeof(x) == "array"
end function

/// Checks whether a value is a function.
/// @param x Value supplied for `x`.
function isFunction(x)
  return typeof(x) == "function"
end function

/// Returns fallback if x is void, otherwise x.
/// @param x Value supplied for `x`.
/// @param fallback Value supplied for `fallback`.
function coalesce(x, fallback)
  if typeof(x) == "void" then
    return fallback
  end if
  return x
end function

/// Minimum of two comparable values.
/// @param a First input value.
/// @param b Second input value.
function min(a, b)
  if a < b then
    return a
  end if
  return b
end function

/// Maximum of two comparable values.
/// @param a First input value.
/// @param b Second input value.
function max(a, b)
  if a > b then
    return a
  end if
  return b
end function

/// Clamp a value into [lo, hi].
/// @param x Value supplied for `x`.
/// @param lo Value supplied for `lo`.
/// @param hi Value supplied for `hi`.
function clamp(x, lo, hi)
  if x < lo then
    return lo
  end if
  if x > hi then
    return hi
  end if
  return x
end function

/// Absolute value.
/// @param x Value supplied for `x`.
function abs(x)
  if x < 0 then
    return - x
  end if
  return x
end function

/// Sign of a number.
/// @param x Value supplied for `x`.
function sign(x)
  if x < 0 then
    return -1
  end if
  if x > 0 then
    return 1
  end if
  return 0
end function

/// Safe len(): returns len(x) if x supports it, otherwise fallback.
/// @param x Value supplied for `x`.
/// @param fallback Value supplied for `fallback`.
function safeLen(x, fallback)
  ty = typeof(x)
  if ty == "string" or ty == "array" or ty == "bytes" then
    return len(x)
  end if
  return fallback
end function

/// Safe toNumber(): returns converted value or fallback.
/// @param x Value supplied for `x`.
/// @param fallback Value supplied for `fallback`.
function safeToNumber(x, fallback)
  n = toNumber(x)
  if typeof(n) == "void" then
    return fallback
  end if
  return n
end function


