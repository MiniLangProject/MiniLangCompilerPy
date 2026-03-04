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

package std.core

// ------------------------------------------------------------
// std.core
// Small, dependency-free helpers that are safe to import anywhere.
//
// Notes:
// - The native backend has no exceptions: many type errors evaluate to `void`.
// - These helpers make it easy to check types and provide fallbacks.
// ------------------------------------------------------------

/*
checks whether a value is void
input: any x
returns: bool isVoid
*/
function isVoid(x)
  return typeof(x) == "void"
end function

/*
checks whether a value is an int
input: any x
returns: bool isInt
*/
function isInt(x)
  return typeof(x) == "int"
end function

/*
checks whether a value is a float
input: any x
returns: bool isFloat
*/
function isFloat(x)
  return typeof(x) == "float"
end function

/*
checks whether a value is a number (int or float)
input: any x
returns: bool isNumber
*/
function isNumber(x)
  ty = typeof(x)
  return ty == "int" or ty == "float"
end function

/*
checks whether a value is a bool
input: any x
returns: bool isBool
*/
function isBool(x)
  return typeof(x) == "bool"
end function

/*
checks whether a value is a string
input: any x
returns: bool isString
*/
function isString(x)
  return typeof(x) == "string"
end function

/*
checks whether a value is an array
input: any x
returns: bool isArray
*/
function isArray(x)
  return typeof(x) == "array"
end function

/*
checks whether a value is a function
input: any x
returns: bool isFunction
*/
function isFunction(x)
  return typeof(x) == "function"
end function

/*
returns fallback if x is void, otherwise x
input: any x, any fallback
returns: any value
*/
function coalesce(x, fallback)
  if typeof(x) == "void" then
    return fallback
  end if
  return x
end function

/*
minimum of two comparable values
input: comparable a, comparable b
returns: comparable minValue
*/
function min(a, b)
  if a < b then
    return a
  end if
  return b
end function

/*
maximum of two comparable values
input: comparable a, comparable b
returns: comparable maxValue
*/
function max(a, b)
  if a > b then
    return a
  end if
  return b
end function

/*
clamp a value into [lo, hi]
input: comparable x, comparable lo, comparable hi
returns: comparable clamped
*/
function clamp(x, lo, hi)
  if x < lo then
    return lo
  end if
  if x > hi then
    return hi
  end if
  return x
end function

/*
absolute value
input: int|float x
returns: int|float absX
*/
function abs(x)
  if x < 0 then
    return - x
  end if
  return x
end function

/*
sign of a number
input: int|float x
returns: int sign (-1, 0, 1)
*/
function sign(x)
  if x < 0 then
    return -1
  end if
  if x > 0 then
    return 1
  end if
  return 0
end function

/*
safe len(): returns len(x) if x supports it, otherwise fallback
input: any x, int fallback
returns: int length
*/
function safeLen(x, fallback)
  ty = typeof(x)
  if ty == "string" or ty == "array" or ty == "bytes" then
    return len(x)
  end if
  return fallback
end function

/*
safe toNumber(): returns converted value or fallback
input: any x, int|float fallback
returns: int|float number
*/
function safeToNumber(x, fallback)
  n = toNumber(x)
  if typeof(n) == "void" then
    return fallback
  end if
  return n
end function


