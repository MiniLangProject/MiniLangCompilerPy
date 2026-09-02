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

//! Provides the std assert package.

package std.assert

// ------------------------------------------------------------
// std.assert
// Lightweight assert helpers (no exceptions; return true/false).
// Intended for tests and quick sanity checks.
// ------------------------------------------------------------

/// Asserts that a condition is true.
/// @param cond Value supplied for `cond`.
/// @param label Value supplied for `label`.
function assertTrue(cond, label)
  if cond then
    print label + " [OK]"
    return true
  end if

  print label + " [FAIL]"
  print "condition was false"
  return false
end function

/// Asserts that a condition is false.
/// @param cond Value supplied for `cond`.
/// @param label Value supplied for `label`.
function assertFalse(cond, label)
  if not cond then
    print label + " [OK]"
    return true
  end if

  print label + " [FAIL]"
  print "condition was true"
  return false
end function

/// Asserts that two values are equal (==).
/// @param actual Value supplied for `actual`.
/// @param expected Value supplied for `expected`.
/// @param label Value supplied for `label`.
function assertEq(actual, expected, label)
  if actual == expected then
    print label + " [OK]"
    return true
  end if

  print label + " [FAIL]"
  print "got"
  print actual
  print "expected"
  print expected
  return false
end function

/// Asserts that two values are not equal (!=).
/// @param actual Value supplied for `actual`.
/// @param expected Value supplied for `expected`.
/// @param label Value supplied for `label`.
function assertNe(actual, expected, label)
  if actual != expected then
    print label + " [OK]"
    return true
  end if

  print label + " [FAIL]"
  print "did not expect"
  print expected
  return false
end function

/// Asserts that a is greater than b.
/// @param a First input value.
/// @param b Second input value.
/// @param label Value supplied for `label`.
function assertGt(a, b, label)
  if a > b then
    print label + " [OK]"
    return true
  end if

  print label + " [FAIL]"
  print "expected >"
  print b
  print "got"
  print a
  return false
end function

/// Asserts that a is less than b.
/// @param a First input value.
/// @param b Second input value.
/// @param label Value supplied for `label`.
function assertLt(a, b, label)
  if a < b then
    print label + " [OK]"
    return true
  end if

  print label + " [FAIL]"
  print "expected <"
  print b
  print "got"
  print a
  return false
end function

/// Asserts that two numbers are approximately equal.
/// @param actual Value supplied for `actual`.
/// @param expected Value supplied for `expected`.
/// @param eps Value supplied for `eps`.
/// @param label Value supplied for `label`.
function assertApprox(actual, expected, eps, label)
  // Avoid importing std.math from std.assert (keep this dependency-free).
  d = actual - expected
  if d < 0 then
    d = 0 - d
  end if
  if d <= eps then
    print label + " [OK]"
    return true
  end if

  print label + " [FAIL]"
  print "got"
  print actual
  print "expected"
  print expected
  print "eps"
  print eps
  return false
end function

/// Asserts that a value is not void.
/// @param x Value supplied for `x`.
/// @param label Value supplied for `label`.
function assertNotVoid(x, label)
  if typeof(x) != "void" then
    print label + " [OK]"
    return true
  end if

  print label + " [FAIL]"
  print "value was void"
  return false
end function


