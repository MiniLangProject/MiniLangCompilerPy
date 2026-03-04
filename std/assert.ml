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

package std.assert

// ------------------------------------------------------------
// std.assert
// Lightweight assert helpers (no exceptions; return true/false).
// Intended for tests and quick sanity checks.
// ------------------------------------------------------------

/*
asserts that a condition is true
input: bool cond, string label
returns: bool success
*/
function assertTrue(cond, label)
  if cond then
    print label + " [OK]"
    return true
  end if

  print label + " [FAIL]"
  print "condition was false"
  return false
end function

/*
asserts that a condition is false
input: bool cond, string label
returns: bool success
*/
function assertFalse(cond, label)
  if not cond then
    print label + " [OK]"
    return true
  end if

  print label + " [FAIL]"
  print "condition was true"
  return false
end function

/*
asserts that two values are equal (==)
input: any actual, any expected, string label
returns: bool success
*/
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

/*
asserts that two values are not equal (!=)
input: any actual, any expected, string label
returns: bool success
*/
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

/*
asserts that a is greater than b
input: comparable a, comparable b, string label
returns: bool success
*/
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

/*
asserts that a is less than b
input: comparable a, comparable b, string label
returns: bool success
*/
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

/*
asserts that two numbers are approximately equal
input: int|float actual, int|float expected, float eps, string label
returns: bool success
*/
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

/*
asserts that a value is not void
input: any x, string label
returns: bool success
*/
function assertNotVoid(x, label)
  if typeof(x) != "void" then
    print label + " [OK]"
    return true
  end if

  print label + " [FAIL]"
  print "value was void"
  return false
end function


