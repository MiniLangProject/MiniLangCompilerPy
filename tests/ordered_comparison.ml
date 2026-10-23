/// Dynamic ordered comparisons must retain numeric results and catchable errors.
/// Keep callback parameters untyped so all four operators use dynamic lowering.
failures = 0

function lessCaught(left, right)
  return try(left < right)
end function
function greaterCaught(left, right)
  return try(left > right)
end function
function lessEqualCaught(left, right)
  return try(left <= right)
end function
function greaterEqualCaught(left, right)
  return try(left >= right)
end function

function lessPropagated(left, right)
  return left < right
end function
function greaterPropagated(left, right)
  return left > right
end function
function lessEqualPropagated(left, right)
  return left <= right
end function
function greaterEqualPropagated(left, right)
  return left >= right
end function

function keepComparison(value)
  return value
end function
function lessArgument(left, right)
  return try(keepComparison(left < right))
end function
function greaterArgument(left, right)
  return try(keepComparison(left > right))
end function
function lessEqualArgument(left, right)
  return try(keepComparison(left <= right))
end function
function greaterEqualArgument(left, right)
  return try(keepComparison(left >= right))
end function

/// Adjacent joins must not leave stale branch candidates or shifted fixups.
function adjacentComparisons(left, right)
  less = try(left < right)
  greater = try(left > right)
  lessEqual = try(left <= right)
  greaterEqual = try(left >= right)
  return [less, greater, lessEqual, greaterEqual]
end function

struct NonNumeric
  value
end struct

function checkValue(actual, expected, label)
  global failures
  if typeof(actual) != "bool" or actual != expected then
    failures += 1
    print "[FAIL] " + label
  end if
end function

function checkError(actual, op, kind)
  global failures
  if typeof(actual) != "error" then
    failures += 1
    print "[FAIL] missing comparison error: " + op + " " + kind
    return
  end if
  if actual.code != 1200 or actual.message != "Cannot apply '" + op + "' to " + kind then
    failures += 1
    print "[FAIL] comparison error details: " + op + " " + kind
  end if
end function

function main(args)
  global failures
  forms = [
    [lessCaught, greaterCaught, lessEqualCaught, greaterEqualCaught],
    [lessPropagated, greaterPropagated, lessEqualPropagated, greaterEqualPropagated],
    [lessArgument, greaterArgument, lessEqualArgument, greaterEqualArgument]
  ]
  operators = ["<", ">", "<=", ">="]
  cases = [
    [-5, 7, [true, false, true, false]],
    [7, -5, [false, true, false, true]],
    [7, 7, [false, false, true, true]],
    [1.25, 2.5, [true, false, true, false]],
    [2.5, 1.25, [false, true, false, true]],
    [1.25, 1.25, [false, false, true, true]],
    [1, 1.25, [true, false, true, false]],
    [1.25, 1, [false, true, false, true]]
  ]
  for each pair in cases
    for each callbacks in forms
      for op = 0 to 3
        callback = callbacks[op]
        actual = try(callback(pair[0], pair[1]))
        checkValue(actual, pair[2][op], "numeric " + operators[op])
      end for
    end for
    adjacent = adjacentComparisons(pair[0], pair[1])
    for op = 0 to 3 checkValue(adjacent[op], pair[2][op], "adjacent numeric") end for
  end for

  // Test both operand positions and void precedence over another invalid type.
  invalid = [
    [void, 1, "void"], [1, void, "void"], [void, void, "void"],
    [void, "bad", "void"], ["bad", void, "void"],
    ["bad", 1, "non-numeric values"], [1, "bad", "non-numeric values"],
    [true, 1, "non-numeric values"], [1.25, false, "non-numeric values"],
    [[], 1, "non-numeric values"], [1, bytes(0), "non-numeric values"],
    [NonNumeric(1), 1, "non-numeric values"]
  ]
  for each pair in invalid
    for each callbacks in forms
      for op = 0 to 3
        callback = callbacks[op]
        actual = try(callback(pair[0], pair[1]))
        checkError(actual, operators[op], pair[2])
      end for
    end for
    adjacent = adjacentComparisons(pair[0], pair[1])
    for op = 0 to 3 checkError(adjacent[op], operators[op], pair[2]) end for
  end for
  if failures != 0 then return 1 end if
  print "[OK] dynamic ordered comparisons"
  return 0
end function
