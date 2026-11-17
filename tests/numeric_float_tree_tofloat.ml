// User-defined and rebound conversions are not pure numeric leaf proofs.
function toFloat(value, unused = 0)
  return value
end function

function replacement(value, unused = 0)
  return "changed"
end function

function shadowedTree(value as int, right as float)
  converted = toFloat(value)
  return (converted + 0.125) + (right * 0.2)
end function

function shadowedComparison(value as int, right as float)
  converted = toFloat(value)
  return converted + 0.125 < right
end function

function reference(value, right)
  first = value + 0.125
  second = right * 0.2
  return first + second
end function

function referenceComparison(value, right)
  first = value + 0.125
  return first < right
end function

function main(args)
  global toFloat
  if shadowedTree(3, 0.25) != reference(3, 0.25) then return 1 end if
  if shadowedComparison(3, 4.0) != referenceComparison(3, 4.0) then return 2 end if
  toFloat = replacement
  if shadowedTree(3, 0.25) != reference("changed", 0.25) then return 3 end if
  caught = try(shadowedComparison(3, 4.0))
  expected = try(referenceComparison("changed", 4.0))
  if typeof(caught) != typeof(expected) then return 4 end if
  if typeof(caught) == "error" then
    if caught.code != expected.code then return 5 end if
  else
    if caught != expected then return 6 end if
  end if
  print "NUMERIC FLOAT TREE TOFLOAT [OK]"
  return 0
end function
