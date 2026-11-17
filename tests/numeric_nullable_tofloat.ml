// The spelling toFloat does not make a user function a trusted conversion.
function toFloat(value, unused = 0)
  return value
end function

function replacement(value, unused = 0)
  return "changed"
end function

function shadowedDivision(value as int, right as float)
  quotient = 3.0 / toFloat(value)
  return (quotient + 0.125) + right
end function

function shadowedRight(a as float, b as float, value as int)
  right = toFloat(value)
  return (a + b) + right
end function

function reference(a, b, right)
  child = a + b
  return child + right
end function

function main(args)
  global toFloat
  if shadowedDivision(2, 0.25) != 1.875 then return 1 end if
  caught = try(shadowedDivision(0, 0.25))
  if typeof(caught) != "error" then return 2 end if
  if caught.code != 1200 then return 3 end if
  if shadowedRight(0.1, 0.2, 3) != reference(0.1, 0.2, 3) then return 4 end if
  toFloat = replacement
  changed = try(shadowedDivision(2, 0.25))
  if typeof(changed) != "error" then return 5 end if
  if changed.code != 1200 then return 6 end if
  if shadowedRight(0.1, 0.2, 3) != reference(0.1, 0.2, "changed") then return 7 end if
  print "NUMERIC NULLABLE TOFLOAT [OK]"
  return 0
end function
