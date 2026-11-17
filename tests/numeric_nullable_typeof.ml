// An observable custom guard may approve strings, void or integer Values.
// Its annotations cannot justify the guarded numeric candidate analysis.
calls = 0

function typeof(value, label = "float")
  global calls
  calls = calls + 1
  return label
end function

function shadowedDivisor(value as float, right as float)
  quotient = 3.0 / value
  return (quotient + 0.125) + right
end function

function shadowedRight(a as float, b as float, right as float)
  return (a + b) + right
end function

function main(args)
  global calls
  if typeof(args) != "float" then return 1 end if
  calls = 0
  if shadowedDivisor(2, 0.25) != 1.875 then return 2 end if
  caught = try(shadowedDivisor("wrong", 0.25))
  if caught.code != 1200 then return 3 end if
  if calls != 4 then return 4 end if
  if shadowedRight(9007199254740993, -9007199254740992, 9007199254740993) != 9007199254740994 then return 5 end if
  if calls != 7 then return 6 end if
  if shadowedRight("x", 1, "y") != "x1y" then return 7 end if
  if calls != 10 then return 8 end if
  print "NUMERIC NULLABLE TYPEOF [OK]"
  return 0
end function
