// Custom guards are observable and may approve values with any runtime tag.
// Their annotations cannot make a float-only tree eligible.
calls = 0

function typeof(value, label = "float")
  global calls
  calls = calls + 1
  return label
end function

function shadowedTree(a as float, b as float, c as float, d as float)
  return (a + b) + (c + d)
end function

function shadowedComparison(a as float, b as float, right as float)
  return a + b < right
end function

function main(args)
  global calls
  if typeof(args) != "float" then return 1 end if
  calls = 0
  if shadowedTree("a", 1, "b", 2) != "a1b2" then return 2 end if
  if calls != 4 then return 3 end if
  if shadowedTree(9007199254740993, -9007199254740992, 2, 3) != 6 then return 4 end if
  if calls != 8 then return 5 end if
  if shadowedComparison(9007199254740993, -9007199254740992, 2) != true then return 6 end if
  if calls != 11 then return 7 end if
  caught = try(shadowedTree(void, 0.2, 0.3, 0.4))
  if caught.code != 1200 then return 8 end if
  if calls != 15 then return 9 end if
  print "NUMERIC FLOAT TREE TYPEOF [OK]"
  return 0
end function
