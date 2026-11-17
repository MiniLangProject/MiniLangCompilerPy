// Custom typeof may approve arbitrary tags. Its annotated parameters cannot
// authorize a float loop, even when the counter and bound are obvious ints.
calls = 0

function typeof(value, label = "float")
  global calls
  calls = calls + 1
  return label
end function

function shadowedLoop(value as float, step as float)
  i = 0
  while i < 3
    value = value + step
    i = i + 1
  end while
  return value
end function

function main(args)
  global calls
  calls = 0
  if shadowedLoop("v", "x") != "vxxx" then return 1 end if
  if calls != 2 then return 2 end if
  if shadowedLoop(9007199254740993, 1) != 9007199254740996 then return 3 end if
  if calls != 4 then return 4 end if
  caught = try(shadowedLoop(void, 0.25))
  if caught.code != 1200 then return 5 end if
  if calls != 6 then return 6 end if
  print "NUMERIC FLOAT LOOP TYPEOF [OK]"
  return 0
end function
