// Custom typeof cannot establish the numeric facts used by nested candidates.
calls = 0

function typeof(value, label = "float")
  global calls
  calls = calls + 1
  return label
end function

function shadowedNested(value as float, step as float)
  outer = 0
  while outer < 2
    inner = 0
    while inner < 3
      value = value + step
      inner = inner + 1
    end while
    outer = outer + 1
  end while
  return value
end function

function shadowedCompound(value as float, step as float)
  i = 0
  while i < 3 and value != step
    value = value + step
    i = i + 1
  end while
  return value
end function

function main(args)
  global calls
  calls = 0
  if shadowedNested("v", "x") != "vxxxxxx" then return 1 end if
  if calls != 2 then return 2 end if
  if shadowedNested(9007199254740993, 1) != 9007199254740999 then return 3 end if
  if calls != 4 then return 4 end if
  if shadowedCompound("v", "x") != "vxxx" then return 5 end if
  if calls != 6 then return 6 end if
  caught = try(shadowedNested(void, 0.25))
  if caught.code != 1200 then return 7 end if
  if calls != 8 then return 8 end if
  print "NUMERIC FLOAT NESTED TYPEOF [OK]"
  return 0
end function
